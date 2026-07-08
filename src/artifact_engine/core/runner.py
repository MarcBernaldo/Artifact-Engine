"""Run a single parser against a volume.

Resolves the command templates, checks the artifact exists and runs the tool
(external binary) or the Python handler. Returns a ParserRun with status,
duration and detail for the execution manifest and the report.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import os
import re
import shlex
import shutil
import time
from dataclasses import dataclass, replace
from pathlib import Path

from artifact_engine.core import procs
from artifact_engine.logging_setup import get_logger
from artifact_engine.models import ParserManifest

log = get_logger()


class HandlerSkip(Exception):
    """A handler raises this to declare it has nothing to do on this volume
    (e.g. no web root for the webshell scanner). Reported as "skipped", not
    "error", and no .done marker is written so a later run re-evaluates it."""

# Some EZ tools prefix outputs with a timestamp (e.g. "20260620231505_Amcache_*.csv")
# and suffix "_Output"; others (RECmd) write into a timestamped subfolder. We strip
# both so output names stay clean and uniform.
_TS_PREFIX = re.compile(r"^\d{6,}_")
_TS_DIR = re.compile(r"^\d{8,}$")
# Redundant tool-name prefixes stripped before applying the parser's short code.
_TOOL_PREFIXES = ("Amcache_", "SrumECmd_", "SumECmd_", "DeepBlue-", "DeepBlue_")


def _short_stem(stem: str, short: str) -> str:
    """Build the clean table-friendly stem: <short>_<subtype> (no doubling)."""
    stem = _TS_PREFIX.sub("", stem).replace("_Output", "")
    if not short:
        # No short code: the parser's --csvf (or handler) already named it cleanly.
        return stem
    for pre in _TOOL_PREFIXES:
        if stem.startswith(pre):
            stem = stem[len(pre):]
            break
    if not stem or stem.lower() == short.lower():
        return short
    if stem.lower().startswith(short.lower() + "_"):
        return stem
    return f"{short}_{stem}"


@dataclass
class ParserContext:
    """Data passed to a Python handler (`def run(ctx)`)."""

    evidence: Path     # volume root to parse (read-only)
    out: Path          # output folder (already created)
    tools: Path        # binaries folder
    assets: Path       # wordlists/rules folder
    machine_name: str
    volume: str
    log: object


@dataclass
class ParserRun:
    parser_id: str
    volume: str
    status: str          # "ok" | "skipped" | "error"
    duration_s: float
    detail: str = ""


def marker_path(out_dir: Path, parser_id: str) -> Path:
    """Idempotency marker, written in the output dir on a successful run. Its
    content is the parser fingerprint (see `parser_fingerprint`)."""
    return out_dir / f".{parser_id}.done"


_SRC_CACHE: dict[str, bytes] = {}


def _handler_source(handler: str) -> bytes:
    """Bytes of the handler module's own .py file (cached per module, empty on miss)."""
    mod = handler.partition(":")[0]
    if mod not in _SRC_CACHE:
        data = b""
        try:
            spec = importlib.util.find_spec(mod)
            if spec and spec.origin and spec.origin.endswith(".py"):
                data = Path(spec.origin).read_bytes()
        except (ImportError, ValueError, OSError, AttributeError):
            data = b""
        _SRC_CACHE[mod] = data
    return _SRC_CACHE[mod]


def parser_fingerprint(parser: ParserManifest) -> str:
    """Stable digest of HOW a parser runs and WHAT it needs, stored in the .done
    marker. A re-run re-parses only the parsers whose manifest or handler code
    changed -- so touching one handler no longer needs a global `--force`.

    Caveat: only the handler's OWN module is hashed; a change in a shared helper it
    imports (e.g. `_lincommon`, `win_systeminfo`) won't invalidate it -- touch the
    handler file or `--force` that run. Command/EZtool parsers hash the manifest
    only (a tool-binary update is handled separately by `aeng setup`)."""
    h = hashlib.sha1()
    core = repr([parser.id, parser.command, parser.handler, parser.short,
                 sorted(parser.requires), parser.tool.binary if parser.tool else None])
    h.update(core.encode("utf-8"))
    if parser.handler:
        h.update(_handler_source(parser.handler))
    return h.hexdigest()[:16]


def is_cached(parser: ParserManifest, out_dir: Path, force: bool = False) -> bool:
    """True if this parser already completed for `out_dir` with the SAME fingerprint
    (marker present, content matches, not forced). Lets the scheduler skip a re-run
    without dispatching it, while a changed parser re-runs on its own."""
    if force:
        return False
    try:
        return marker_path(out_dir, parser.id).read_text(
            encoding="utf-8").strip() == parser_fingerprint(parser)
    except OSError:
        return False


def cached_run(parser: ParserManifest, volume: str) -> ParserRun:
    """The ParserRun a cached (already-parsed) task reports without running."""
    return ParserRun(parser.id, volume, "skipped", 0.0, "already parsed")


def _fmt(token: str, ctx: ParserContext, binary: Path | None) -> str:
    return token.format(
        binary=str(binary) if binary else "",
        evidence=str(ctx.evidence),
        out=str(ctx.out),
        tools=str(ctx.tools),
        assets=str(ctx.assets),
        machine=ctx.machine_name,
    )


def _build_argv(command, ctx: ParserContext, binary: Path | None) -> list[str]:
    """Build the argv, substituting each element separately.

    If `command` is a list, each arg is passed as-is (robust with spaced paths).
    If it is a string (legacy), it is split with shlex before substitution.
    """
    tokens = command if isinstance(command, list) else shlex.split(command)
    return [_fmt(t, ctx, binary) for t in tokens]


# Common Windows crash exit codes (NTSTATUS).
_RC_LABELS = {
    0xC0000409: "stack buffer overrun (tool crash)",
    0xC0000005: "access violation (tool crash)",
    0xC00000FD: "stack overflow (tool crash)",
}


def _describe_rc(rc: int) -> str:
    """Format the exit code; for Windows crashes show it in hex with a label."""
    if rc < 0 or rc > 0x7FFFFFFF:
        code = rc & 0xFFFFFFFF
        label = _RC_LABELS.get(code)
        return f"rc=0x{code:08X}" + (f" {label}" if label else "")
    return f"rc={rc}"


def _clean_output_names(out_dir: Path, before: set[Path], short: str = "") -> None:
    """Tidy output names: drop RECmd's redundant timestamp subfolder and rename
    new CSVs to the clean `<short>_<subtype>` form (strips timestamps/_Output and
    redundant tool-name prefixes)."""
    # 1) RECmd writes the canonical CSV at out_dir/<csvf> AND a redundant copy under
    #    a "<timestamp>/" subfolder of per-hive CSVs. Drop that subfolder.
    for sub in list(out_dir.iterdir()):
        if sub.is_dir() and _TS_DIR.fullmatch(sub.name):
            shutil.rmtree(sub, ignore_errors=True)
    # 2) rename new CSVs to <short>_<subtype>.
    for f in list(out_dir.glob("*.csv")):
        if f in before:
            continue
        new = _short_stem(f.stem, short) + ".csv"
        if new != f.name:
            target = out_dir / new
            if not target.exists():
                try:
                    f.rename(target)
                except OSError:
                    pass


def _merge_into(work: Path, dest: Path) -> None:
    """Move everything the parser produced from its private work dir into the
    shared category folder (atomic per-file replace on the same filesystem)."""
    for item in list(work.iterdir()):
        target = dest / item.name
        try:
            if item.is_dir():
                if target.exists():
                    for sub in sorted(item.rglob("*")):
                        dst = target / sub.relative_to(item)
                        if sub.is_dir():
                            dst.mkdir(parents=True, exist_ok=True)
                        else:
                            dst.parent.mkdir(parents=True, exist_ok=True)
                            os.replace(sub, dst)
                else:
                    item.rename(target)
            else:
                os.replace(item, target)
        except OSError:
            pass


def _run_command(parser: ParserManifest, ctx: ParserContext) -> tuple[str, str]:
    binary = ctx.tools / parser.tool.binary
    if not binary.is_file():
        return "error", f"binary not found: {parser.tool.binary} (run 'aeng setup')"
    argv = _build_argv(parser.command, ctx, binary)
    rc, _out, err = procs.run(argv, timeout=parser.timeout)
    if rc == 0:
        return "ok", ""
    detail = _describe_rc(rc)
    err = (err or "").strip()
    if err:
        detail += f": {err[:160]}"
    return "error", detail


def _run_handler(parser: ParserManifest, ctx: ParserContext) -> tuple[str, str]:
    mod_name, _, func_name = parser.handler.partition(":")
    module = importlib.import_module(mod_name)
    func = getattr(module, func_name)
    func(ctx)
    return "ok", ""


def run_parser(parser: ParserManifest, ctx: ParserContext, force: bool = False) -> ParserRun:
    """Run a parser against a volume and return its result.

    Idempotent: on success it writes a marker; if the marker exists the parser is
    skipped (unless `force=True`), so re-runs don't re-parse what's already done.
    """
    start = time.monotonic()
    marker = marker_path(ctx.out, parser.id)
    if is_cached(parser, ctx.out, force):
        return cached_run(parser, ctx.volume)

    # Don't fire if a required artifact is missing on this volume
    for req in parser.requires:
        if not (ctx.evidence / req).exists():
            return ParserRun(parser.id, ctx.volume, "skipped", 0.0, "artifact missing")

    ctx.out.mkdir(parents=True, exist_ok=True)
    # Isolate this parser's outputs in a private work dir so `short`/cleanup only
    # ever touch THIS parser's files. Many parsers of the same category write into
    # the same folder concurrently (global pool); without isolation a `short`
    # parser would rename whatever lands there during its run window.
    work = ctx.out / f".work_{parser.id}"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    pctx = replace(ctx, out=work)
    try:
        if parser.command:
            status, detail = _run_command(parser, pctx)
        else:
            status, detail = _run_handler(parser, pctx)
    except HandlerSkip as e:
        status, detail = "skipped", str(e)[:200] or "nothing to do"
    except Exception as e:  # noqa: BLE001 - reported per parser, doesn't break the rest
        status, detail = "error", str(e)[:200]

    if status == "ok":
        _clean_output_names(work, set(), parser.short)
    _merge_into(work, ctx.out)
    shutil.rmtree(work, ignore_errors=True)

    if status == "ok":
        try:
            marker.write_text(parser_fingerprint(parser), encoding="utf-8")
        except OSError:
            pass

    return ParserRun(parser.id, ctx.volume, status, round(time.monotonic() - start, 2), detail)
