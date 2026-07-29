"""Run a single parser against a volume.

Resolves the command templates, checks the artifact exists and runs the tool
(external binary) or the Python handler. Returns a ParserRun with status,
duration and detail for the execution manifest and the report.
"""

from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.util
import os
import re
import shlex
import shutil
import time
import traceback
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
_PKG = "artifact_engine"


def _module_file(mod: str) -> Path | None:
    """Path of a first-party module's .py file, or None if it is not one."""
    try:
        spec = importlib.util.find_spec(mod)
    except (ImportError, ValueError, AttributeError):
        return None
    if spec and spec.origin and spec.origin.endswith(".py"):
        return Path(spec.origin)
    return None


def _first_party_imports(src: bytes, mod: str) -> set[str]:
    """Names under `artifact_engine` that `src` imports, absolute or relative.

    `from .lin_yara import _compile_rules` yields both the module and the dotted
    attribute; the attribute simply fails to resolve later and is dropped, which
    is cheaper than deciding here which names are modules.
    """
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return set()
    pkg = mod.rpartition(".")[0]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:                       # relative: climb out of the package
                base = pkg
                for _ in range(node.level - 1):
                    base = base.rpartition(".")[0]
                base = f"{base}.{node.module}" if node.module else base
            elif node.module:
                base = node.module
            else:
                continue
            found.add(base)
            found.update(f"{base}.{a.name}" for a in node.names)
    return {m for m in found if m == _PKG or m.startswith(_PKG + ".")}


def _handler_closure(handler: str) -> bytes:
    """Source of the handler module AND of every first-party module it reaches.

    Hashing only the handler's own file was the earlier behaviour and it was
    wrong in the dangerous direction: 51 of the handlers share `_lincommon`, and
    a dozen import private helpers from a sibling handler, so fixing a bug in a
    shared writer left every already-processed case serving output from the
    broken version -- for good, since a `.done` never expires. Over-invalidating
    costs one re-parse; under-invalidating costs a wrong answer nobody sees.
    """
    root = handler.partition(":")[0]
    if root in _SRC_CACHE:
        return _SRC_CACHE[root]
    seen: dict[str, bytes] = {}
    queue = [root]
    while queue:
        mod = queue.pop()
        if mod in seen:
            continue
        path = _module_file(mod)
        if path is None:                         # attribute, namespace pkg or C ext
            seen[mod] = b""
            continue
        try:
            seen[mod] = path.read_bytes()
        except OSError:
            seen[mod] = b""
            continue
        queue.extend(_first_party_imports(seen[mod], mod) - seen.keys())
    # Names are part of the digest: moving a helper between modules is a change.
    blob = b"".join(f"\n--{m}--\n".encode() + seen[m] for m in sorted(seen))
    _SRC_CACHE[root] = blob
    return blob


def parser_fingerprint(parser: ParserManifest) -> str:
    """Stable digest of HOW a parser runs and WHAT it needs, stored in the .done
    marker. A re-run re-parses only the parsers whose manifest or handler code
    changed -- so touching one handler no longer needs a global `--force`.

    The handler's whole first-party import closure is hashed, not just its own
    module, so editing a shared helper re-parses everything that reaches it. That
    is deliberately blunt: a helper high in the graph invalidates most of the set,
    which costs one re-parse, whereas the alternative served stale output from a
    version known to be broken. Command/EZtool parsers hash the manifest only (a
    tool-binary update is handled separately by `aeng setup`)."""
    h = hashlib.sha1()
    core = repr([parser.id, parser.command, parser.handler, parser.short,
                 sorted(parser.requires), parser.tool.binary if parser.tool else None])
    h.update(core.encode("utf-8"))
    if parser.handler:
        h.update(_handler_closure(parser.handler))
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
    except (OSError, ValueError):
        # ValueError covers UnicodeDecodeError: a marker half-written when the
        # machine lost power, or when the parent process died the way §12 of the
        # architecture doc describes. This runs OUTSIDE the pools, before any
        # task is dispatched, so letting it raise would end the whole run over
        # one unreadable byte. An undecodable marker just means "not cached".
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


def _merge_into(work: Path, dest: Path) -> list[str]:
    """Move everything the parser produced from its private work dir into the
    shared category folder (atomic per-file replace on the same filesystem).

    Returns the names it could NOT move. The usual cause is the analyst having the
    previous CSV open in Excel, which holds a Windows lock: the parser worked, the
    result cannot land, and reporting "ok" there would both hide the loss and write
    a .done marker claiming the volume was parsed."""
    failed: list[str] = []
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
            failed.append(item.name)
    return failed


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
        # The type is half the diagnosis. Bare str(e) on a KeyError is a single
        # quoted token, which reads like a corrupt-evidence message when it may
        # instead be a parser broken on every machine in the case -- and since no
        # .done is written, every re-run reproduces the same uninformative line.
        # The traceback goes to the log file only; the console is the analyst's.
        status, detail = "error", f"{type(e).__name__}: {e}"[:200]
        log.debug(f"{parser.id} @{ctx.machine_name}: {traceback.format_exc()}")

    if status == "ok":
        _clean_output_names(work, set(), parser.short)
    stuck = _merge_into(work, ctx.out)
    shutil.rmtree(work, ignore_errors=True)

    if stuck and status == "ok":
        # The parse succeeded but its output could not be written. Say so and skip
        # the marker, so the next run retries instead of trusting a phantom result.
        status = "error"
        detail = (f"could not write {len(stuck)} output(s): {', '.join(sorted(stuck)[:3])}"
                  " - is one open in Excel or another program?")

    if status == "ok":
        try:
            marker.write_text(parser_fingerprint(parser), encoding="utf-8")
        except OSError:
            pass

    return ParserRun(parser.id, ctx.volume, status, round(time.monotonic() - start, 2), detail)
