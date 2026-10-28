"""Handler: Hayabusa (Sigma-based EVTX analysis). Outputs: hayabusa*.csv

Hayabusa is the Windows-event-log Sigma engine. This is the Windows counterpart
of the Linux `sigma` parser (Sigma there runs over auditd/syslog; here over
EVTX). Runs the tool fetched by `aeng setup` into tools/hayabusa/ and produces
two views:

- art_hayabusa.csv         -- the level-rated detection timeline: `dfir-timeline`
                          since hayabusa 4, `csv-timeline` before it.
- art_hayabusa_base64.csv  -- extract-base64: base64 blobs pulled out of the logs
                          (encoded PowerShell etc.).

Its logon-summary view is not run any more (v0.7.161): per-user/host logon counts
are what art_evtx_security and the lateral-movement graph already hold, edge by edge.

Non-interactive: the timeline needs `-w` (no wizard) AND `--sort` together.
Output is suppressed when a view has no rows, per the 0-row policy.

A VIEW THAT FAILS IS AN ERROR (one exception, below). MEASURED: hayabusa 4
folded `csv-timeline` and `json-timeline` into one `dfir-timeline`, so on a
host where `aeng setup` fetched
the current release the timeline exited 2 at once -- "unrecognized subcommand" --
while the other views ran. This handler logged a warning and
returned, so the parser read `ok`, there was no `art_hayabusa.csv`, and
`alert_hayabusa` skipped with "no art_hayabusa.csv to read": a machine's Sigma
detections gone, with nothing counted as an error. On the same acquisition 3.10's
`csv-timeline` and 4.0's `dfir-timeline` write the same ten columns and the same
rows, so which one runs is read off the build's own `help`. Nor is exit 0 taken on
its word: 3.x reports a fatal error with exit 0 and writes nothing (see `_run`).

ONE CORRUPT LOG DOES NOT TAKE THE BASE64 VIEW (v0.7.125). MEASURED with 3.10
and 4.1.0: `extract-base64 -d` panics (exit 101, a slice out of range in the
evtx crate) on one snapshot's corrupt log, and the parser was an error on
every run. On a 101 the view is asked again one log at a time (`-f`), the
parts are joined under one header, and the logs that panic are NAMED in a
warning: their strings are what is missing, not the machine's. Any other
failure of a per-log run is still an error, as is a 101 from the other views.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from artifact_engine.core import procs
from artifact_engine.core.runner import HandlerSkip

# Minimum rule level for the timeline. "informational" is hayabusa's default but
# a firehose (benign logons etc.); "low" keeps real low+ detections.
_MIN_LEVEL = "low"
_QUIET = ["-q", "-Q", "-K", "-U"]      # no banner / no error logs / no color / UTC
_PANIC = 101                           # a Rust panic: the tool crashed, not refused


def _find_exe(tools: Path) -> Path | None:
    haya = tools / "hayabusa"
    if haya.is_dir():
        return next(iter(haya.glob("hayabusa*.exe")), None) or next(iter(haya.rglob("hayabusa*.exe")), None)
    return None


_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Newest first. Hayabusa 4 folded csv-timeline and json-timeline into one
# `dfir-timeline`, whose output type defaults to CSV; 3.x has only the old name.
_TIMELINE_SUBCOMMANDS = ("dfir-timeline", "csv-timeline")


def timeline_subcommand(help_text: str) -> str | None:
    """The timeline subcommand this build offers, read off its own `help`.

    Asked of the binary, not inferred from the version in its file name: the name
    is what `setup` saved, the command list is what the binary will parse. Only
    the first word of an indented line counts, so a description that mentions
    another subcommand is not mistaken for it.
    """
    listed = {line.split()[0] for line in _ANSI.sub("", help_text).splitlines()
              if line.startswith("  ") and line.split()}
    return next((s for s in _TIMELINE_SUBCOMMANDS if s in listed), None)


def _suppress_empty(path: Path) -> None:
    """Drop a header-only / missing CSV (0-row policy)."""
    try:
        if not path.is_file() or sum(1 for _ in path.open(encoding="utf-8", errors="replace")) <= 1:
            path.unlink(missing_ok=True)
    except OSError:
        pass


def _base64_log_by_log(evtx: list[Path], dest: Path, run_view) -> list[str]:
    """`extract-base64 -f` over each log, joined into `dest` under one header.

    Returns the names of the logs that panicked. Any other failure goes through
    `run_view` and is an error like any view's. The parts are joined as bytes --
    the header line of every part after the first is dropped -- so a row is
    exactly what hayabusa wrote."""
    parts = dest.parent / ".hayabusa_base64_parts"
    shutil.rmtree(parts, ignore_errors=True)
    parts.mkdir(parents=True)
    dest.unlink(missing_ok=True)       # whatever the crashed run left
    panicked: list[str] = []
    try:
        with dest.open("wb") as out:
            header = False
            for i, log in enumerate(evtx):
                part = parts / f"{i}.csv"
                rc = run_view(["extract-base64", "-f", str(log), "-o", str(part), *_QUIET],
                              part.is_file, panic_ok=True)
                if rc == _PANIC:
                    panicked.append(log.name)
                    continue
                if not part.is_file():
                    continue
                with part.open("rb") as fh:
                    first = fh.readline()
                    if not header:
                        out.write(first)
                        header = True
                    shutil.copyfileobj(fh, out)
    finally:
        shutil.rmtree(parts, ignore_errors=True)
    return panicked


def run(ctx) -> None:
    exe = _find_exe(ctx.tools)
    if exe is None:
        raise HandlerSkip("hayabusa not installed (run 'aeng setup')")

    logs = ctx.evidence / "Windows" / "System32" / "winevt" / "Logs"
    if not logs.is_dir() or not next(iter(logs.glob("*.evtx")), None):
        raise HandlerSkip("no EVTX logs")

    ctx.out.mkdir(parents=True, exist_ok=True)
    # Resolved: hayabusa is started IN its own folder, so a relative tools dir handed
    # it `-r`/`-c` paths relative to a cwd they were never relative to -- measured,
    # "[ERROR] ... not found" and an empty timeline.
    exe = exe.resolve()
    cwd = str(exe.parent)              # so default ./rules and ./config resolve
    d = ["-d", str(logs)]

    _rc, listing, listing_err = procs.run([str(exe), "help"], timeout=120, cwd=cwd)
    timeline = timeline_subcommand(f"{listing}\n{listing_err}")
    if timeline is None:
        raise RuntimeError(f"{exe.name} lists no timeline subcommand this engine knows "
                           f"(looked for {', '.join(_TIMELINE_SUBCOMMANDS)})")
    failed: list[str] = []

    def _run(args: list[str], wrote, panic_ok: bool = False) -> int:
        rc, out, err = procs.run([str(exe), *args], timeout=1800, cwd=cwd)
        if panic_ok and rc == _PANIC:
            return rc                  # the caller asks again, log by log
        said = _ANSI.sub("", f"{out}\n{err}")
        # 3.x reports a fatal error with exit 0. MEASURED with 3.10: rules it could
        # not find ended the timeline at once, "[ERROR] ... not found", exit 0, and
        # nothing written. So an [ERROR] line counts too -- but only when the view
        # wrote nothing, since a scan that finished may still complain about one log.
        if rc == 0 and ("[ERROR]" not in said or wrote()):
            return rc
        lines = [ln.strip() for ln in said.splitlines() if ln.strip()]
        first = next((ln for ln in lines if "[ERROR]" in ln), lines[0] if lines else "")
        failed.append(f"{args[0]} exit {rc}" + (f" ({first[:120]})" if first else ""))
        if ctx.log:
            ctx.log.warning(f"[!] hayabusa {args[0]} exit {rc}: {first[:200]}")
        return rc

    # 1. Detection timeline.
    rules, config = exe.parent / "rules", exe.parent / "rules" / "config"
    tl = ctx.out / "art_hayabusa.csv"
    cmd = [timeline, *d, "-o", str(tl), "-w", "--sort", "-X", "-m", _MIN_LEVEL, *_QUIET]
    if rules.is_dir():
        cmd += ["-r", str(rules)]
    if config.is_dir():
        cmd += ["-c", str(config)]
    _run(cmd, tl.is_file)
    _suppress_empty(tl)

    # 2. Base64 strings hidden in the logs.
    b64 = ctx.out / "art_hayabusa_base64.csv"
    if _run(["extract-base64", *d, "-o", str(b64), *_QUIET], b64.is_file,
            panic_ok=True) == _PANIC:
        panicked = _base64_log_by_log(sorted(logs.glob("*.evtx")), b64, _run)
        if panicked and ctx.log:
            ctx.log.warning(
                f"[!] hayabusa extract-base64 crashed on {len(panicked)} log(s) -- their "
                f"base64 strings are NOT in art_hayabusa_base64.csv: "
                f"{', '.join(panicked[:10])}" + (" ..." if len(panicked) > 10 else ""))
    _suppress_empty(b64)

    if failed:
        # After every view, not at the first failure: what the others wrote is kept
        # (the runner merges it), and without a marker the next run tries again.
        raise RuntimeError(f"hayabusa: {'; '.join(failed)}")
