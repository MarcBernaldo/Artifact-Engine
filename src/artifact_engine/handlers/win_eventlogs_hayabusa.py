"""Handler: Hayabusa (Sigma-based EVTX analysis). Outputs: hayabusa*.csv

Hayabusa is the Windows-event-log Sigma engine. This is the Windows counterpart
of the Linux `sigma` parser (Sigma there runs over auditd/syslog; here over
EVTX). Runs the tool fetched by `aeng setup` into tools/hayabusa/ and produces
three views:

- hayabusa.csv         -- the level-rated detection timeline: `dfir-timeline`
                          since hayabusa 4, `csv-timeline` before it.
- hayabusa_logon-*.csv -- logon-summary: per-user/host logon statistics
                          (lateral movement / brute force at a glance).
- hayabusa_base64.csv  -- extract-base64: base64 blobs pulled out of the logs
                          (encoded PowerShell etc.).

Non-interactive: the timeline needs `-w` (no wizard) AND `--sort` together.
Output is suppressed when a view has no rows, per the 0-row policy.

A VIEW THAT FAILS IS AN ERROR. MEASURED: hayabusa 4 folded `csv-timeline` and
`json-timeline` into one `dfir-timeline`, so on a host where `aeng setup` fetched
the current release the timeline exited 2 at once -- "unrecognized subcommand" --
while logon-summary and extract-base64 ran. This handler logged a warning and
returned, so the parser read `ok`, there was no `hayabusa.csv`, and
`sigma_sources` skipped with "no hayabusa.csv to read": a machine's Sigma
detections gone, with nothing counted as an error. On the same acquisition 3.10's
`csv-timeline` and 4.0's `dfir-timeline` write the same ten columns and the same
rows, so which one runs is read off the build's own `help`. Nor is exit 0 taken on
its word: 3.x reports a fatal error with exit 0 and writes nothing (see `_run`).
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.core import procs
from artifact_engine.core.runner import HandlerSkip

# Minimum rule level for the timeline. "informational" is hayabusa's default but
# a firehose (benign logons etc.); "low" keeps real low+ detections.
_MIN_LEVEL = "low"
_QUIET = ["-q", "-Q", "-K", "-U"]      # no banner / no error logs / no color / UTC


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

    def _run(args: list[str], wrote) -> None:
        rc, out, err = procs.run([str(exe), *args], timeout=1800, cwd=cwd)
        said = _ANSI.sub("", f"{out}\n{err}")
        # 3.x reports a fatal error with exit 0. MEASURED with 3.10: rules it could
        # not find ended the timeline at once, "[ERROR] ... not found", exit 0, and
        # nothing written. So an [ERROR] line counts too -- but only when the view
        # wrote nothing, since a scan that finished may still complain about one log.
        if rc == 0 and ("[ERROR]" not in said or wrote()):
            return
        lines = [ln.strip() for ln in said.splitlines() if ln.strip()]
        first = next((ln for ln in lines if "[ERROR]" in ln), lines[0] if lines else "")
        failed.append(f"{args[0]} exit {rc}" + (f" ({first[:120]})" if first else ""))
        if ctx.log:
            ctx.log.warning(f"[!] hayabusa {args[0]} exit {rc}: {first[:200]}")

    # 1. Detection timeline.
    rules, config = exe.parent / "rules", exe.parent / "rules" / "config"
    tl = ctx.out / "hayabusa.csv"
    cmd = [timeline, *d, "-o", str(tl), "-w", "--sort", "-X", "-m", _MIN_LEVEL, *_QUIET]
    if rules.is_dir():
        cmd += ["-r", str(rules)]
    if config.is_dir():
        cmd += ["-c", str(config)]
    _run(cmd, tl.is_file)
    _suppress_empty(tl)

    # 2. Logon summary (-o is a prefix -> several CSVs).
    _run(["logon-summary", *d, "-o", str(ctx.out / "hayabusa_logon"), *_QUIET],
         lambda: any(ctx.out.glob("hayabusa_logon*")))
    for f in ctx.out.glob("hayabusa_logon*"):
        _suppress_empty(f)

    # 3. Base64 strings hidden in the logs.
    b64 = ctx.out / "hayabusa_base64.csv"
    _run(["extract-base64", *d, "-o", str(b64), *_QUIET], b64.is_file)
    _suppress_empty(b64)

    if failed:
        # After every view, not at the first failure: what the others wrote is kept
        # (the runner merges it), and without a marker the next run tries again.
        raise RuntimeError(f"hayabusa: {'; '.join(failed)}")
