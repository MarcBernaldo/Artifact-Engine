"""Handler: Hayabusa (Sigma-based EVTX analysis). Outputs: hayabusa*.csv

Hayabusa is the Windows-event-log Sigma engine. This is the Windows counterpart
of the Linux `sigma` parser (Sigma there runs over auditd/syslog; here over
EVTX). Runs the tool fetched by `aeng setup` into tools/hayabusa/ and produces
three views:

- hayabusa.csv         -- csv-timeline: the level-rated detection timeline.
- hayabusa_logon-*.csv -- logon-summary: per-user/host logon statistics
                          (lateral movement / brute force at a glance).
- hayabusa_base64.csv  -- extract-base64: base64 blobs pulled out of the logs
                          (encoded PowerShell etc.).

Non-interactive: csv-timeline needs `-w` (no wizard) AND `--sort` together.
Output is suppressed when a view has no rows, per the 0-row policy.
"""

from __future__ import annotations

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
    cwd = str(exe.parent)              # so default ./rules and ./config resolve
    d = ["-d", str(logs)]

    def _run(args: list[str]) -> None:
        rc, _out, err = procs.run([str(exe), *args], timeout=1800, cwd=cwd)
        if rc != 0 and ctx.log:
            ctx.log.warning(f"[!] hayabusa {args[0]} exit {rc}: {err.strip()[:200]}")

    # 1. Detection timeline.
    rules, config = exe.parent / "rules", exe.parent / "rules" / "config"
    tl = ctx.out / "hayabusa.csv"
    cmd = ["csv-timeline", *d, "-o", str(tl), "-w", "--sort", "-X", "-m", _MIN_LEVEL, *_QUIET]
    if rules.is_dir():
        cmd += ["-r", str(rules)]
    if config.is_dir():
        cmd += ["-c", str(config)]
    _run(cmd)
    _suppress_empty(tl)

    # 2. Logon summary (-o is a prefix -> several CSVs).
    _run(["logon-summary", *d, "-o", str(ctx.out / "hayabusa_logon"), *_QUIET])
    for f in ctx.out.glob("hayabusa_logon*"):
        _suppress_empty(f)

    # 3. Base64 strings hidden in the logs.
    b64 = ctx.out / "hayabusa_base64.csv"
    _run(["extract-base64", *d, "-o", str(b64), *_QUIET])
    _suppress_empty(b64)
