"""Handler: DeepBlueCLI (SANS) over the Event Logs.

DeepBlue.ps1 is a PowerShell script that analyzes a .evtx for suspicious activity
(obfuscated PowerShell, brute force, persistence, etc.). It is run per log and the
result is written to DeepBlue-<log>.csv (normalized to deepblue_<log> via short).
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core import procs

# Logs where DeepBlueCLI adds value.
_LOGS = [
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Windows PowerShell.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
]


def _ps_quote(path: Path) -> str:
    """A path as a PowerShell single-quoted literal.

    Everything else here passes argv lists to CreateProcess, but DeepBlue needs a
    pipeline, so this one builds a `-Command` string - and inside a single-quoted
    PowerShell string the only escape is a doubled quote. A case folder whose name
    carries an apostrophe (`C:\\Cases\\Web d'Exemple compromesa`) - routine in
    Catalan, Spanish, French and Irish naming - otherwise ends the string early:
    the rest of the path is parsed as code, the command fails, and the logs for
    that machine are silently never analysed.
    """
    return "'" + str(path).replace("'", "''") + "'"


def _find_ps1(tools: Path) -> Path | None:
    direct = tools / "deepbluecli-master" / "DeepBlue.ps1"
    if direct.is_file():
        return direct
    return next(tools.rglob("DeepBlue.ps1"), None)


def run(ctx) -> None:
    ps1 = _find_ps1(ctx.tools)
    if ps1 is None:
        raise RuntimeError("DeepBlue.ps1 not found (run 'aeng setup')")

    logs_dir = ctx.evidence / "Windows" / "System32" / "winevt" / "Logs"
    ctx.out.mkdir(parents=True, exist_ok=True)

    for log in _LOGS:
        evtx = logs_dir / log
        if not evtx.is_file():
            continue
        safe = log.replace("%4", "-").replace(" ", "").replace(".evtx", "")
        out_csv = ctx.out / f"DeepBlue-{safe}.csv"
        # Set-Location to the script folder: DeepBlue reads regexes.txt relative to the CWD.
        # -Command receives the WHOLE pipeline as a single argument (there is no shell here).
        ps = (
            f"Set-Location {_ps_quote(ps1.parent)}; "
            f"& {_ps_quote(ps1)} {_ps_quote(evtx)} | "
            f"Export-Csv -NoTypeInformation -Encoding UTF8 -Path {_ps_quote(out_csv)}"
        )
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps]
        procs.run(cmd, timeout=1800)
