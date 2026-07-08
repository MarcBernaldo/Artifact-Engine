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
            f"Set-Location '{ps1.parent}'; "
            f"& '{ps1}' '{evtx}' | Export-Csv -NoTypeInformation -Encoding UTF8 -Path '{out_csv}'"
        )
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps]
        procs.run(cmd, timeout=1800)
