"""Handler: Windows command lines that look like data leaving the host.
Output: exfil_commands.csv (see `_exfil`).

Command lines from each user's PowerShell history (ConsoleHost_history.txt)
and, on the live volume, the running processes of a Velociraptor LiveResponse,
matched against LOLExfil's patterns.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _exfil
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_consolehost import iter_history
from artifact_engine.handlers.win_liveresponse_velociraptor import (
    _artifact_key,
    _find_results,
    _read_jsonl,
)


def _lines(ctx):
    for user, _seq, cmd in iter_history(Path(ctx.evidence)):
        yield "powershell_history", user, cmd
    if str(ctx.volume).upper().startswith("VSS"):
        return                                   # LiveResponse is the live host's
    results = _find_results(ctx)
    if results is None:
        return
    for f in results.glob("*.json"):
        if _artifact_key(f) == "Windows.System.Pslist":
            for p in _read_jsonl(f):
                who = f"pid {p.get('Pid')} {p.get('Name') or ''}".strip()
                yield "liveresponse_process", who, p.get("CommandLine") or ""


def run(ctx) -> None:
    patterns = _exfil.load(Path(ctx.assets))
    if not patterns:
        raise HandlerSkip(f"no LOLExfil patterns ({_exfil.ASSET})")
    write_csv(ctx.out, _exfil.TABLE, _exfil.HEADER, _exfil.scan(_lines(ctx), patterns))
