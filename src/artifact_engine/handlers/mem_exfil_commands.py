"""Handler: command lines in a memory image that look like data leaving the host.
Output: exfil_commands.csv (see `_exfil`).

Every process's command line as mem_findings assembles it (cmdline, else the
pstree's), matched against LOLExfil's patterns. mem_findings raises each row
as an `exfil_command` alert.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _exfil
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.mem_findings import _TABLES, _processes, _read


def run(ctx) -> None:
    patterns = _exfil.load(Path(ctx.assets))
    if not patterns:
        raise HandlerSkip(f"no LOLExfil patterns ({_exfil.ASSET})")
    base = Path(ctx.evidence) / "CSVs"
    t = {name: _read(base, name) for name in _TABLES}
    if not t["mem_pslist"] and not t["mem_psscan"]:
        raise HandlerSkip("no process table from the memory image (pslist/psscan)")
    lines = ((("memory_process", f"pid {pid} {p['process']}", p["cmdline"])
              for pid, p in sorted(_processes(t).items())))
    write_csv(ctx.out, _exfil.TABLE, _exfil.HEADER, _exfil.scan(lines, patterns))
