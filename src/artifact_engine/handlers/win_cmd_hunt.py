"""Handler: one search of every Windows command line, for every catalog (v0.7.104).
Output: alert_exfil_commands.csv, alert_suspicious_commands.csv

The command-line sibling of `win_exec_hunt`. Every command line the machine
kept -- PowerShell history, the live response's processes, scheduled tasks,
service ImagePaths, PowerShell's own event logs (400/800 host application,
4104 script blocks, 4103 pipeline payloads) and Sysmon 1 (`_commands`) -- is
reduced to its distinct lines once (`_exfil.collect`) and every catalog runs
over that one list:

  alert_exfil_commands       LOLExfil's endpoint patterns (`_exfil`), the most telling
                       match per line and tool;
  alert_suspicious_commands  the analyst's `suspicious_tools.txt`, every category --
                       named tools AND the actions (`procdump ... lsass`,
                       `vssadmin delete shadows`) the file-name hunt leaves out --
                       several joined with `+`, as the history's `flag` column.

Each row carries the source, the account, how many times the line was seen and
its first and last UTC time. Replaces `alert_exfil_commands` (v0.7.101), which read
the history and the live processes only.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _exfil, _wtfbins
from artifact_engine.handlers._commands import commands
from artifact_engine.handlers._indicators import combined, load_indicators
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers._tables import machine_root

SUSPICIOUS = "alert_suspicious_commands.csv"
SUSPICIOUS_HEADER = ["category", "source", "who", "command", "first_seen_utc",
                     "last_seen_utc", "count", "known_benign"]


def flag(lines: list[_exfil.Line], rules, notes: dict[str, str] | None = None) -> list[list]:
    """One row per line that any `suspicious_tools.txt` rule matches. `notes` (WTFBins)
    annotates a line whose program -- or, for a process, the process -- is a known
    look-alike; the row stays."""
    notes = notes or {}
    if not rules:
        return []
    gate = combined(rules)
    rows = []
    for ln in lines:
        if gate is not None and not gate.search(ln.text):
            continue
        labels = [label for label, rx in rules if rx.search(ln.text)]
        if labels:
            note = notes.get(_wtfbins.program(ln.text)) or (
                notes.get(ln.who.rsplit(" ", 1)[-1].lower(), "") if ln.source == "process" else "")
            rows.append(["+".join(dict.fromkeys(labels)), ln.source, ln.who,
                         ln.text[:_exfil._COMMAND_CHARS], ln.first_utc, ln.last_utc, ln.count,
                         note])
    return sorted(rows, key=lambda r: (r[0], r[1], r[3]))


def run(ctx) -> None:
    assets = Path(ctx.assets)
    patterns = _exfil.load(assets)
    rules = load_indicators(assets / "suspicious_tools.txt")
    if not patterns and not rules:
        raise HandlerSkip(f"no command-line catalog ({_exfil.ASSET} / suspicious_tools.txt)")
    lines = _exfil.collect(commands(ctx, machine_root(Path(ctx.out)) / "CSVs"))
    if patterns:
        write_csv(ctx.out, _exfil.TABLE, _exfil.HEADER, _exfil.scan(lines, patterns))
    if rules:
        write_csv(ctx.out, SUSPICIOUS, SUSPICIOUS_HEADER,
                  flag(lines, rules, _wtfbins.load(assets)))
