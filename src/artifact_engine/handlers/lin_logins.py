"""Handler: login history from the text `last`/`lastb`/`lastlog` outputs (UAC).

Complements the binary wtmp parser: lastb adds FAILED logins (brute-force /
spray) and lastlog gives the last login per account. Outputs:
  logins.csv   - successful (last) + failed (lastb), with a `result` column
  lastlog.csv  - most recent login per user
"""

from __future__ import annotations

import re

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

# Start of the time range, e.g. "Tue May 26 16:07" (with or without seconds).
_WHEN = re.compile(
    r"^(\S+)\s+(\S+)\s+(.*?)\s+("
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d+\s+\d{2}:\d{2}(?::\d{2})?)\s*(.*)$"
)


def _parse_last(lines: list[str], result: str, rows: list[list]) -> None:
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith(("wtmp begins", "btmp begins")):
            continue
        m = _WHEN.match(ln)
        if not m:
            continue
        user, tty, source, start, rest = m.groups()
        end = rest.strip()
        if end.startswith("- "):  # "- 15:07  (02:15)" -> "15:07  (02:15)"
            end = end[2:].strip()
        rows.append([result, user, tty, source.strip(), start, end])


def _parse_lastlog(lines: list[str], rows: list[list]) -> None:
    for ln in lines[1:]:  # skip "Username Port From Latest" header
        if "**Never logged in**" in ln or not ln.strip():
            continue
        parts = ln.split(None, 3)
        if len(parts) == 4:
            user, port, frm, latest = parts
            rows.append([user, port, frm, latest.strip()])
        elif len(parts) >= 2:  # no source recorded
            rows.append([parts[0], "", "", " ".join(parts[1:]).strip()])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    logins: list[list] = []
    lastlog: list[list] = []
    if lr:
        sysd = lr / "system"
        _parse_last(read_lines(sysd / "last.txt"), "ok", logins)
        _parse_last(read_lines(sysd / "lastb.txt"), "failed", logins)
        _parse_lastlog(read_lines(sysd / "lastlog.txt"), lastlog)
    write_csv(ctx.out, "logins.csv",
              ["result", "user", "tty", "source", "start_local", "end_local"], logins)
    write_csv(ctx.out, "lastlog.csv",
              ["user", "port", "source", "latest_local"], lastlog)
