"""How far back this machine's logging reaches, on the front page.

The findings section says what was flagged. This says what could have been
flagged AT ALL -- and it is printed first, because the two are read together or
neither is read correctly. A channel that holds ten days cannot report an
intrusion from three weeks ago, and its silence is indistinguishable from a quiet
host unless somebody says so on the same page.

The measuring is done by the parsers (`log_coverage` on Windows, `log_integrity`
on Linux); this only reads the table back out of the consolidated database and
lays it out. A machine whose parser did not run has no table, and then there is
no section -- an absent measurement is not reported as full coverage.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# Windows: written by win_log_coverage. Linux: by lin_log_integrity, whose
# `rotations` rows answer the same question for /var/log.
_TABLES = ("log_coverage", "log_integrity")

# Order the channels the way an analyst reads them: what is wrong, then what
# limits the window, then the rest.
_KIND_ORDER = {"full dump": 0, "absent": 1, "filtered dump": 2}

_MAX_ROWS = 40


def _s(row: dict, key: str) -> str:
    """A row's value as text. Every column here arrives from SQLite, where an
    all-numeric CSV column comes back as an int and a missing one as None."""
    value = row.get(key)
    return "" if value is None else str(value)


def _rows(conn: sqlite3.Connection, table: str) -> list[dict]:
    cur = conn.execute(f'SELECT * FROM "{table}"')
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def read(db: Path) -> tuple[str, list[dict]]:
    """(table name, rows) from the first coverage table present, or ("", [])."""
    if not db.is_file():
        return "", []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error:
        return "", []
    try:
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        have = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for t in _TABLES:
            if t in have:
                try:
                    return t, _rows(conn, t)
                except sqlite3.Error:
                    return "", []
    finally:
        conn.close()
    return "", []


def _windows_lines(rows: list[dict]) -> list[str]:
    """One line per channel: the span, then the verdict that qualifies it."""
    def key(r: dict) -> tuple:
        return (_KIND_ORDER.get(_s(r, "kind"), 3),
                _s(r, "suspicious") != "yes", _s(r, "channel"))

    channels = [r for r in rows if _s(r, "kind") in _KIND_ORDER]
    events = [r for r in rows if _s(r, "kind").startswith("event ")]
    if not channels and not events:
        return []

    width = max((len(_s(r, "channel")) for r in channels), default=8)
    width = min(max(width, 8), 52)

    out = ["", "Log coverage (how far back this host's logging reaches):"]
    for r in sorted(channels, key=key)[:_MAX_ROWS]:
        first, last = _s(r, "first_event_utc"), _s(r, "last_event_utc")
        span = f"{first} .. {last}" if first and last else "-"
        total = _s(r, "span_days")
        seen = f"{_s(r, 'days_with_events')}/{total}d with events" if total else ""
        mark = "!" if _s(r, "suspicious") == "yes" else " "
        out.append(f"  {mark} {_s(r, 'channel')[:width]:<{width}}  "
                   f"{span:<25}  {seen}".rstrip())
        out.append(f"      {_s(r, 'verdict')}")
    if events:
        out.append("")
        for r in sorted(events, key=lambda e: _s(e, "kind")):
            mark = "!" if _s(r, "suspicious") == "yes" else " "
            out.append(f"  {mark} {_s(r, 'kind'):<10} {_s(r, 'channel'):<10} "
                       f"{_s(r, 'verdict')}".rstrip())
    return out


def _linux_lines(rows: list[dict]) -> list[str]:
    """The Linux table answers the same question in its `rotations` rows: how many
    archives /var/log kept, and the span they cover."""
    rot = [r for r in rows if _s(r, "status") == "rotations"]
    bad = [r for r in rows if _s(r, "suspicious") == "yes"]
    if not rot and not bad:
        return []
    out = ["", "Log coverage (how far back this host's logging reaches):"]
    width = max((len(_s(r, "artifact")) for r in rot + bad), default=8)
    width = min(max(width, 8), 40)
    for r in sorted(rot, key=lambda e: _s(e, "artifact"))[:_MAX_ROWS]:
        out.append(f"    {_s(r, 'artifact'):<{width}}  {_s(r, 'detail')}".rstrip())
    for r in sorted(bad, key=lambda e: _s(e, "artifact"))[:_MAX_ROWS]:
        out.append(f"  ! {_s(r, 'artifact'):<{width}}  "
                   f"{_s(r, 'status')}: {_s(r, 'detail')}".rstrip())
    return out


def render(table: str, rows: list[dict]) -> list[str]:
    """The report.txt section, or nothing when the machine has no such table."""
    if not rows:
        return []
    lines = _windows_lines(rows) if table == "log_coverage" else _linux_lines(rows)
    if not lines:
        return []
    lines.append("")
    lines.append("  A channel is only as good as the window it covers: silence outside")
    lines.append("  these ranges is absence of evidence, not evidence of absence.")
    return lines
