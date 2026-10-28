"""The `timeline` view of a machine's `.db`: every timed row of every table, one
shape, no data copied (v0.7.172).

A table is in it when the time of each of its rows is known to be UTC, which
ARCHITECTURE §5 says a column name tells: `time_utc` (the Linux logs, logins,
shell history, auditd, ...), and the `TimeCreated` of the EvtxECmd channels
(`art_evtx_*`), which that tool renders in UTC. Each row of the view is

    time_utc    'YYYY-MM-DD HH:MM:SS' (sub-seconds and a `T` separator dropped,
                so every table sorts and compares as the same text)
    tbl         the table it comes from
    row_id      its rowid there: `SELECT * FROM "<tbl>" WHERE rowid = <row_id>`
    suspicious  the table's own `suspicious`, or '' where it has none
    summary     a few of its describing columns, `name=value` joined by ` | `

Out of it, stated: a table whose times have another name (`first_seen_utc`,
`mtime_utc`, `start_time_utc`, SRUM's `Timestamp`, ...) -- an aggregate's first
and last sighting, or one of several times of one file, is not one event at one
moment, and a view that picked one of them would be a guess; and every row whose
time is empty. A view costs nothing until it is read; read it with an ORDER BY
and a time window, since the logs make it millions of rows:

    SELECT * FROM timeline WHERE time_utc >= '2026-05-01' AND time_utc < '2026-05-03'
    ORDER BY time_utc        -- text: the upper bound is the day after, exclusive
"""

from __future__ import annotations

import sqlite3

from artifact_engine.logging_setup import get_logger

log = get_logger()

VIEW = "timeline"

# Columns that say what a row is, most telling first; the first few a table has
# make the summary.
_DESCRIBING = ("event", "type", "MapDescription", "rule", "program", "message", "command",
               "cmdline", "user", "UserName", "account", "auid", "source", "host",
               "RemoteHost", "addr", "detail", "reason", "PayloadData1", "PayloadData2",
               "path", "file")
_SUMMARY_COLUMNS = 5


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _lit(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _time_column(table: str, cols: list[str]) -> str | None:
    if "time_utc" in cols:
        return "time_utc"
    if table.lower().startswith("art_evtx_") and "TimeCreated" in cols:
        return "TimeCreated"
    return None


def _select(table: str, cols: list[str], tcol: str) -> str:
    t = f"substr(replace({_q(tcol)}, 'T', ' '), 1, 19)"
    sus = _q("suspicious") if "suspicious" in cols else "''"
    parts = [c for c in _DESCRIBING if c in cols and c != tcol][:_SUMMARY_COLUMNS]
    # each non-empty column as ' | name=value', the first separator cut off
    pieces = [f"CASE WHEN COALESCE({_q(c)}, '') = '' THEN '' "
              f"ELSE {_lit(' | ' + c + '=')} || {_q(c)} END" for c in parts]
    summary = f"substr({' || '.join(pieces)}, 4)" if pieces else "''"
    return (f"SELECT {t} AS time_utc, {_lit(table)} AS tbl, rowid AS row_id, "
            f"COALESCE({sus}, '') AS suspicious, {summary} AS summary "
            f"FROM {_q(table)} WHERE COALESCE({_q(tcol)}, '') <> ''")


def create(conn: sqlite3.Connection) -> int:
    """(Re)create the view over the tables now in `conn`. Returns how many tables
    it covers; 0 leaves no view. Never raises: a `.db` without its timeline is
    still the `.db`."""
    try:
        tables = [t for (t,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
        selects = []
        for t in tables:
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({_q(t)})")]
            tcol = _time_column(t, cols)
            if tcol:
                selects.append(_select(t, cols, tcol))
        conn.execute(f"DROP VIEW IF EXISTS {_q(VIEW)}")
        if selects:
            conn.execute(f"CREATE VIEW {_q(VIEW)} AS " + "\nUNION ALL\n".join(selects))
        conn.commit()
        return len(selects)
    except sqlite3.Error as e:
        log.warning(f"[!] timeline view not created: {e}")
        return 0
