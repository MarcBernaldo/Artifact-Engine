"""What a SQLite browser needs from a machine's `.db`: indexes and views.

The `.db` is where a case is worked. Two things make it quicker to work in, and
both are part of the file, so any SQLite browser uses them without knowing this
engine exists:

- **Indexes** on the columns a question is asked by: the time columns of the big
  tables, and the handful of columns an analyst pivots on (an event id, a file
  name, a client address). Measured on real cases: one index costs about a
  second and 27 MB per million rows, and a question by hour, by exact value or
  "the newest hundred" over 17 million rows went from four seconds to nothing.
  A "contains" filter cannot use an index to find its rows, but it reads the
  index instead of the table and came out two to five times faster.
- **Views**, which a browser lists beside the tables and which cost nothing to
  store: `v_alerts` is every finding of the machine in one place, most severe
  first, `v_logons` every logon with its type spelled out, and `v_timeline`
  (AE-046) both of those and the small dated sources in one UTC order.

Nothing here may fail a build. An index or a view that could not be created is a
slower or a longer way to the same rows; the tables are the deliverable.
"""

from __future__ import annotations

import sqlite3

from artifact_engine.core import findings
from artifact_engine.logging_setup import get_logger

log = get_logger()

# Below this a whole-table scan is hundredths of a second (measured: 62,031 rows,
# 0.03 s), and the index would be bytes and build time for nothing.
INDEX_MIN_ROWS = 100_000

# Time indexes per table. A bodyfile has four time columns and all four are asked
# by; an MFT has eight and nobody sorts by the 0x30 ones.
_MAX_TIME_INDEXES = 4

# The time columns of the tables an external tool writes, and the engine's own
# with no basis suffix (ARCHITECTURE section 5), lower-case.
_TIME_NAMED = ("timestamp", "timecreated", "updatetimestamp", "created0x10",
               "lastmodified0x10", "lastwritetimestamp", "first_seen", "last_seen")

# What an analyst pivots on besides time, by table and by table prefix.
_KEY_COLUMNS = {"art_mft": ("FileName",), "art_usn": ("Name",),
                "art_web_access": ("source_ip",)}
_KEY_PREFIXES = {"art_evtx_": ("EventId",)}

VIEW_ALERTS = "v_alerts"
VIEW_LOGONS = "v_logons"
VIEW_TIMELINE = "v_timeline"

# The small sources of v_timeline besides the alerts and the logons (AE-046):
# (table, its UTC time column, kind, the columns of the summary). What a program,
# a service, a task, a download or a command did, when. The MFT, the USN and the
# full event-log channels stay out: the timeline points at an hour and the
# indexes take the analyst from there. A `_local` column is no source: it does
# not sort with the rest.
_TIMELINE_SOURCES = (
    ("art_prefetch", "LastRun", "execution (prefetch)", ("ExecutableName", "RunCount")),
    ("art_amcache_associated_files", "FileKeyLastWriteTimestamp", "program (amcache)",
     ("FullPath", "SHA1")),
    ("art_amcache_unassociated_files", "FileKeyLastWriteTimestamp", "program (amcache)",
     ("FullPath", "SHA1")),
    ("art_service_installs", "timestamp_utc", "service install",
     ("service_name", "path", "runas")),
    ("art_task_installs", "registered_utc", "task registered",
     ("task", "action", "registered_by")),
    ("art_browser_downloads", "start_utc", "download", ("source_url", "path", "user")),
    ("art_shell_history", "timestamp_utc", "shell command", ("user", "command_line")),
    ("art_log_sudo", "timestamp_utc", "sudo", ("user", "runas", "command_line")),
    ("art_log_cron", "timestamp_utc", "cron", ("kind", "user", "detail")),
    ("art_packages", "install_time_utc", "package install", ("name", "version")),
)
# Earlier than this is an empty FILETIME (1601) or a clock never set, not an event.
_TIMELINE_FLOOR = "1980-01-01"

# Columns joined into a `v_alerts` row's summary, and how long it may get: the
# same idea as the report's (`findings._summary`), which reads the first values
# that are not empty. SQL cannot count those, so it takes the first columns.
_SUMMARY_COLS = 6
_SUMMARY_CHARS = 160

# `priority` in v_alerts: the order report.txt prints its tiers in.
_PRIORITY = {"critical": 1, "high": 2, "flagged": 3, "medium": 4, "low": 5}

# Security 4624/4625 LogonType, as Microsoft names them.
_LOGON_TYPES = {2: "interactive", 3: "network", 4: "batch", 5: "service",
                7: "unlock", 8: "network cleartext", 9: "new credentials",
                10: "remote interactive (RDP)", 11: "cached interactive",
                12: "cached remote interactive", 13: "cached unlock"}
_LOGON_EVENTS = {4624: ("logon", "ok"), 4625: ("failed logon", "failed"),
                 4648: ("explicit credentials", "ok")}


def _q(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _lit(text: str) -> str:
    return "'" + str(text).replace("'", "''") + "'"


def _tables(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({_q(table)})")]


def _rowid(cols) -> str | None:
    """The name this table's row number answers to. `rowid`, `oid` and `_rowid_`
    all mean it -- until the table has a column of that name, which then wins: an
    external tool's `RowId` column would be read as the pointer, and counted as
    the number of rows. None when the table took all three."""
    taken = {str(c).lower() for c in cols}
    return next((n for n in ("rowid", "_rowid_", "oid") if n not in taken), None)


def _cast(cols: dict[str, str], name: str) -> str:
    """A column as text by its lower-case name, NULL when the table lacks it."""
    return f"CAST({_q(cols[name])} AS TEXT)" if name in cols else "NULL"


def time_columns(cols: list[str]) -> list[str]:
    """A table's time columns, the ones a question is asked by first.

    `_utc` columns when it has any, since those sort as time whatever the host;
    else the names an external tool uses, or the engine's own with the offset in
    the value; else `_local`. One tier only: a table that says both when a line
    was logged and that moment in UTC is asked by the second."""
    low = [(c, c.lower()) for c in cols]
    for pick in (lambda n: n.endswith("_utc"), lambda n: n in _TIME_NAMED,
                 lambda n: n.endswith("_local")):
        got = [c for c, n in low if pick(n)]
        if got:
            return got[:_MAX_TIME_INDEXES]
    return []


def _key_columns(table: str, cols: list[str]) -> list[str]:
    name = table.lower()
    want = list(_KEY_COLUMNS.get(name, ()))
    for prefix, keys in _KEY_PREFIXES.items():
        if name.startswith(prefix):
            want += keys
    by_low = {c.lower(): c for c in cols}
    return [by_low[w.lower()] for w in want if w.lower() in by_low]


def create_indexes(conn: sqlite3.Connection, min_rows: int = INDEX_MIN_ROWS) -> int:
    """Index the time and pivot columns of every table past `min_rows`.

    Returns how many it created. The row count is the highest rowid: these
    tables were just written and nothing was deleted from them, and COUNT(*)
    would read each of them whole to say the same."""
    made = 0
    for table in _tables(conn):
        try:
            cols = _columns(conn, table)
            rid = _rowid(cols)
            if rid is None:
                continue
            rows = conn.execute(f"SELECT MAX({rid}) FROM {_q(table)}").fetchone()[0] or 0
            if rows < min_rows:
                continue
            wanted = dict.fromkeys(time_columns(cols) + _key_columns(table, cols))
            for col in wanted:
                conn.execute(f"CREATE INDEX IF NOT EXISTS {_q(f'ix_{table}_{col}')} "
                             f"ON {_q(table)}({_q(col)})")
                made += 1
        except (sqlite3.Error, MemoryError) as e:
            log.debug(f"index: {table}: {type(e).__name__}: {e}")
    conn.commit()
    return made


def _summary_sql(cols: list[str], skip: set[str]) -> str:
    """The first few columns of a row as one line, empty ones left out."""
    picked = [c for c in cols if c.lower() not in skip][:_SUMMARY_COLS]
    if not picked:
        return "''"
    parts = [f"COALESCE(NULLIF(TRIM(CAST({_q(c)} AS TEXT)), '') || ' | ', '')" for c in picked]
    line = "REPLACE(REPLACE(" + " || ".join(parts) + ", char(10), ' '), char(13), ' ')"
    return f"SUBSTR(RTRIM({line}, ' |'), 1, {_SUMMARY_CHARS})"


def _alert_select(conn: sqlite3.Connection, table: str) -> str | None:
    """One table's findings as a SELECT of v_alerts' columns, or None when it
    holds none: the rows `findings` puts on the report's front page, read by the
    same two columns. A table named `alert_` with neither column is findings
    from its first row to its last, which is what the prefix says -- with
    neither column at all: one that has a `level` the report does not read as a
    rating (a value in it is no severity word) stays out, as it does there,
    since listing its rows as flagged would put the ones its parser rated low
    above every medium."""
    cols, flag, sev, rule = findings.finding_columns(conn, table)
    rid = _rowid(cols)
    if rid is None:
        return None
    if flag is None and sev is None:
        named = {c.lower() for c in cols} & set(findings._SEV_COLS)
        if named or not table.lower().startswith("alert_"):
            return None
    norm = findings._norm(sev) if sev else "''"
    words = findings._TIER_WORDS
    level = ("CASE WHEN {n} IN ('critical', 'crit') THEN 'critical' "
             "WHEN {n} = 'high' THEN 'high' WHEN {n} IN ({m}) THEN 'medium' "
             "WHEN {n} IN ({lo}) THEN 'low' ELSE 'flagged' END").format(
                 n=norm, m=", ".join(_lit(w) for w in words["medium"]),
                 lo=", ".join(_lit(w) for w in words["low"]))
    conds = []
    if sev:
        rated = [w for tier in ("high", "medium", "low") for w in words[tier]]
        conds.append(f"{norm} IN ({', '.join(_lit(w) for w in rated)})")
    if flag:
        conds.append(f"TRIM(COALESCE(CAST({_q(flag)} AS TEXT), '')) <> ''")
    when = time_columns(cols)
    skip = {c.lower() for c in (flag, sev, rule, *when[:1]) if c}
    return (f"SELECT {level} AS level, {_lit(table)} AS source_table, "
            f"{rid} AS source_rowid, "
            f"{f'CAST({_q(rule)} AS TEXT)' if rule else 'NULL'} AS rule, "
            f"{f'CAST({_q(when[0])} AS TEXT)' if when else 'NULL'} AS timestamp, "
            f"{_summary_sql(cols, skip)} AS summary FROM {_q(table)}"
            + (f" WHERE {' OR '.join(conds)}" if conds else ""))


def _alerts_view(conn: sqlite3.Connection) -> str | None:
    tables = _tables(conn)
    present = {t.lower() for t in tables}
    selects = []
    for t in tables:
        if findings._AGGREGATED.get(t.lower()) in present:
            continue            # its rows are in the aggregate, once
        try:
            sel = _alert_select(conn, t)
            if sel:
                # Read it alone first: one table SQLite refuses must cost its
                # own rows, not the view every other table is in.
                conn.execute(f"SELECT * FROM ({sel}) LIMIT 0").fetchall()
        except sqlite3.Error as e:
            log.debug(f"view {VIEW_ALERTS}: {t}: {e}")
            continue
        if sel:
            selects.append(sel)
    if not selects:
        return None
    prio = " ".join(f"WHEN {_lit(k)} THEN {v}" for k, v in _PRIORITY.items())
    return (f"CREATE VIEW {VIEW_ALERTS} AS SELECT CASE level {prio} END AS priority, "
            f"level, source_table, source_rowid, rule, timestamp, summary FROM ("
            + " UNION ALL ".join(selects)
            + ") ORDER BY priority, source_table, source_rowid")


def _logons_view(conn: sqlite3.Connection) -> str | None:
    """Every logon the machine recorded, in one shape whichever system wrote it:
    Security 4624/4625/4648 with the logon type named, and a Linux host's wtmp,
    btmp and lastlog rows that have a result -- a boot or a run-level change is
    in the same table and is not a logon."""
    tables = {t.lower(): t for t in _tables(conn)}
    selects = []
    sec = tables.get("art_evtx_security")
    if sec:
        cols = {c.lower(): c for c in _columns(conn, sec)}
        rid = _rowid(cols)
        if rid and {"timecreated", "eventid"} <= cols.keys():
            payload = " || '|' || ".join(
                f"COALESCE(CAST({_q(cols[p])} AS TEXT), '')"
                for p in (f"payloaddata{i}" for i in range(1, 7)) if p in cols) or "''"

            eid = _q(cols["eventid"])
            names = " ".join(f"WHEN {k} THEN {_lit(v)}" for k, v in _LOGON_TYPES.items())
            event = " ".join(f"WHEN {k} THEN {_lit(v[0])}" for k, v in _LOGON_EVENTS.items())
            result = " ".join(f"WHEN {k} THEN {_lit(v[1])}" for k, v in _LOGON_EVENTS.items())
            selects.append(
                f"SELECT timestamp_utc, CASE eid {result} END AS result, "
                f"CASE eid {event} END AS event, logon_type, "
                f"CASE logon_type {names} END AS logon, user, source_address, host, "
                f"detail, {_lit(sec)} AS source_table, source_rowid FROM ("
                f"SELECT {_cast(cols, 'timecreated')} AS timestamp_utc, CAST({eid} AS INTEGER) AS eid, "
                f"CASE WHEN INSTR(p, 'LogonType ') > 0 THEN "
                f"CAST(SUBSTR(p, INSTR(p, 'LogonType ') + 10, 3) AS INTEGER) END AS logon_type, "
                f"{_cast(cols, 'username')} AS user, {_cast(cols, 'remotehost')} AS source_address, "
                f"{_cast(cols, 'computer')} AS host, {_cast(cols, 'payloaddata1')} AS detail, "
                f"rid AS source_rowid FROM (SELECT *, {rid} AS rid, {payload} AS p "
                f"FROM {_q(sec)} WHERE {eid} IN ({', '.join(map(str, _LOGON_EVENTS))})))")
    lin = tables.get("art_logins")
    if lin:
        cols = {c.lower(): c for c in _columns(conn, lin)}
        rid = _rowid(cols)
        if rid and "timestamp_utc" in cols:
            selects.append(
                f"SELECT {_cast(cols, 'timestamp_utc')} AS timestamp_utc, {_cast(cols, 'result')} AS result, "
                f"{_cast(cols, 'source')} AS event, NULL AS logon_type, {_cast(cols, 'type')} AS logon, "
                f"{_cast(cols, 'user')} AS user, {_cast(cols, 'source_address')} AS source_address, "
                f"NULL AS host, {_cast(cols, 'tty')} AS detail, {_lit(lin)} AS source_table, "
                f"{rid} AS source_rowid FROM {_q(lin)}"
                + (f" WHERE TRIM(COALESCE({_cast(cols, 'result')}, '')) <> ''"
                   if "result" in cols else ""))
    if not selects:
        return None
    return (f"CREATE VIEW {VIEW_LOGONS} AS SELECT * FROM (" + " UNION ALL ".join(selects)
            + ") ORDER BY timestamp_utc DESC")


def _utc(expr: str) -> str:
    """A time value as `YYYY-MM-DD HH:MM:SS` UTC, or NULL when it is none. SQLite's
    datetime() reads the ISO forms the tools write (a `T` or a space, any number of
    fraction digits, `Z` or an offset, which it applies); hayabusa's space before
    the offset is taken out first."""
    return (f"datetime(REPLACE(REPLACE(CAST({expr} AS TEXT), ' +', '+'), ' -', '-'))")


def _views(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='view'")}


def _timeline_view(conn: sqlite3.Connection) -> str | None:
    """Every dated thing of the machine in one list, oldest first (AE-046): the
    alerts and the logons the other two views hold, and the sources in
    _TIMELINE_SOURCES. Columns: time_utc, kind, source_table, source_rowid,
    summary. An alert table whose time column is `_local` is left out -- it would
    sort hours away from the rest -- as is a row with no time or one before 1980."""
    tables = {t.lower(): t for t in _tables(conn)}
    views = _views(conn)
    selects = []
    if VIEW_ALERTS in views:
        local = sorted(t for t in tables.values()
                       if (tc := time_columns(_columns(conn, t))) and tc[0].lower().endswith("_local"))
        selects.append(
            f"SELECT {_utc('timestamp')} AS time_utc, 'alert ' || level AS kind, source_table, "
            f"source_rowid, COALESCE(rule || ' | ', '') || COALESCE(summary, '') AS summary "
            f"FROM {VIEW_ALERTS}"
            + (f" WHERE source_table NOT IN ({', '.join(_lit(t) for t in local)})" if local else ""))
    if VIEW_LOGONS in views:
        selects.append(
            # Windows names the event; a Linux row names its file (wtmp, btmp):
            # read by its result instead, so both say logon or failed logon.
            f"SELECT {_utc('timestamp_utc')} AS time_utc, CASE "
            f"WHEN source_table = 'art_logins' AND result = 'failed' THEN 'failed logon' "
            f"WHEN source_table = 'art_logins' THEN 'logon' "
            f"ELSE COALESCE(event, 'logon') END AS kind, "
            f"source_table, source_rowid, "
            f"RTRIM(" + " || ".join(
                f"COALESCE(NULLIF(TRIM({c}), '') || ' | ', '')"
                for c in ("user", "logon", "source_address", "result")) + ", ' |') AS summary "
            f"FROM {VIEW_LOGONS}")
    for table, when, kind, show in _TIMELINE_SOURCES:
        real = tables.get(table)
        if real is None:
            continue
        cols = {c.lower(): c for c in _columns(conn, real)}
        rid = _rowid(cols)
        if rid is None or when.lower() not in cols:
            continue
        picked = [cols[c.lower()] for c in show if c.lower() in cols]
        sel = (f"SELECT {_utc(_q(cols[when.lower()]))} AS time_utc, {_lit(kind)} AS kind, "
               f"{_lit(real)} AS source_table, {rid} AS source_rowid, "
               f"{_summary_sql(picked, set())} AS summary FROM {_q(real)}")
        try:
            conn.execute(f"SELECT * FROM ({sel}) LIMIT 0").fetchall()
        except sqlite3.Error as e:
            log.debug(f"view {VIEW_TIMELINE}: {real}: {e}")
            continue
        selects.append(sel)
    if not selects:
        return None
    return (f"CREATE VIEW {VIEW_TIMELINE} AS SELECT * FROM ("
            + " UNION ALL ".join(selects)
            + f") WHERE time_utc >= {_lit(_TIMELINE_FLOOR)} ORDER BY time_utc, source_table, source_rowid")


def create_views(conn: sqlite3.Connection) -> list[str]:
    """Create the views this database has the tables for; returns their names.
    The timeline last: it reads the other two."""
    made = []
    for name, build in ((VIEW_ALERTS, _alerts_view), (VIEW_LOGONS, _logons_view),
                        (VIEW_TIMELINE, _timeline_view)):
        try:
            sql = build(conn)
            if not sql:
                continue
            conn.execute(f"DROP VIEW IF EXISTS {name}")
            conn.execute(sql)
            conn.execute(f"SELECT * FROM {name} LIMIT 1").fetchall()   # it must READ, too
            made.append(name)
        except (sqlite3.Error, MemoryError) as e:
            log.debug(f"view {name}: {type(e).__name__}: {e}")
            try:
                conn.execute(f"DROP VIEW IF EXISTS {name}")
            except sqlite3.Error:
                pass
    conn.commit()
    return made


def finish(conn: sqlite3.Connection, indexes: bool = True) -> None:
    """Everything above, for a database whose tables are all written.

    Whatever goes wrong in here stays in here: the tables are written and the
    caller has a database to close and a verdict to give. The index sort goes to
    temp files first -- in memory, which is how a single machine's build runs,
    one index over 17 million rows takes about a gigabyte, in every pool worker
    at once."""
    for step in ((lambda: conn.execute("PRAGMA temp_store=FILE")),
                 (lambda: create_indexes(conn)) if indexes else None,
                 (lambda: create_views(conn))):
        if step is None:
            continue
        try:
            step()
        except Exception as e:  # noqa: BLE001 - an aid, never the deliverable
            log.debug(f"dbnav: {type(e).__name__}: {e}")
