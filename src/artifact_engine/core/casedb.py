"""One database for the whole case: every host's alerts and timeline (AE-047).

A machine's `.db` answers questions about that machine. Questions about the case
-- which hosts ran this program, what happened on every host between ten and
eleven, which host has the most high findings -- need every machine at once, and
`sweep` only searches for a value. `case.db`, at the case root, holds:

- `hosts`: one row per machine `.db` read: its findings per level, how many
  timeline rows it gave, its first and last dated event, and the `.db` it came
  from (relative to the root) -- or why it could not be read.
- `alerts`: every machine's `v_alerts` (core/dbnav.py), with a `host` column.
- `timeline`: every machine's `v_timeline`, with a `host` column, indexed by time
  and by host: the case's events in one UTC order.
- every `alert_` table of every machine, as one table per name with a `host`
  column first and the union of the columns the hosts' copies have. A table whose
  rows are aggregated into another (`findings._AGGREGATED`: hayabusa's timeline)
  is left out, as v_alerts leaves it; a table's own `host` column is kept as
  `host_in_table`.

Built again on every run, after consolidation, from the machine databases: it is
a copy of what they hold, so it is never stale and never the only place a row is.
Written to a temporary file and moved into place, so a reader never opens half of
one. Nothing here may fail a run: a machine `.db` that cannot be read is a row in
`hosts` that says so, and a case.db that cannot be written is a warning.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from artifact_engine.core import dbnav, findings
from artifact_engine.logging_setup import get_logger

log = get_logger()

CASE_DB = "case.db"
LEVELS = ("critical", "high", "medium", "low", "flagged")
# What an alert table's own `host` column is called in case.db.
OWN_HOST = "host_in_table"

_HOSTS_COLS = ("host", "db", "status", *LEVELS, "timeline_rows",
               "first_time_utc", "last_time_utc")


def _ro(path: Path) -> str:
    """A read-only SQLite URI for `path`. Built with as_uri(), which percent-encodes:
    a raw path with a `#` in a folder name (`Case #12`) ended the URI there, so SQLite
    opened -- and created, read-write -- a file named after what came before it."""
    return Path(path).resolve().as_uri() + "?mode=ro"


def _q(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _views(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='view'")}


def _tables(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
        "ORDER BY name")]


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({_q(table)})")]


class _Writer:
    """The tables of case.db, created on first use with the columns they get."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.cols: dict[str, list[str]] = {}

    def insert(self, table: str, cols: list[str], rows) -> int:
        have = self.cols.get(table)
        if have is None:
            have = self.cols[table] = list(cols)
            self.conn.execute(f"CREATE TABLE {_q(table)} ({', '.join(_q(c) for c in have)})")
        else:
            low = {c.lower() for c in have}
            for c in cols:
                if c.lower() not in low:       # a column this host's copy adds
                    self.conn.execute(f"ALTER TABLE {_q(table)} ADD COLUMN {_q(c)}")
                    have.append(c)
                    low.add(c.lower())
        sql = (f"INSERT INTO {_q(table)} ({', '.join(_q(c) for c in cols)}) "
               f"VALUES ({', '.join('?' * len(cols))})")
        n = 0
        cur = self.conn.cursor()
        batch = []
        for r in rows:
            batch.append(r)
            if len(batch) >= 5000:
                cur.executemany(sql, batch)
                n += len(batch)
                batch.clear()
        if batch:
            cur.executemany(sql, batch)
            n += len(batch)
        return n


def _stale_host(host: str, db: Path, root: Path, why: str) -> dict:
    row = {"host": host, "status": f"not rebuilt this run: {why}"[:200],
           **{lv: 0 for lv in LEVELS}, "timeline_rows": 0,
           "first_time_utc": None, "last_time_utc": None}
    try:
        row["db"] = db.relative_to(root).as_posix()
    except ValueError:
        row["db"] = str(db)
    return row


def _one_host(w: _Writer, host: str, db: Path, root: Path) -> dict:
    """Copy one machine's alerts, timeline and alert_ tables; its `hosts` row."""
    row = {"host": host, "status": "ok", **{lv: 0 for lv in LEVELS}, "timeline_rows": 0,
           "first_time_utc": None, "last_time_utc": None}
    try:
        row["db"] = db.relative_to(root).as_posix()
    except ValueError:
        row["db"] = str(db)
    if not db.is_file():
        row["status"] = "no .db"
        return row
    try:
        src = sqlite3.connect(_ro(db), uri=True)
    except sqlite3.Error as e:
        row["status"] = f"unreadable: {type(e).__name__}"
        return row
    try:
        views = _views(src)
        if dbnav.VIEW_ALERTS in views:
            cur = src.execute(f"SELECT priority, level, source_table, source_rowid, rule, "
                              f"timestamp, summary FROM {dbnav.VIEW_ALERTS}")
            levels = {lv: 0 for lv in LEVELS}

            def counted(rows):
                for r in rows:
                    if r[1] in levels:
                        levels[r[1]] += 1
                    yield (host, *r)
            w.insert("alerts", ["host", "priority", "level", "source_table", "source_rowid",
                                "rule", "timestamp", "summary"], counted(cur))
            row.update(levels)
        if dbnav.VIEW_TIMELINE in views:
            cur = src.execute(f"SELECT time_utc, kind, source_table, source_rowid, summary "
                              f"FROM {dbnav.VIEW_TIMELINE}")
            row["timeline_rows"] = w.insert(
                "timeline", ["host", "time_utc", "kind", "source_table", "source_rowid",
                             "summary"], ((host, *r) for r in cur))
            first, last = src.execute(f"SELECT MIN(time_utc), MAX(time_utc) "
                                      f"FROM {dbnav.VIEW_TIMELINE}").fetchone()
            row["first_time_utc"], row["last_time_utc"] = first, last
        tables = _tables(src)
        present = {t.lower() for t in tables}
        for t in tables:
            if not t.lower().startswith("alert_"):
                continue
            if findings._AGGREGATED.get(t.lower()) in present:
                continue                  # its rows are in the aggregate
            cols = _columns(src, t)
            # The table's own `host` (alert_hayabusa names the Computer field) is
            # kept under another name: `host` here is the machine the row is from.
            named = [OWN_HOST if c.lower() == "host" else c for c in cols]
            w.insert(t.lower(), ["host", *named],
                     ((host, *r) for r in src.execute(f"SELECT * FROM {_q(t)}")))
    except sqlite3.Error as e:
        row["status"] = f"partly read: {type(e).__name__}: {e}"[:200]
    finally:
        src.close()
    return row


def _unique(dbs: list[tuple[str, Path]], root: Path) -> list[tuple[str, Path]]:
    """One label per database. Two units can share a host name -- its disk and its
    memory, two acquisitions of it -- and their rows must not merge into one host:
    a repeated name gets the folder its `.db` is in, then a number if need be."""
    names = [h for h, _ in dbs]
    out, seen = [], set()
    for host, db in dbs:
        label = host
        if names.count(host) > 1:
            try:
                where = Path(db).parent.relative_to(root).as_posix() or "."
            except ValueError:
                where = Path(db).parent.name
            label = f"{host} ({where})"
        base, n = label, 2
        while label.lower() in seen:
            label, n = f"{base} #{n}", n + 1
        seen.add(label.lower())
        out.append((label, db))
    return out


def build(root: Path, dbs: list[tuple[str, Path]],
          not_rebuilt: dict[str, str] | None = None) -> Path | None:
    """Write `<root>/case.db` from the machine databases `[(host, path)]`.

    `not_rebuilt` maps a database path (as given) to why this run did not build it
    (`cli._consolidate_all`'s broken units): what is on disk there is the last run's,
    or half of one, so it is listed in `hosts` with that reason and not copied.

    Returns its path, or None when there was nothing to read or it could not be
    written (logged as a warning: the machine databases are the deliverable)."""
    if not dbs:
        return None
    root = Path(root)
    final = root / CASE_DB
    tmp = root / (CASE_DB + ".tmp")
    for _host, db in dbs:
        # A machine named `case` detected at the root writes <root>/case.db itself
        # (NTFS ignores case): replacing it would destroy that machine's database.
        if Path(db).parent.resolve() == root.resolve() and Path(db).name.lower() in (
                CASE_DB, CASE_DB + ".tmp"):
            log.warning(f"[!] {CASE_DB} not written: a machine database at the case "
                        f"root has that name ({Path(db).name})")
            return None
    stale = {str(Path(p)): why for p, why in (not_rebuilt or {}).items()}
    dbs = _unique(dbs, root)
    try:
        tmp.unlink(missing_ok=True)
        conn = sqlite3.connect(tmp)
        try:
            conn.execute("PRAGMA journal_mode=OFF")
            conn.execute("PRAGMA synchronous=OFF")
            w = _Writer(conn)
            hosts = [_stale_host(host, Path(db), root, stale[str(Path(db))])
                     if str(Path(db)) in stale else _one_host(w, host, Path(db), root)
                     for host, db in dbs]
            w.insert("hosts", list(_HOSTS_COLS),
                     ([h[c] for c in _HOSTS_COLS] for h in hosts))
            if "timeline" in w.cols:
                conn.execute('CREATE INDEX ix_timeline_time ON timeline (time_utc)')
                conn.execute('CREATE INDEX ix_timeline_host ON timeline (host, time_utc)')
            if "alerts" in w.cols:
                conn.execute('CREATE INDEX ix_alerts_host ON alerts (host, priority)')
            conn.commit()
        finally:
            conn.close()
        os.replace(tmp, final)
    except (OSError, sqlite3.Error) as e:
        log.warning(f"[!] {CASE_DB} not written: {type(e).__name__}: {e}")
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    return final


def host_findings(case_db: Path) -> list[dict]:
    """The `hosts` table of a case.db, most findings first (critical, then high...)."""
    try:
        conn = sqlite3.connect(_ro(case_db), uri=True)
    except sqlite3.Error:
        return []
    try:
        conn.row_factory = sqlite3.Row
        order = ", ".join(f"{_q(lv)} DESC" for lv in LEVELS)
        return [dict(r) for r in conn.execute(f"SELECT * FROM hosts ORDER BY {order}, host")]
    except sqlite3.Error:
        return []
    finally:
        conn.close()
