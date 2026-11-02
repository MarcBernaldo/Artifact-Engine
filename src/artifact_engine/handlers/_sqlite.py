"""Open an evidence SQLite database as the application last saw it.

A database collected from a live system keeps its newest writes in the
write-ahead log beside it (`<db>-wal`), sometimes all of them: an
ActivitiesCache.db of 4 KB with 2 MB of activity in its WAL is ordinary. Opening
the evidence `immutable=1` never touches it but reads the main file alone, and
everything still in the WAL is silently missing -- including, there, the schema,
so the table "does not exist" and the parser finds nothing. Opening it normally
would apply the log by writing into the evidence.

So the database and its `-wal` / `-journal` are copied to a temp dir, SQLite
replays the log on the copy, and the result is loaded into memory; the temp dir is
gone before the caller sees a row, so no copy of the evidence outlives the call
whatever happens to the handler afterwards. A log that does not fit its file (a
collector that copied them minutes apart, across a checkpoint) fails the
integrity check, and the main file is then read alone, as before. A WAL from
another database that happens to be consistent cannot be told apart.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path

_LOGS = ("-wal", "-journal")


def _load(copy: Path) -> sqlite3.Connection | None:
    """The copy, its log applied, as an in-memory database; None if SQLite cannot
    read it whole."""
    try:
        disk = sqlite3.connect(copy)
    except sqlite3.Error:
        return None
    try:
        if disk.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            return None
        mem = sqlite3.connect(":memory:")
        disk.backup(mem)
        return mem
    except sqlite3.Error:
        return None
    finally:
        disk.close()


def _copy(db: Path, into: Path, logs: bool) -> Path:
    for f in into.iterdir():
        f.unlink()
    copy = into / db.name
    shutil.copyfile(db, copy)
    for side in _LOGS if logs else ():
        log = db.with_name(db.name + side)
        if log.is_file():
            shutil.copyfile(log, copy.with_name(copy.name + side))
    return copy


def connect_copy(db: Path) -> sqlite3.Connection | None:
    """`db` with its log applied, in memory; None if it is not a database SQLite
    can read. An OSError copying it is raised: a database that could not be read
    must not look like an empty one."""
    has_log = any(db.with_name(db.name + s).is_file() for s in _LOGS)
    with tempfile.TemporaryDirectory(prefix="aeng_sqlite_") as tmp:
        conn = _load(_copy(db, Path(tmp), logs=True))
        if conn is None and has_log:              # the log does not fit: the file alone
            conn = _load(_copy(db, Path(tmp), logs=False))
    if conn is not None:
        # Corrupt/hostile rows can hold invalid UTF-8; the default strict decode
        # would error out and lose the whole table, so decode with replacement.
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
    return conn
