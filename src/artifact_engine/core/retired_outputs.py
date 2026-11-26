"""What the engine once wrote at a case root and writes no more (AE-131).

v0.7.200 to v0.7.209 wrote `case.db` (every host's alerts and timeline) and
`case.html` (built from it) at the case root, each through a `.tmp` beside it that
a killed run could leave. A case processed then still holds them, and they are the
engine's, not its evidence. But nothing writes those names any more, so in a case
that version never touched a file called `case.db` or `case.html` is simply a
delivered file: the name alone no longer says whose it is.

- `case.db` is the engine's when its bytes hold the CREATE TABLE statement of one
  of the tables case.db had, exactly as casedb wrote it (SQLite keeps that text
  verbatim in the file). Read as plain bytes, never opened with SQLite: phase 0
  calls this before hashing, and even a read-only SQLite connection creates
  `-shm`/`-wal` files beside a WAL-mode database -- in the evidence folder, under
  the custody record (found by review).
- `case.html` is the engine's when it starts the way case.html did and says, in
  its first kilobytes, that it was generated from case.db.
- `case.db.tmp` / `case.html.tmp` are the engine's own temporary names, taken by
  name: a killed run's `.tmp` can be empty (the connection was opened, nothing
  written yet), with no content to tell it by, and no delivery carries them.

Anything else of those names is not the engine's: phase 0 hashes it as an original
and no warning calls it an old output. (`sweep` searches only machine databases:
a machine named `case` below the case root keeps its own case.db; any other
case.db is evidence, which sweep never searched.)
"""

from __future__ import annotations

from pathlib import Path

NAMES = ("case.db", "case.db.tmp", "case.html", "case.html.tmp")
_TEMP_NAMES = ("case.db.tmp", "case.html.tmp")


def _create(table: str, cols: tuple[str, ...]) -> bytes:
    """The statement casedb's `_Writer` ran, byte for byte."""
    q = '"{}"'.format
    return f"CREATE TABLE {q(table)} ({', '.join(q(c) for c in cols)})".encode()


# The tables case.db had, with their columns in order (core/casedb.py, removed in
# v0.7.210). Every finished case.db holds `hosts`, created last; `alerts` and
# `timeline` only when a host had the views they were read from. None of them need
# be near the start: once the alert tables copied from the hosts fill the first
# page, the schema moves to pages written after the rows (found by review).
_DB_MARKS = (
    _create("hosts", ("host", "db", "status", "critical", "high", "medium", "low",
                      "flagged", "timeline_rows", "first_time_utc", "last_time_utc")),
    _create("alerts", ("host", "priority", "level", "source_table", "source_rowid",
                       "rule", "timestamp", "summary")),
    _create("timeline", ("host", "time_utc", "kind", "source_table", "source_rowid",
                         "summary")),
)
_SQLITE_MAGIC = b"SQLite format 3\x00"
# How every case.html began (core/casepage.py, removed in v0.7.210): its doctype,
# its title and the line saying what it was generated from, in its first kilobytes.
_PAGE_START = b"<!doctype html><html lang=en>"
_PAGE_MARKS = (b"<title>Case: ", b" from case.db</p>")
_HEAD = 8192
_CHUNK = 1 << 20


def _holds(path: Path, marks: tuple[bytes, ...]) -> bool:
    """Whether any of `marks` is in the file, read in slices that overlap by enough
    for a mark cut at a slice boundary still to be found."""
    keep = max(len(m) for m in marks) - 1
    tail = b""
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            buf = tail + chunk
            if any(m in buf for m in marks):
                return True
            tail = buf[-keep:]
    return False


def is_one(path: Path) -> bool:
    """True when `path` is a case.db or case.html (or its .tmp) the engine wrote."""
    p = Path(path)
    name = p.name.lower()
    if name not in NAMES:
        return False
    try:
        if name in _TEMP_NAMES:
            return p.is_file()
        with open(p, "rb") as fh:
            head = fh.read(_HEAD)
        if name == "case.html":
            return head.startswith(_PAGE_START) and all(m in head for m in _PAGE_MARKS)
        return head.startswith(_SQLITE_MAGIC) and _holds(p, _DB_MARKS)
    except OSError:
        return False


def found(root: Path) -> list[Path]:
    """The engine's own, at `root`: where it wrote them, and nowhere else."""
    try:
        entries = sorted(Path(root).iterdir())
    except OSError:
        return []
    return [p for p in entries if p.name.lower() in NAMES and is_one(p)]
