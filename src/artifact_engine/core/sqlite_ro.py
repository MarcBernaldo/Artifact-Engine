"""Open an engine database read-only, whatever its path holds.

`sqlite3.connect(f"file:{path}?mode=ro", uri=True)` is the obvious way, and it is
wrong for a path with a `#`, `?` or `%` in it: SQLite reads the text as a URI, so
`C:\\Cases\\Case #12\\HOST-01.db` ends at the `#`, the `?mode=ro` after it is gone,
and SQLite opens -- creating it, read-write -- a file named `C:\\Cases\\Case `.
Measured: the database read is empty, so a machine's findings, its log coverage
and a sweep over it all came back as nothing, with no error (v0.7.201).

The URI is therefore percent-encoded (`Path.as_uri`), except for a UNC path: the
`file://server/share/...` that `as_uri` gives is an authority SQLite refuses, so a
share is written `file:////server/share/...` (core/mcp_tools.py found this first).
"""

from __future__ import annotations

import sqlite3
import urllib.parse
from pathlib import Path


def uri(path: Path | str) -> str:
    """A read-only SQLite URI for `path`."""
    p = Path(path)
    if not p.is_absolute():
        p = p.resolve()
    posix = p.as_posix()
    if posix.startswith("//"):
        return "file://" + urllib.parse.quote(posix, safe="/:$") + "?mode=ro"
    return p.as_uri() + "?mode=ro"


def connect(path: Path | str, **kwargs) -> sqlite3.Connection:
    """`path` opened read-only: a write fails whatever the statement."""
    return sqlite3.connect(uri(path), uri=True, **kwargs)
