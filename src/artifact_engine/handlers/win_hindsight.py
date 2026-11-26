"""Handler: every browser artifact Hindsight reads, in one table. Output:
art_browser_hindsight.csv

Hindsight (Ryan Benson, `hindsight.exe`) parses the Chromium browsers (Chrome, Edge,
Brave, Vivaldi, Opera) and Firefox under the Users folder: history, downloads,
cookies, autofill, saved logins, bookmarks, preferences, site settings, sessions and
closed tabs, the cache, Local Storage and IndexedDB, extensions and their storage,
sync data and service workers. It copies each database to a temp folder before it
opens it (`--temp_dir`), so the evidence is never opened in place, and writes
SQLite. Its `timeline` is already one table of everything with a time; the storage,
extension and sync records, which it keeps apart, are added to it with their origin
as the url, their key as the title, so one table holds everything (v0.7.211).

Times are UTC (`-t UTC`), cut to the second. `user` is the profile folder the
browser profile is under. A value longer than `_MAX` characters (a Local Storage
blob can be half a megabyte) is cut, saying how much was left out.

art_browser keeps its own history and downloads tables, read natively.
"""

from __future__ import annotations

import re
import shutil
import sqlite3
import tempfile
from pathlib import Path

from artifact_engine.core import procs
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv

TOOL = "hindsight.exe"
_TIMEOUT = 3600
_MAX = 8000
HEADER = ["timestamp_utc", "type", "user", "profile", "url", "title", "value",
          "interpretation", "source_item", "visit_count", "typed_count", "visit_duration",
          "transition", "visit_source", "url_hidden", "visit_id", "from_visit",
          "opener_visit", "danger_type", "interrupt_reason", "opened", "mime_type",
          "referrer", "tab_url", "download_source", "hash", "guid", "body_sha256", "etag",
          "last_modified", "http_headers", "tab_id", "window_id", "session_id",
          "database", "object_store", "state"]
# Hindsight's timeline columns kept as they are (its name -> ours).
_TIMELINE = {"type": "type", "url": "url", "title": "title", "value": "value",
             "interpretation": "interpretation", "source_item": "source_item",
             "visit_count": "visit_count", "typed_count": "typed_count",
             "visit_duration": "visit_duration", "transition": "transition",
             "visit_source": "visit_source", "url_hidden": "url_hidden",
             "visit_id": "visit_id", "from_visit": "from_visit",
             "opener_visit": "opener_visit", "danger_type": "danger_type",
             "interrupt_reason": "interrupt_reason", "opened": "opened",
             "mime_type": "mime_type", "referrer": "referrer", "tab_url": "tab_url",
             "download_source": "download_source", "hash": "hash", "guid": "guid",
             "body_sha256": "body_sha256", "etag": "etag", "last_modified": "last_modified",
             "http_headers": "http_headers", "tab_id": "tab_id", "window_id": "window_id",
             "session_id": "session_id"}
_TS = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")


def _utc(value) -> str:
    m = _TS.search(str(value or ""))
    return f"{m.group(1)} {m.group(2)}" if m else ""


def _cut(value) -> str:
    s = "" if value is None else str(value)
    return s if len(s) <= _MAX else s[:_MAX] + f" ...[{len(s) - _MAX} more characters]"


def _user(profile: str) -> str:
    """`...\\Users\\<name>\\AppData\\...` -> <name>."""
    parts = re.split(r"[\\/]", profile or "")
    low = [p.lower() for p in parts]
    return parts[low.index("users") + 1] if "users" in low and low.index("users") + 1 < len(parts) else ""


def _profile(profile: str, users: Path) -> str:
    """The profile path from the Users folder down (Users\\<name>\\AppData\\...)."""
    p = str(profile or "").replace("/", "\\")
    base = str(users).replace("/", "\\")
    i = p.lower().find(base.lower())
    return "Users" + p[i + len(base):] if i >= 0 else p


def _cols(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')}


def _rows(db: Path, users: Path) -> list[list]:
    conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    out: list[list] = []
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

        def add(ts, row: dict) -> None:
            prof = row.get("profile") or ""
            rec = {k: "" for k in HEADER}
            rec.update({k: v for k, v in row.items() if k in rec and v is not None})
            rec["timestamp_utc"] = _utc(ts)
            rec["user"] = _user(prof)
            rec["profile"] = _profile(prof, users)
            rec["value"] = _cut(rec["value"])
            rec["http_headers"] = _cut(rec["http_headers"])
            out.append([rec[k] for k in HEADER])

        if "timeline" in tables:
            have = _cols(conn, "timeline")
            for r in conn.execute("SELECT * FROM timeline"):
                d = dict(r)
                add(d.get("timestamp"), {**{ours: d.get(theirs) for theirs, ours in _TIMELINE.items()
                                            if theirs in have}, "profile": d.get("profile")})
        # Records Hindsight keeps apart: the origin (or extension) as url, the key as title.
        for table, origin in (("storage", "origin"), ("extension_data", "extension_id"),
                              ("sync_data", None), ("service_workers", "origin")):
            if table not in tables:
                continue
            for r in conn.execute(f'SELECT * FROM "{table}"'):
                d = dict(r)
                add(d.get("modification_time"), {
                    "type": d.get("type") or table, "url": d.get(origin) if origin else "",
                    "title": d.get("key"), "value": d.get("value"),
                    "interpretation": d.get("interpretation"), "profile": d.get("profile"),
                    "source_item": d.get("source_path"), "database": d.get("database"),
                    "object_store": d.get("object_store"),
                    "state": d.get("state_friendly")})
        if "installed_extensions" in tables:
            for r in conn.execute("SELECT * FROM installed_extensions"):
                d = dict(r)
                add("", {"type": "extension (installed)",
                         "url": f"chrome-extension://{d.get('ext_id') or ''}",
                         "title": d.get("name"), "value": d.get("version"),
                         "interpretation": d.get("description"), "profile": d.get("profile"),
                         "source_item": d.get("permissions")})
    finally:
        conn.close()
    return out


def run(ctx) -> None:
    users = Path(ctx.evidence) / "Users"
    if not users.is_dir():
        raise HandlerSkip("no Users folder")
    tool = Path(ctx.tools) / TOOL
    if not tool.is_file():
        raise HandlerSkip("hindsight.exe not installed (run 'aeng setup')")
    work = Path(tempfile.mkdtemp(prefix="aeng_hindsight_"))
    try:
        rc, said, err = procs.run([str(tool), "-i", str(users), "-o", str(work / "hindsight"),
                                   "-f", "sqlite", "-t", "UTC", "-l", str(work / "hindsight.log"),
                                   "--temp_dir", str(work / "copies")], timeout=_TIMEOUT)
        db = work / "hindsight.sqlite"
        if not db.is_file():
            if rc != 0:
                why = (err or said or "").strip().splitlines()
                raise RuntimeError(f"hindsight exit {rc}: {why[-1][:160] if why else ''}")
            raise HandlerSkip("no browser profile under Users")
        rows = _rows(db, users)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if not rows:
        raise HandlerSkip("no browser profile under Users")
    rows.sort(key=lambda r: (r[0] == "", r[0], r[1]))
    write_csv(ctx.out, "art_browser_hindsight.csv", HEADER, rows)
