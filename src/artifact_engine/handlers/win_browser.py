"""Handler: web browser history and downloads (Chromium + Firefox).

EZ Tools do not parse browsers, so we read the SQLite stores directly. The
databases are opened in immutable mode (``?immutable=1``): the read-only
evidence is never modified and locked/dirty DBs are still readable without a
WAL replay.

Outputs (one row per visit / download, with user + browser + profile columns):
    browser_history.csv
    browser_downloads.csv
"""

from __future__ import annotations

import csv
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Chromium "WebKit" epoch: microseconds since 1601-01-01 UTC.
_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# Firefox PRTime: microseconds since the Unix epoch.
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Chromium "User Data" roots relative to a user profile folder.
_CHROMIUM = {
    "Chrome": r"AppData/Local/Google/Chrome/User Data",
    "Edge": r"AppData/Local/Microsoft/Edge/User Data",
    "Brave": r"AppData/Local/BraveSoftware/Brave-Browser/User Data",
}
# Firefox profiles root relative to a user profile folder.
_FIREFOX = r"AppData/Roaming/Mozilla/Firefox/Profiles"


def _chrome_time(value) -> str:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        return (_CHROME_EPOCH + timedelta(microseconds=v)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError):
        return ""


def _firefox_time(value) -> str:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        return (_UNIX_EPOCH + timedelta(microseconds=v)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError):
        return ""


def _connect(db: Path) -> sqlite3.Connection | None:
    """Open a SQLite DB read-only (immutable) without touching the evidence.

    immutable=1 tells SQLite the file can't change, so it reads a locked/dirty
    DB without a WAL replay and never creates -wal/-journal side files on the
    read-only evidence. as_uri() yields the correct file:///C:/... form.
    """
    try:
        uri = db.resolve().as_uri() + "?immutable=1"
        conn = sqlite3.connect(uri, uri=True)
        # Corrupt/hostile rows can hold invalid UTF-8; the default strict decode
        # would error out and lose the whole table, so decode with replacement.
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        return conn
    except (sqlite3.Error, ValueError):
        return None


def _query(conn: sqlite3.Connection, sql: str) -> list[tuple]:
    try:
        cur = conn.execute(sql)
        return cur.fetchall()
    except sqlite3.Error:
        return []


def _iter_users(evidence: Path):
    users = evidence / "Users"
    if not users.is_dir():
        return
    for user_dir in users.iterdir():
        if user_dir.is_dir():
            yield user_dir.name, user_dir


def _chromium(user: str, user_dir: Path, history_rows: list, download_rows: list) -> None:
    for browser, rel in _CHROMIUM.items():
        user_data = user_dir / rel
        if not user_data.is_dir():
            continue
        # Default, Profile 1, Profile 2, Guest Profile, ...
        for hist in user_data.glob("*/History"):
            profile = hist.parent.name
            conn = _connect(hist)
            if conn is None:
                continue
            try:
                for url, title, visits, last in _query(
                    conn,
                    "SELECT url, title, visit_count, last_visit_time FROM urls",
                ):
                    history_rows.append(
                        (user, browser, profile, url, title, visits, _chrome_time(last))
                    )
                for tgt, src, total, start, end in _query(
                    conn,
                    "SELECT target_path, tab_url, total_bytes, start_time, end_time FROM downloads",
                ):
                    download_rows.append(
                        (user, browser, profile, tgt, src, total,
                         _chrome_time(start), _chrome_time(end))
                    )
            finally:
                conn.close()


def _firefox(user: str, user_dir: Path, history_rows: list) -> None:
    profiles = user_dir / _FIREFOX
    if not profiles.is_dir():
        return
    for places in profiles.glob("*/places.sqlite"):
        profile = places.parent.name
        conn = _connect(places)
        if conn is None:
            continue
        try:
            for url, title, visits, last in _query(
                conn,
                "SELECT url, title, visit_count, last_visit_date FROM moz_places",
            ):
                history_rows.append(
                    (user, "Firefox", profile, url, title, visits, _firefox_time(last))
                )
        finally:
            conn.close()


def _scrub(value):
    """csv.writer cannot emit an embedded NUL ("need to escape" error), and
    real-world history rows do contain them -- drop just that byte."""
    if isinstance(value, str) and "\x00" in value:
        return value.replace("\x00", "")
    return value


def _write(path: Path, header: list[str], rows: list[tuple]) -> None:
    if not rows:
        return                       # no history/downloads -> no CSV
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows([_scrub(v) for v in row] for row in rows)


def run(ctx) -> None:
    history_rows: list[tuple] = []
    download_rows: list[tuple] = []

    for user, user_dir in _iter_users(ctx.evidence):
        _chromium(user, user_dir, history_rows, download_rows)
        _firefox(user, user_dir, history_rows)

    ctx.out.mkdir(parents=True, exist_ok=True)
    _write(
        ctx.out / "browser_history.csv",
        ["user", "browser", "profile", "url", "title", "visit_count", "last_visit"],
        history_rows,
    )
    _write(
        ctx.out / "browser_downloads.csv",
        ["user", "browser", "profile", "target_path", "source_url", "bytes",
         "start_time", "end_time"],
        download_rows,
    )
