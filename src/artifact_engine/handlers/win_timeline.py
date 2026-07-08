"""Handler: Windows Timeline (ActivitiesCache.db). Output: timeline.csv

Windows 10 (1803+) records a per-user activity feed in
``Users\\<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<L.*>\\ActivitiesCache.db``
(a SQLite store). Its ``Activity`` table is execution + file-open evidence that
survives when Prefetch/UserAssist do not: which application ran, which document
was opened, and (for focus activities) for how long — with start/end timestamps.

Read natively (no external tool): the DB is opened immutable so the read-only
evidence is never modified. We surface the human-readable activities (Open /
InFocus), decoding the app from the ``AppId`` JSON and the document / window
title from ``Payload``. Clipboard and copy/paste rows (types 10/11/16) carry a
protobuf blob rather than text, so only their app + timestamp is reported.
``suspicious`` = the app or the opened content sits in a staging dir or is a LOLBin.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_liveresponse_velociraptor import _in_staging, _is_lolbin

# ActivityType -> label (documented Windows Timeline values; unknowns kept as-is).
_TYPES = {2: "Notification", 3: "Backup", 5: "Open", 6: "InFocus",
          10: "Clipboard", 11: "CopyPaste", 16: "Copy"}

# KNOWNFOLDER GUIDs the win32 AppId uses in place of a base path.
_KNOWN = {
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "%ProgramFiles%",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "%ProgramFiles(x86)%",
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "%System32%",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "%Windir%",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "%Desktop%",
    "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "%Documents%",
    "{374DE290-123F-4565-9164-39C4925E467B}": "%Downloads%",
}
_GUID = re.compile(r"\{[0-9A-Fa-f\-]{36}\}")


def _s(v) -> str:
    """AppId/Payload are stored as BLOBs on some rows -> come back as bytes."""
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", "replace")
    return v or ""


def _user_of(db: Path) -> str:
    parts = db.parts
    for i, part in enumerate(parts):
        if part.lower() == "users" and i + 1 < len(parts):
            return parts[i + 1]
    return db.parent.name


def _epoch(v) -> str:
    """ActivitiesCache stores Unix epoch seconds; 0/None -> blank."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    try:
        return datetime.fromtimestamp(n, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def _app(appid_json: str) -> str:
    """The application from the AppId JSON array (prefer the win32 entry)."""
    try:
        arr = json.loads(appid_json)
    except (json.JSONDecodeError, TypeError):
        return ""
    win32 = other = ""
    for e in arr if isinstance(arr, list) else []:
        app = (e.get("application") or "").strip()
        if not app or app == "data_boundary":
            continue
        if e.get("platform") == "windows_win32":
            win32 = win32 or app
        else:
            other = other or app
    app = win32 or other
    for guid, name in _KNOWN.items():                # translate the base-path GUID
        if guid.lower() in app.lower():
            return _GUID.sub(name, app)
    return app


def _content(payload: str) -> str:
    """Human-readable detail from the Payload JSON (title + opened file)."""
    if not payload or not payload.lstrip().startswith("{"):
        return ""                                    # clipboard / protobuf blob
    try:
        p = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return ""
    title = (p.get("displayText") or p.get("appDisplayName") or "").strip()
    uri = (p.get("contentUri") or "").strip()
    if uri.lower().startswith("file:"):
        uri = uri.split("?", 1)[0]                   # drop the ?VolumeId=...&ObjectId=... tail
        uri = unquote(uri[5:].lstrip("/")).replace("/", "\\")
    elif uri:
        uri = ""                                     # activation/http URIs are noise
    return " | ".join(x for x in (title, uri) if x)


def _connect(db: Path):
    try:
        conn = sqlite3.connect(db.resolve().as_uri() + "?immutable=1", uri=True)
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        return conn
    except (sqlite3.Error, ValueError):
        return None


def run(ctx) -> None:
    dbs = [p for p in Path(ctx.evidence).rglob("ActivitiesCache.db") if p.is_file()]
    if not dbs:
        raise HandlerSkip("no ActivitiesCache.db")

    rows: list[list] = []
    for db in dbs:
        user = _user_of(db)
        conn = _connect(db)
        if conn is None:
            continue
        try:
            cur = conn.execute(
                "SELECT AppId, ActivityType, Payload, StartTime, EndTime, "
                "LastModifiedTime FROM Activity")
            for appid, atype, payload, start, end, lastmod in cur:
                app = _app(_s(appid))
                content = _content(_s(payload))
                susp = "yes" if (_in_staging(app + " " + content) or _is_lolbin(app)) else ""
                rows.append([user, _epoch(start), _epoch(end),
                             _TYPES.get(atype, f"type{atype}"), app, content,
                             _epoch(lastmod), susp])
        except sqlite3.Error:
            pass
        finally:
            conn.close()

    rows.sort(key=lambda r: (r[7] != "yes", r[1] or "", r[0]))
    write_csv(ctx.out, "timeline.csv",
              ["user", "start", "end", "activity_type", "app", "content",
               "last_modified", "suspicious"], rows)
