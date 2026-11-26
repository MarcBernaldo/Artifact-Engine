"""art_browser_hindsight: Hindsight's SQLite as one table (v0.7.211).

The database is written here in Hindsight's own shape (its `timeline`, `storage`
and `installed_extensions` tables); values are invented (jdoe, example.local)."""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.handlers import win_hindsight as H
from artifact_engine.registry import load_parsers

_PROFILE = r"C:\Cases\Case-01\HOST-01\C\Users\jdoe\AppData\Local\Google\Chrome\User Data\Default"


def _db(path: Path) -> Path:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE timeline(type TEXT, timestamp TEXT, url TEXT, title TEXT, "
                 "value TEXT, interpretation TEXT, profile TEXT, source_item TEXT, "
                 "visit_count INT, typed_count INT, transition TEXT, danger_type TEXT)")
    conn.executemany("INSERT INTO timeline VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", [
        ("url", "2026-01-02 03:04:05.123456", "https://example.local/a", "A", None, None,
         _PROFILE, "History", 3, 1, "typed", None),
        ("download", "2026-01-02 03:05:00.000001", "https://example.local/t.exe", None,
         r"C:\Users\jdoe\Downloads\t.exe", None, _PROFILE, "History", None, None, None,
         "not dangerous"),
    ])
    conn.execute("CREATE TABLE storage(type TEXT, origin TEXT, key TEXT, value TEXT, "
                 "modification_time TEXT, interpretation TEXT, profile TEXT, source_path TEXT, "
                 "database TEXT, object_store TEXT, state_friendly TEXT)")
    conn.execute("INSERT INTO storage VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 ("local storage", "https://example.local", "token", "x" * (H._MAX + 10), None,
                  None, _PROFILE, "Local Storage", None, None, "Live"))
    conn.execute("CREATE TABLE installed_extensions(name TEXT, description TEXT, version TEXT, "
                 "ext_id TEXT, profile TEXT, permissions TEXT, manifest TEXT)")
    conn.execute("INSERT INTO installed_extensions VALUES (?,?,?,?,?,?,?)",
                 ("Helper", "does things", "1.2", "abcdef", _PROFILE, "tabs", "{}"))
    conn.commit()
    conn.close()
    return path


def test_everything_hindsight_wrote_is_one_table(tmp_path):
    users = Path(r"C:\Cases\Case-01\HOST-01\C\Users")
    rows = [dict(zip(H.HEADER, r)) for r in H._rows(_db(tmp_path / "h.sqlite"), users)]
    by = {r["type"]: r for r in rows}
    assert set(by) == {"url", "download", "local storage", "extension (installed)"}
    url = by["url"]
    assert url["timestamp_utc"] == "2026-01-02 03:04:05" and url["visit_count"] == 3
    assert url["user"] == "jdoe"
    assert url["profile"] == r"Users\jdoe\AppData\Local\Google\Chrome\User Data\Default"
    assert by["download"]["danger_type"] == "not dangerous"
    st = by["local storage"]            # kept apart by Hindsight, here a row like the rest
    assert (st["url"], st["title"], st["state"]) == ("https://example.local", "token", "Live")
    assert st["timestamp_utc"] == "" and st["value"].endswith("...[10 more characters]")
    ext = by["extension (installed)"]
    assert (ext["url"], ext["title"], ext["value"]) == ("chrome-extension://abcdef", "Helper", "1.2")


def _ctx(tmp_path, tools):
    ev = tmp_path / "C"
    return ParserContext(evidence=ev, out=ev / "CSVs" / "Browser", tools=tools,
                         assets=tmp_path, machine_name="HOST-01", volume="C",
                         log=logging.getLogger("aeng.test"))


def test_no_users_folder_or_no_tool_is_a_skip(tmp_path):
    with pytest.raises(HandlerSkip):
        H.run(_ctx(tmp_path, tmp_path / "tools"))
    (tmp_path / "C" / "Users").mkdir(parents=True)
    with pytest.raises(HandlerSkip, match="aeng setup"):
        H.run(_ctx(tmp_path, tmp_path / "tools"))


def test_the_tool_is_pinned_and_verified():
    p = {x.id: x for x in load_parsers([DATA_DIR / "parsers"])}["art_browser_hindsight"]
    assert p.tool.binary == H.TOOL
    assert p.tool.source.sha256 and "/v2026.11/" in p.tool.source.url
