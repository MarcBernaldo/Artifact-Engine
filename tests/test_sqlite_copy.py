"""An evidence SQLite database is read with its write-ahead log, from a copy."""

import csv
import logging
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import _sqlite as S
from artifact_engine.handlers import win_browser, win_timeline
from artifact_engine.handlers._sqlite import connect_copy


def _collected_live(dest: Path, schema: str, insert: str, rows: list[tuple]) -> None:
    """Write `dest` the way a live collection catches it: the writer still open,
    nothing checkpointed, so the schema and every row are in `<dest>-wal` and the
    main file is the bare header."""
    work = dest.parent / "_writer"
    work.mkdir()
    conn = sqlite3.connect(work / dest.name)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute(schema)
    conn.executemany(insert, rows)
    conn.commit()
    for side in ("", "-wal"):                       # copied while the writer is open
        shutil.copyfile(work / (dest.name + side), dest.with_name(dest.name + side))
    conn.close()
    shutil.rmtree(work)


def _snapshot(d: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in d.iterdir()}


def _ctx(evidence: Path, out: Path) -> ParserContext:
    return ParserContext(evidence=evidence, out=out, tools=evidence, assets=evidence,
                         machine_name="HOST-01", volume="C", log=logging.getLogger("aeng.test"))


@pytest.fixture
def temp(tmp_path, monkeypatch):
    """Where connect_copy's temp dirs go, to see that none is left behind."""
    t = tmp_path / "temp"
    t.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(t))
    return t


def test_rows_only_in_the_wal_are_read_and_the_evidence_is_untouched(tmp_path, temp):
    db = tmp_path / "ev" / "x.db"
    db.parent.mkdir()
    _collected_live(db, "CREATE TABLE t (a)", "INSERT INTO t VALUES (?)", [(1,), (2,), (3,)])
    before = _snapshot(db.parent)
    # what immutable=1 saw: the main file alone, no table at all
    ro = sqlite3.connect(db.resolve().as_uri() + "?immutable=1", uri=True)
    assert ro.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0
    ro.close()
    conn = connect_copy(db)
    cur = conn.execute("SELECT a FROM t")
    assert cur.fetchone() == (1,)
    # mid-query, with the connection open: no copy of the evidence is on disk
    assert not any(temp.iterdir())
    conn.close()
    assert _snapshot(db.parent) == before             # no -shm, nothing replayed in place


def test_a_log_that_does_not_fit_falls_back_to_the_file_alone(tmp_path, temp, monkeypatch):
    """A collector that copied the file and its WAL across a checkpoint."""
    db = tmp_path / "x.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE t (a)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    con.close()
    (tmp_path / "x.db-wal").write_bytes(b"wal")
    seen = []
    real = S._load

    def load(copy):
        seen.append(copy.with_name(copy.name + "-wal").exists())
        return None if len(seen) == 1 else real(copy)

    monkeypatch.setattr(S, "_load", load)
    conn = connect_copy(db)
    assert seen == [True, False]                      # the second read is the file alone
    assert conn.execute("SELECT a FROM t").fetchall() == [(1,)]
    conn.close()
    assert not any(temp.iterdir())


def test_a_database_that_cannot_be_copied_is_an_error_not_empty(tmp_path, temp, monkeypatch):
    db = tmp_path / "x.db"
    sqlite3.connect(db).close()

    def full(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(S.shutil, "copyfile", full)
    with pytest.raises(OSError):
        connect_copy(db)
    assert not any(temp.iterdir())


def test_what_is_not_a_database_is_none(tmp_path, temp):
    bad = tmp_path / "x.db"
    bad.write_bytes(b"not sqlite at all" * 100)
    assert connect_copy(bad) is None
    assert not any(temp.iterdir())


def test_the_timeline_reads_activity_still_in_the_wal(tmp_path):
    cdp = tmp_path / "Users" / "jdoe" / "AppData/Local/ConnectedDevicesPlatform/L.jdoe"
    cdp.mkdir(parents=True)
    _collected_live(cdp / "ActivitiesCache.db",
                    "CREATE TABLE Activity (AppId, ActivityType, Payload, StartTime, "
                    "EndTime, LastModifiedTime)",
                    "INSERT INTO Activity VALUES (?,?,?,?,?,?)",
                    [('[{"application":"notepad.exe","platform":"windows_win32"}]', 5,
                      '{"displayText":"notes.txt"}', 1700000000, 1700000060, 1700000060)])
    win_timeline.run(_ctx(tmp_path, tmp_path / "out"))
    with open(tmp_path / "out" / "art_win_timeline.csv", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert [r["app"] for r in rows] == ["notepad.exe"]


def test_firefox_history_still_in_the_wal_is_read(tmp_path):
    prof = tmp_path / "Users" / "jdoe" / "AppData/Roaming/Mozilla/Firefox/Profiles/abc.default"
    prof.mkdir(parents=True)
    _collected_live(prof / "places.sqlite",
                    "CREATE TABLE moz_places (url, title, visit_count, last_visit_date)",
                    "INSERT INTO moz_places VALUES (?,?,?,?)",
                    [("https://example.local/", "Example", 1, 1700000000000000)])
    rows: list = []
    win_browser._firefox("jdoe", tmp_path / "Users" / "jdoe", rows)
    assert [r[3] for r in rows] == ["https://example.local/"]
