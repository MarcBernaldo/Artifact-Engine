"""An engine database opened read-only whatever its path holds (core/sqlite_ro.py).

A raw `file:{path}?mode=ro` URI ends at a `#`: SQLite opened (and created) another
file and the readers saw an empty database -- no findings, no coverage, no sweep
hit, and no error. Every value is invented."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from artifact_engine.core import coverage, findings, sqlite_ro, sweep


@pytest.fixture
def odd_db(tmp_path) -> Path:
    folder = tmp_path / "Case #12 100%" / "HOST-01"
    folder.mkdir(parents=True)
    db = folder / "HOST-01.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE alert_win_sigma (level, rule, first_seen, \"match\")")
    conn.execute("INSERT INTO alert_win_sigma VALUES ('high', 'Rule A', '2026-05-01', "
                 "'C:\\Tools\\evil-example.exe')")
    conn.execute("CREATE TABLE art_log_coverage (channel, first_event_utc, last_event_utc, "
                 "events)")
    conn.execute("INSERT INTO art_log_coverage VALUES ('Security', '2026-05-01', "
                 "'2026-05-02', 10)")
    conn.commit()
    conn.close()
    return db


def test_a_path_with_a_hash_or_a_percent_reads_the_right_file(odd_db, tmp_path):
    conn = sqlite_ro.connect(odd_db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM alert_win_sigma").fetchone() == (1,)
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("CREATE TABLE x (y)")
    finally:
        conn.close()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Case #12 100%"], "no stray file"


def test_the_report_findings_read_it(odd_db):
    f = findings.collect(odd_db)
    assert not f.unreadable
    assert [(t.table, t.tier, t.flagged) for t in f.tables if t.flagged] == [
        ("alert_win_sigma", "high", 1)]


def test_the_log_coverage_reads_it(odd_db):
    assert coverage._read_table(odd_db, "art_log_coverage") != []


def test_a_sweep_finds_its_values(odd_db):
    hits, why, _hidden = sweep.sweep_database("HOST-01", odd_db, ["evil-example.exe"])
    assert why == "" and len(hits) == 1


def test_a_share_is_written_as_sqlite_wants_it():
    assert sqlite_ro.uri("//server/share/Case #1/h.db") == \
        "file:////server/share/Case%20%231/h.db?mode=ro"
