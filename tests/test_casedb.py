"""The case database (core/casedb.py, AE-047): every host's alerts and timeline in
one file at the case root. Every value is invented."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from artifact_engine.core import casedb, dbnav, sweep


def _machine_db(path: Path, tables: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    for name, (cols, rows) in tables.items():
        conn.execute(f'CREATE TABLE "{name}" ({", ".join(chr(34) + c + chr(34) for c in cols)})')
        conn.executemany(f'INSERT INTO "{name}" VALUES ({",".join("?" * len(cols))})', rows)
    conn.commit()
    dbnav.create_views(conn)
    conn.close()
    return path


def _case(tmp_path: Path) -> list[tuple[str, Path]]:
    a = _machine_db(tmp_path / "HOST-01" / "HOST-01.db", {
        "alert_win_sigma": (["level", "rule", "first_seen", "match"], [
            ("high", "Rule A", "2026-05-01 10:00:00", "a.exe"),
            ("low", "Rule B", "2026-05-01 12:00:00", "b.exe")]),
        "art_prefetch": (["ExecutableName", "RunCount", "LastRun"], [
            ("EVIL.EXE", "1", "2026-05-01 09:00:00")]),
        "alert_hayabusa": (["level", "rule", "hits", "first_seen"], [
            ("medium", "Rule H", 3, "2026-05-01 08:00:00")]),
        # aggregated into alert_hayabusa: left out, as v_alerts leaves it
        "alert_hayabusa_timeline": (["Timestamp", "RuleTitle", "Level"], [
            ("2026-05-01 08:00:00", "Rule H", "med")] * 3),
    })
    b = _machine_db(tmp_path / "HOST-02" / "HOST-02.db", {
        "alert_win_sigma": (["level", "rule", "first_seen", "match", "volumes"], [
            ("critical", "Rule C", "2026-05-01 09:30:00", "c.exe", "C,VSS1")]),
        "art_logins": (["timestamp_utc", "result", "type", "user", "tty", "source_address",
                        "source"], [("2026-05-01 11:00:00", "ok", "", "jdoe", "pts/0",
                                     "10.0.0.5", "wtmp")]),
    })
    return [("HOST-01", a), ("HOST-02", b)]


def _rows(db: Path, sql: str) -> list[tuple]:
    conn = sqlite3.connect(db)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def test_every_hosts_timeline_is_one_utc_order(tmp_path):
    db = casedb.build(tmp_path, _case(tmp_path))
    assert db == tmp_path / "case.db"
    assert _rows(db, "SELECT host, time_utc, kind FROM timeline ORDER BY time_utc") == [
        ("HOST-01", "2026-05-01 08:00:00", "alert medium"),
        ("HOST-01", "2026-05-01 09:00:00", "execution (prefetch)"),
        ("HOST-02", "2026-05-01 09:30:00", "alert critical"),
        ("HOST-01", "2026-05-01 10:00:00", "alert high"),
        ("HOST-02", "2026-05-01 11:00:00", "logon"),
        ("HOST-01", "2026-05-01 12:00:00", "alert low"),
    ]
    plan = " ".join(r[-1] for r in _rows(
        db, "EXPLAIN QUERY PLAN SELECT * FROM timeline WHERE time_utc >= '2026-05-01 10'"))
    assert "USING INDEX ix_timeline_time" in plan


def test_hosts_count_their_findings_and_point_at_their_db(tmp_path):
    db = casedb.build(tmp_path, _case(tmp_path))
    hosts = casedb.host_findings(db)
    assert [(h["host"], h["db"], h["status"], h["critical"], h["high"], h["medium"], h["low"],
             h["timeline_rows"], h["first_time_utc"], h["last_time_utc"]) for h in hosts] == [
        ("HOST-02", "HOST-02/HOST-02.db", "ok", 1, 0, 0, 0, 2,
         "2026-05-01 09:30:00", "2026-05-01 11:00:00"),
        ("HOST-01", "HOST-01/HOST-01.db", "ok", 0, 1, 1, 1, 4,
         "2026-05-01 08:00:00", "2026-05-01 12:00:00"),
    ], "most severe first: one critical outranks any number of highs"
    assert _rows(db, "SELECT host, level, rule FROM alerts ORDER BY host, priority") == [
        ("HOST-01", "high", "Rule A"), ("HOST-01", "medium", "Rule H"),
        ("HOST-01", "low", "Rule B"), ("HOST-02", "critical", "Rule C")]


def test_an_alert_table_is_one_table_for_every_host_with_every_column(tmp_path):
    db = casedb.build(tmp_path, _case(tmp_path))
    assert _rows(db, "SELECT host, rule, volumes FROM alert_win_sigma ORDER BY host, rule") == [
        ("HOST-01", "Rule A", None), ("HOST-01", "Rule B", None),
        ("HOST-02", "Rule C", "C,VSS1")]
    tables = {r[0] for r in _rows(db, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "alert_hayabusa" in tables and "alert_hayabusa_timeline" not in tables
    assert "art_prefetch" not in tables, "artifacts stay in the machine .db"


def test_a_db_that_is_missing_or_not_a_database_is_a_row_that_says_so(tmp_path):
    dbs = _case(tmp_path)
    junk = tmp_path / "HOST-03" / "HOST-03.db"
    junk.parent.mkdir()
    junk.write_bytes(b"not a database at all" * 100)
    dbs += [("HOST-03", junk), ("HOST-04", tmp_path / "HOST-04" / "HOST-04.db")]
    db = casedb.build(tmp_path, dbs)
    status = {h["host"]: h["status"] for h in casedb.host_findings(db)}
    assert status["HOST-01"] == status["HOST-02"] == "ok"
    assert status["HOST-03"].startswith(("unreadable", "partly read"))
    assert status["HOST-04"] == "no .db"


def test_a_case_db_that_cannot_be_written_leaves_the_last_one(tmp_path, monkeypatch):
    dbs = _case(tmp_path)
    first = casedb.build(tmp_path, dbs)
    before = first.read_bytes()

    def refuse(*a, **k):
        raise sqlite3.OperationalError("disk I/O error")
    monkeypatch.setattr(casedb.sqlite3, "connect", refuse)
    assert casedb.build(tmp_path, dbs) is None
    assert first.read_bytes() == before
    assert not (tmp_path / "case.db.tmp").exists()


def test_nothing_to_read_writes_nothing(tmp_path):
    assert casedb.build(tmp_path, []) is None
    assert not (tmp_path / "case.db").exists()


def test_sweep_does_not_take_the_case_db_for_a_machine(tmp_path):
    dbs = _case(tmp_path)
    for _host, db in dbs:
        (db.parent / "report.txt").write_text("report", encoding="utf-8")   # a machine's outputs
    casedb.build(tmp_path, dbs)
    found = sweep.find_case_databases(tmp_path)
    assert sorted(name for name, _ in found) == ["HOST-01", "HOST-02"]
    assert all(p.name != "case.db" for _, p in found)


def test_a_run_writes_the_case_db_and_the_next_run_does_not_hash_it(tmp_path, monkeypatch):
    """End to end through cmd_run, twice: the machine's .db is consolidated, case.db
    is built from it at the root, and the second run's phase 0 skips it."""
    import argparse
    import csv

    from artifact_engine import cli
    from artifact_engine.core import extractor, hashing, pipeline, scheduler
    from artifact_engine.core.detector import Machine, Volume
    from artifact_engine.core.runner import ParserRun

    (tmp_path / "HOST-01.zip").write_bytes(b"evidence")
    mdir = tmp_path / "HOST-01"
    det = mdir / "CSVs" / "Detections"
    det.mkdir(parents=True)
    (det / "alert_win_sigma.csv").write_text(
        "level,rule,first_seen,match\nhigh,Rule A,2026-05-01 10:00:00,a.exe\n", encoding="utf-8")
    m = Machine("HOST-01", "windows", "kape", "windows_kape", mdir, "src",
                [Volume("live", mdir, True)])
    m.display = "HOST-01"

    def run_all(*a, **k):
        results = [(m, [ParserRun("alert_win_sigma", "live", "ok", 1.0, "")])]
        scheduler.write_manifests(results)
        return results

    monkeypatch.setattr(extractor, "extract_all", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "detect", lambda *a, **k: [m])
    monkeypatch.setattr(scheduler, "run_all", run_all)
    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)

    cli.cmd_run(args)
    db = tmp_path / casedb.CASE_DB
    assert _rows(db, "SELECT host, level, rule FROM alerts") == [("HOST-01", "high", "Rule A")]
    cli.cmd_run(args)

    with open(tmp_path / hashing.TRACES_CSV, encoding="utf-8", newline="") as fh:
        recorded = {r[0] for r in list(csv.reader(fh))[1:] if r}
    assert casedb.CASE_DB not in recorded and "HOST-01.zip" in recorded
    # AE-048: the case page and the summary's findings per host; the page is an
    # engine output to the next run's phase 0 as well
    import json
    assert "case.html" not in recorded
    assert "HOST-01" in (tmp_path / "case.html").read_text(encoding="utf-8")
    summary = json.loads((tmp_path / "run-summary.json").read_text(encoding="utf-8"))
    assert [(h["host"], h["high"]) for h in summary["findings_per_host"]] == [("HOST-01", 1)]


# --------------------------------------------------------------------------- #
# Found by review (v0.7.200)
# --------------------------------------------------------------------------- #
def test_a_hash_in_a_folder_name_opens_the_right_database(tmp_path):
    root = tmp_path / "Case #12"
    dbs = _case(root)
    db = casedb.build(root, dbs)
    hosts = {h["host"]: h for h in casedb.host_findings(db)}
    assert hosts["HOST-02"]["critical"] == 1 and hosts["HOST-01"]["high"] == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == ["Case #12"], "no stray file"


def test_an_alert_table_with_its_own_host_column_is_kept(tmp_path):
    db_path = _machine_db(tmp_path / "HOST-01" / "HOST-01.db", {
        "alert_hayabusa": (["level", "rule", "hits", "host", "first_seen"], [
            ("high", "Rule H", 2, "HOST-01.example.local", "2026-05-01 08:00:00")])})
    db = casedb.build(tmp_path, [("HOST-01", db_path)])
    assert _rows(db, f"SELECT host, rule, {casedb.OWN_HOST} FROM alert_hayabusa") == [
        ("HOST-01", "Rule H", "HOST-01.example.local")]


def test_two_units_of_one_host_stay_two_hosts(tmp_path):
    disk = _machine_db(tmp_path / "HOST-01" / "HOST-01.db", {
        "alert_win_sigma": (["level", "rule", "first_seen"], [("high", "Disk", "2026-05-01")])})
    mem = _machine_db(tmp_path / "HOST-01_memory" / "HOST-01.db", {
        "alert_mem_malfind": (["level", "rule", "first_seen"], [("high", "Mem", "2026-05-01")])})
    db = casedb.build(tmp_path, [("HOST-01", disk), ("HOST-01", mem)])
    assert sorted(_rows(db, "SELECT host, rule FROM alerts")) == [
        ("HOST-01 (HOST-01)", "Disk"), ("HOST-01 (HOST-01_memory)", "Mem")]


def test_a_db_this_run_did_not_rebuild_is_named_and_not_copied(tmp_path):
    dbs = _case(tmp_path)
    db = casedb.build(tmp_path, dbs, not_rebuilt={str(dbs[1][1]): "PermissionError: locked"})
    status = {h["host"]: h["status"] for h in casedb.host_findings(db)}
    assert status == {"HOST-01": "ok",
                      "HOST-02": "not rebuilt this run: PermissionError: locked"}
    assert _rows(db, "SELECT DISTINCT host FROM alerts") == [("HOST-01",)]


def test_a_machine_named_case_at_the_root_keeps_its_database(tmp_path):
    own = _machine_db(tmp_path / "x" / "CASE.db", {
        "alert_win_sigma": (["level", "rule", "first_seen"], [("high", "R", "2026-05-01")])})
    at_root = tmp_path / "CASE.db"
    own.replace(at_root)
    before = at_root.read_bytes()
    assert casedb.build(tmp_path, [("CASE", at_root)]) is None
    assert at_root.read_bytes() == before


def test_a_run_whose_consolidation_failed_says_so_in_the_case_db(tmp_path, monkeypatch):
    """cmd_run hands case.db the units it did not build: a .db left by an earlier
    run is named as not rebuilt, not read as this run's."""
    import argparse

    from artifact_engine import cli
    from artifact_engine.core import consolidate, extractor, pipeline, scheduler
    from artifact_engine.core.detector import Machine, Volume
    from artifact_engine.core.runner import ParserRun

    mdir = tmp_path / "HOST-01"
    _machine_db(mdir / "HOST-01.db", {   # the last run's database
        "alert_win_sigma": (["level", "rule", "first_seen"], [("high", "Old", "2026-05-01")])})
    m = Machine("HOST-01", "windows", "kape", "windows_kape", mdir, "src",
                [Volume("live", mdir, True)])
    m.display = "HOST-01"

    def run_all(*a, **k):
        results = [(m, [ParserRun("p", "live", "ok", 1.0, "")])]
        scheduler.write_manifests(results)
        return results

    monkeypatch.setattr(extractor, "extract_all", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "detect", lambda *a, **k: [m])
    monkeypatch.setattr(scheduler, "run_all", run_all)
    monkeypatch.setattr(consolidate, "consolidate_unit",
                        lambda i, *a, **k: (i, "PermissionError: locked", {}))
    cli.cmd_run(argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False))

    db = tmp_path / casedb.CASE_DB
    assert _rows(db, "SELECT host, status FROM hosts") == [
        ("HOST-01", "not rebuilt this run: PermissionError: locked")]
    assert _rows(db, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'alerts'") == [(0,)]
