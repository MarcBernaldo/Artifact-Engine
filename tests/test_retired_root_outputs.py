"""case.db and case.html are no longer written (AE-131), and what an earlier version
left at a case root is named, kept and never taken for evidence -- told apart from a
delivered file of the same name by its content. Every value is invented."""
from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from pathlib import Path

from artifact_engine import cli
from artifact_engine.core import extractor, hashing, pipeline, report, retired_outputs, scheduler
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.core.runner import ParserRun

# The tables v0.7.200-v0.7.209 gave case.db, written out here rather than imported:
# a change to the module's own list must show up as a failing test.
_HOSTS = ("host", "db", "status", "critical", "high", "medium", "low", "flagged",
          "timeline_rows", "first_time_utc", "last_time_utc")
_ALERTS = ("host", "priority", "level", "source_table", "source_rowid", "rule",
           "timestamp", "summary")
_PAGE = ("<!doctype html><html lang=en><head><meta charset=utf-8>\n"
         "<title>Case: CASE-01</title><style>body{margin:24px}</style></head><body>\n"
         "<h1>Case CASE-01</h1>\n"
         "<p class=muted>1 host(s) | critical 0 | high 1 | generated 2026-11-01 10:00 UTC "
         "from case.db</p>\n</body></html>")


def _sqlite(path: Path, table: str, cols: tuple[str, ...]) -> Path:
    conn = sqlite3.connect(path)
    conn.execute(f'CREATE TABLE "{table}" ({", ".join(chr(34) + c + chr(34) for c in cols)})')
    conn.commit()
    conn.close()
    return path


def _run(tmp_path: Path, monkeypatch) -> int:
    """One `aeng run` over a case of one machine whose parsers already wrote an
    alert table: extraction, detection and parsing stubbed, the rest for real."""
    if not (tmp_path / "HOST-01.zip").exists():
        (tmp_path / "HOST-01.zip").write_bytes(b"evidence")
    mdir = tmp_path / "HOST-01"
    det = mdir / "CSVs" / "Detections"
    det.mkdir(parents=True, exist_ok=True)
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
    return cli.cmd_run(argparse.Namespace(path=str(tmp_path), config=None, verbose=False,
                                          force=False))


def _recorded(tmp_path: Path) -> set[str]:
    with open(tmp_path / hashing.TRACES_CSV, encoding="utf-8", newline="") as fh:
        return {r[0] for r in list(csv.reader(fh))[1:] if r}


def _log(tmp_path: Path) -> str:
    return (tmp_path / "aeng-run.log").read_text(encoding="utf-8", errors="replace")


def test_a_run_keeps_the_machine_db_and_writes_no_case_db_nor_case_page(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)

    assert (tmp_path / "HOST-01" / "HOST-01.db").is_file()     # the machine's .db stays
    assert not (tmp_path / "case.db").exists()
    assert not (tmp_path / "case.html").exists()
    summary = json.loads((tmp_path / "run-summary.json").read_text(encoding="utf-8"))
    assert "findings_per_host" not in summary
    # a key that disappears bumps the contract (report.SCHEMA_VERSION's history)
    assert summary["schema_version"] == report.SCHEMA_VERSION == 7
    assert "Findings per host" not in (tmp_path / "run-summary.txt").read_text(encoding="utf-8")


def test_the_stub_has_no_findings_per_host_either(tmp_path):
    report.write_stub(tmp_path, "running", "start")
    stub = json.loads((tmp_path / "run-summary.json").read_text(encoding="utf-8"))
    assert "findings_per_host" not in stub and stub["schema_version"] == 7


def test_what_an_earlier_version_left_is_named_kept_and_not_hashed(tmp_path, monkeypatch):
    _sqlite(tmp_path / "case.db", "hosts", _HOSTS)
    # a killed run's .tmp: the connection opened, nothing written yet -- empty, so
    # nothing in it says whose it is but the engine's own temporary name
    (tmp_path / "case.db.tmp").write_bytes(b"")
    (tmp_path / "case.html").write_text(_PAGE, encoding="utf-8")
    (tmp_path / "case.html.tmp").write_text(_PAGE[:400], encoding="utf-8")   # cut short
    names = ("case.db", "case.db.tmp", "case.html", "case.html.tmp")
    before = {n: (tmp_path / n).read_bytes() for n in names}

    _run(tmp_path, monkeypatch)
    _run(tmp_path, monkeypatch)

    assert {n: (tmp_path / n).read_bytes() for n in names} == before   # left as it was
    assert _log(tmp_path).count("case.db, case.db.tmp, case.html, case.html.tmp at the case "
                                "root: written by an earlier version") == 2
    recorded = _recorded(tmp_path)
    assert "HOST-01.zip" in recorded
    assert not set(names) & recorded


def test_a_delivered_file_of_that_name_is_evidence(tmp_path, monkeypatch):
    """Nothing writes these names any more, so a case.db or case.html that is not
    the engine's -- a partner's export, a tool's database -- is an original: hashed,
    and never called an earlier version's output."""
    _sqlite(tmp_path / "case.db", "tickets", ("id", "title"))
    (tmp_path / "case.html").write_text("<html><title>Ticket 42</title></html>", encoding="utf-8")

    _run(tmp_path, monkeypatch)

    assert {"case.db", "case.html"} <= _recorded(tmp_path)
    assert "written by an earlier version" not in _log(tmp_path)


def test_an_old_case_db_is_told_by_its_bytes_wherever_its_tables_sit(tmp_path):
    """One holds `alerts` without `hosts`. Another holds `hosts` alone (no host had
    the views `alerts` and `timeline` were read from), and created last: the alert
    tables copied from the hosts filled the first page, so the schema went to pages
    written after the rows, megabytes in (found by review)."""
    from artifact_engine.core import retired_outputs as R

    _sqlite(tmp_path / "case.db", "alerts", _ALERTS)
    assert R.is_one(tmp_path / "case.db")
    big = tmp_path / "x" / "case.db"
    big.parent.mkdir()
    q = '"{}"'.format
    conn = sqlite3.connect(big)
    conn.execute('CREATE TABLE "alert_a" ("host", "v")')
    conn.executemany('INSERT INTO "alert_a" VALUES (?, ?)', [("HOST-01", "x" * 900)] * 3000)
    cols = ", ".join(q(f"c{j}") for j in range(30))
    for i in range(40):                            # what the other hosts' copies brought
        conn.execute(f"CREATE TABLE {q(f'alert_t{i}')} ({cols})")
    conn.execute(f"CREATE TABLE {q('hosts')} ({', '.join(q(c) for c in _HOSTS)})")
    conn.commit()
    conn.close()
    assert big.read_bytes().find(R._DB_MARKS[0]) > 2 * R._CHUNK    # past two slices
    assert R.is_one(big)


def test_a_statement_cut_by_a_slice_boundary_is_found(tmp_path, monkeypatch):
    from artifact_engine.core import retired_outputs as R

    mark = R._DB_MARKS[0]
    f = tmp_path / "blob"
    f.write_bytes(b"x" * 50 + mark + b"y" * 100)
    # 64-byte slices: the statement starts in the first and ends slices later
    monkeypatch.setattr(R, "_CHUNK", 64)
    assert R._holds(f, R._DB_MARKS)
    f.write_bytes(b"x" * 50 + mark[:-1] + b"y" * 100)
    assert not R._holds(f, R._DB_MARKS)


def test_a_delivered_wal_database_is_hashed_and_never_opened(tmp_path, monkeypatch):
    """Even a read-only SQLite connection creates `-shm` and `-wal` beside a WAL-mode
    database: opening a delivered case.db to look at it would write into the case
    before its custody is recorded (found by review). It is read as bytes."""
    conn = sqlite3.connect(tmp_path / "case.db")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute('CREATE TABLE "tickets" ("id", "title")')
    conn.commit()
    conn.close()
    before = (tmp_path / "case.db").read_bytes()

    _run(tmp_path, monkeypatch)

    assert not (tmp_path / "case.db-shm").exists() and not (tmp_path / "case.db-wal").exists()
    assert (tmp_path / "case.db").read_bytes() == before
    assert "case.db" in _recorded(tmp_path)


def test_a_machine_named_case_at_the_root_is_no_leftover(tmp_path):
    """A machine detected at the root and named `case` writes its own case.db (NTFS
    ignores case): a machine database, not the case database an earlier version wrote."""
    own = _sqlite(tmp_path / "CASE.db", "art_prefetch", ("ExecutableName", "RunCount"))
    assert not retired_outputs.is_one(own)
    assert cli._report_retired(tmp_path) == []
