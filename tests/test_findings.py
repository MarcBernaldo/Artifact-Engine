"""The flagged rows, on the front page.

Ninety-seven parsers write a `suspicious` column and nothing read it: report.txt
listed which parsers RAN, and what they FOUND stayed inside the .db behind SQL
somebody had to write. These tests pin the two decisions that make a front page
worth having -- what it ranks by, and what it admits it does not cover.
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

import pytest

from artifact_engine.core import findings as F


def _db(path: Path, tables: dict[str, tuple[list[str], list[tuple]]]) -> Path:
    conn = sqlite3.connect(path)
    for name, (cols, rows) in tables.items():
        coldef = ", ".join(f'"{c}" TEXT' for c in cols)
        conn.execute(f'CREATE TABLE "{name}" ({coldef})')
        marks = ",".join("?" * len(cols))
        conn.executemany(f'INSERT INTO "{name}" VALUES ({marks})', rows)
    conn.commit()
    conn.close()
    return path


_SUSP = ["when", "what", "suspicious"]


@pytest.fixture
def machine(tmp_path) -> Path:
    """A selective flag, a rule that fires on nearly everything, and a table with
    no flag column at all -- the three shapes a real machine produces."""
    return _db(tmp_path / "HOST-01.db", {
        # 2 of 500: the signal worth reading first
        "persistence": (_SUSP, [("2026-05-18", f"unit-{i}", "yes" if i < 2 else "")
                                for i in range(500)]),
        # 40 of 50: a rule, not a finding
        "web_access": (_SUSP, [("2026-05-18", f"req-{i}", "yes" if i < 40 else "")
                               for i in range(50)]),
        # no flag column: an external tool's own schema
        "evtx_Security": (["TimeCreated", "EventId"], [("2026-05-18", "4624")]),
    })


# --------------------------------------------------------------------------- #
# What it ranks by
# --------------------------------------------------------------------------- #
def test_the_selective_flag_outranks_the_noisy_one(machine):
    """Ordering by COUNT puts the table with forty hits above the one with two,
    which is precisely backwards: a rule that fires on most of its own table is
    a rule, and two rows out of five hundred is somebody's afternoon."""
    got = F.collect(machine)
    assert [t.table for t in got.tables if t.flagged] == ["persistence", "web_access"]
    assert got.tables[0].flagged == 2 and got.tables[0].total == 500


def test_the_ranking_is_a_rate_not_a_count(tmp_path):
    """Same absolute count, different denominators: the one that had to pick its
    two rows out of a thousand ranks above the one that picked two out of four."""
    db = _db(tmp_path / "HOST-02.db", {
        "narrow": (_SUSP, [("t", f"a{i}", "yes" if i < 2 else "") for i in range(1000)]),
        "wide": (_SUSP, [("t", f"b{i}", "yes" if i < 2 else "") for i in range(4)]),
    })
    assert [t.table for t in F.collect(db).tables] == ["narrow", "wide"]


def test_a_flagged_row_carries_the_pointer_back_to_itself(machine):
    """A front page whose rows cannot be chased is a front page nobody trusts."""
    top = F.collect(machine).tables[0]
    rowid, summary = top.rows[0]
    conn = sqlite3.connect(machine)
    assert conn.execute('SELECT "what" FROM "persistence" WHERE rowid=?',
                        (rowid,)).fetchone()[0] in summary
    conn.close()


def test_an_empty_flag_is_not_a_flag(machine):
    """The convention is `yes` or EMPTY, never `no`. A blank counted as flagged
    would make every table 100% suspicious."""
    assert F.collect(machine).flagged == 42


# --------------------------------------------------------------------------- #
# What it admits it does not cover
# --------------------------------------------------------------------------- #
def test_the_tables_it_cannot_speak_for_are_named(machine):
    """Most of the evidence by volume -- MFT, the EvtxECmd channels, hayabusa --
    has an external tool's schema and no flag column. A short findings list over
    those tables reads as a short case, so the section says which tables it is
    silent about rather than implying it covered them."""
    got = F.collect(machine)
    assert got.unflagged == ["evtx_Security"]
    text = "\n".join(F.render(got))
    assert "evtx_Security" in text
    assert "NOT covered by this section" in text


def test_a_clean_machine_still_prints_the_section(tmp_path):
    """An absent section and a section saying nothing was flagged read very
    differently to somebody opening the file months later."""
    db = _db(tmp_path / "HOST-03.db", {"persistence": (_SUSP, [("t", "a", "")])})
    text = "\n".join(F.render(F.collect(db)))
    assert "Findings" in text and "Nothing flagged" in text


def test_a_database_that_is_not_there_says_so_rather_than_nothing(tmp_path):
    got = F.collect(tmp_path / "missing.db")
    assert got.unreadable
    assert "NOT AVAILABLE" in "\n".join(F.render(got))


def test_a_corrupt_database_is_not_a_clean_machine(tmp_path):
    bad = tmp_path / "HOST-04.db"
    bad.write_bytes(b"not a database at all")
    got = F.collect(bad)
    assert got.unreadable and got.flagged == 0
    assert "NOT AVAILABLE" in "\n".join(F.render(got))


# --------------------------------------------------------------------------- #
# The CSV half
# --------------------------------------------------------------------------- #
def test_the_csv_is_written_beside_the_report_and_not_inside_CSVs(machine, tmp_path):
    """Consolidation absorbs every CSV under `CSVs/` into the .db. A findings file
    living there would come back next run as a table built from the previous
    run's summary of itself."""
    out = F.write_findings_csv(F.collect(machine), tmp_path)
    assert out is not None and out.parent == tmp_path
    assert out.name == "findings.csv"
    assert not (tmp_path / "CSVs").exists()


def test_the_csv_carries_more_than_the_report_shows(machine, tmp_path):
    """report.txt is a front page; the CSV is what feeds a logbook."""
    got = F.collect(machine)
    F.write_findings_csv(got, tmp_path)
    body = (tmp_path / "findings.csv").read_text(encoding="utf-8").splitlines()[1:]
    assert len(body) == 42                       # every flagged row, not 5 per table
    assert "... 35 more" in "\n".join(F.render(got))   # the report says so


def test_a_table_bigger_than_the_cap_says_it_was_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(F, "_CSV_CAP", 3)
    db = _db(tmp_path / "HOST-05.db",
             {"web_access": (_SUSP, [("t", f"r{i}", "yes") for i in range(10)])})
    got = F.collect(db)
    assert got.tables[0].truncated
    assert "csv truncated at 3" in "\n".join(F.render(got))


def test_nothing_flagged_writes_no_csv(tmp_path):
    db = _db(tmp_path / "HOST-06.db", {"persistence": (_SUSP, [("t", "a", "")])})
    assert F.write_findings_csv(F.collect(db), tmp_path) is None
    assert not (tmp_path / "findings.csv").exists()


# --------------------------------------------------------------------------- #
# Wired into the report
# --------------------------------------------------------------------------- #
def test_report_txt_gains_the_section(machine, tmp_path):
    from artifact_engine.core.detector import Machine
    from artifact_engine.core.report import build

    m = Machine(name="HOST-01", path=tmp_path, os="linux", collector="uac",
                source="x", profile_id="linux_uac")
    build(m, [], out_dir=tmp_path, db_path=machine)
    text = (tmp_path / "report.txt").read_text(encoding="utf-8")
    assert "Findings (rows the parsers flagged):" in text
    assert "persistence: 2 of 500" in text
    assert "aeng sweep" in text, "the cross-case search nobody knew existed"


def test_a_report_without_a_database_is_still_written(tmp_path):
    """The findings section is an addition, not a precondition. `aeng lateral` and
    any caller that has no .db must still get their report."""
    from artifact_engine.core.detector import Machine
    from artifact_engine.core.report import build

    m = Machine(name="HOST-07", path=tmp_path, os="linux", collector="uac",
                source="x", profile_id="linux_uac")
    build(m, [], out_dir=tmp_path)
    text = (tmp_path / "report.txt").read_text(encoding="utf-8")
    assert "Artifact Engine - Machine report" in text
    assert "Findings" not in text


def test_the_section_survives_a_locked_database(machine, tmp_path, monkeypatch, caplog):
    """A .db open in Excel is the ordinary case, not an exception. The report must
    still be written, and it must say the findings are missing rather than empty."""
    from artifact_engine.core.detector import Machine
    from artifact_engine.core.report import build

    monkeypatch.setattr(F.sqlite3, "connect",
                        lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("locked")))
    m = Machine(name="HOST-08", path=tmp_path, os="linux", collector="uac",
                source="x", profile_id="linux_uac")
    with caplog.at_level(logging.WARNING, logger="aeng"):
        build(m, [], out_dir=tmp_path, db_path=machine)
    assert "NOT AVAILABLE" in (tmp_path / "report.txt").read_text(encoding="utf-8")
