"""The flagged rows, on the front page.

Twenty-seven handlers write a `suspicious` column and nothing read it: report.txt
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
    rowid, _sev, summary = top.rows[0]
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
    assert "Findings (rows the parsers flagged or rated):" in text
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
    assert "Artifact-Engine - Machine report" in text
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


# --------------------------------------------------------------------------- #
# The severity the detection tables already claim (v0.7.168)
# --------------------------------------------------------------------------- #
_SIGMA = ["level", "rule", "first_seen", "ip"]


@pytest.fixture
def rated(tmp_path) -> Path:
    """A detection table that rates its rows and never writes `suspicious`, a
    rule table one rule of which fires seven hundred times, a log whose `level`
    is a log level, an EvtxECmd channel, and an alert group restating rows."""
    sigma = [("high", "Noisy scanner rule", "2026-05-19", "10.0.0.5")] * 700
    sigma += [("high", "Webshell upload", "2026-05-19", "10.0.0.6")]
    sigma += [("medium", "Odd user agent", "2026-05-19", "10.0.0.7")] * 3
    sigma += [("low", "Directory listing", "2026-05-19", "10.0.0.8")] * 4
    sigma += [("informational", "Plain request", "2026-05-19", "10.0.0.9")] * 9
    return _db(tmp_path / "HOST-10.db", {
        "exfil_commands": (["severity", "tool", "command"],
                           [("critical", "rclone", "rclone copy x remote:")]
                           + [("low", "curl", f"curl {i}") for i in range(3)]),
        "web_sigma": (_SIGMA, sigma),
        "persistence": (_SUSP, [("t", f"unit-{i}", "yes" if i < 1 else "")
                                for i in range(1000)]),
        "web_errors": (["time", "level", "message"],
                       [("t", "error", "upstream"), ("t", "crit", "disk full")]),
        "evtx_System": (["TimeCreated", "Level"], [("t", "Info"), ("t", "Critical")]),
        "alerts_web": (["alert", "severity", "subject"], [("x", "high", "10.0.0.6")]),
    })


def test_a_rated_detection_table_reaches_the_front_page(rated):
    """exfil_commands and the Sigma tables never wrote `suspicious`: until this
    version their high rows were not on the page and a machine whose only
    detections lived there read as clean."""
    got = F.collect(rated)
    high = {t.table for t in got.tier("high")}
    assert {"exfil_commands", "web_sigma"} <= high
    assert "exfil_commands" not in got.unflagged
    text = "\n".join(F.render(got))
    assert "Critical / high:" in text and "[critical] rclone" in text


def test_a_log_level_is_not_a_severity(rated):
    """nginx writes `crit` in the same column name a Sigma table rates in. A
    column counts only when EVERY value is a severity word."""
    got = F.collect(rated)
    assert "web_errors" in got.unflagged
    assert "web_errors" not in {t.table for t in got.tables}


def test_an_evtx_channel_is_never_read_as_rated(rated):
    """An EvtxECmd channel holding only Info and Critical passes the vocabulary
    test; its `Level` is still the event's log level."""
    assert "evtx_System" in F.collect(rated).unflagged


def test_alert_groups_are_named_and_not_counted_twice(rated):
    got = F.collect(rated)
    assert got.restated == ["alerts_web"]
    assert "alerts_web" not in {t.table for t in got.tables}
    assert "alerts_web" in "\n".join(F.render(got))


def test_a_high_rating_outranks_a_rarer_unrated_flag(rated):
    """Rarity orders tables INSIDE a tier. One flagged row out of a thousand is
    rarer than anything in web_sigma, and still sits below a high rating."""
    order = [(t.tier, t.table) for t in F.collect(rated).tables if t.flagged]
    assert order.index(("high", "web_sigma")) < order.index(("flagged", "persistence"))
    assert order.index(("flagged", "persistence")) < order.index(("medium", "web_sigma"))


def test_a_rule_table_is_shown_per_rule_rarest_first(rated):
    """Seven hundred rows of one scanner rule listed row by row bury the one
    webshell row. Per rule, the rule that fired once comes first."""
    got = F.collect(rated)
    sigma = next(t for t in got.tier("high") if t.table == "web_sigma")
    assert [(g.rule, g.count) for g in sigma.groups] == [
        ("Webshell upload", 1), ("Noisy scanner rule", 700)]
    text = "\n".join(F.render(got))
    assert text.index("Webshell upload: 1 row(s)") < text.index("Noisy scanner rule: 700")
    assert "2 rule(s)" in text


def test_low_is_one_count_line_and_informational_is_nothing(rated, tmp_path):
    got = F.collect(rated)
    text = "\n".join(F.render(got))
    low_line = next(x for x in text.splitlines() if x.strip().startswith("Low"))
    assert "web_sigma 4" in low_line and "exfil_commands 3" in low_line
    assert "Directory listing" not in text           # counted, not listed
    assert "Plain request" not in text and got.flagged == 1 + 3 + 701 + 3 + 4 + 1
    F.write_findings_csv(got, tmp_path)
    body = (tmp_path / "findings.csv").read_text(encoding="utf-8")
    assert "Directory listing" in body               # the CSV has them


def test_the_csv_carries_each_rows_severity(rated, tmp_path):
    import csv as _csv
    F.write_findings_csv(F.collect(rated), tmp_path)
    with open(tmp_path / "findings.csv", encoding="utf-8", newline="") as fh:
        rows = list(_csv.DictReader(fh))
    by = {(r["table"], r["severity"]) for r in rows}
    assert {("exfil_commands", "critical"), ("exfil_commands", "low"),
            ("web_sigma", "high"), ("web_sigma", "medium"),
            ("persistence", "flagged")} <= by
