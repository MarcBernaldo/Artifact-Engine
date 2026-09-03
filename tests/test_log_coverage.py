"""How far back Windows logging reaches, and the two silences that look alike.

A channel that holds ten days and a channel that was wiped for five both produce
an empty result for the interesting week. These tests pin the distinction the
handler exists to make -- dark WHILE SIBLINGS LOGGED is a finding, dark WITH
EVERYONE is a host that was off -- and the honesty rules around it: a filtered
dump never gets gap-analysed, and "the log was never cleared" is written down
rather than left to be inferred from a table that stays silent about it.
"""
from __future__ import annotations

import csv
import sqlite3
from datetime import date, timedelta
from pathlib import Path

import pytest

from artifact_engine.core import coverage
from artifact_engine.handlers import win_log_coverage as W


class _Ctx:
    def __init__(self, evidence: Path, out: Path):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "C"
        self.log = None


def _evtx(logs: Path, name: str, channel: str, days: list[str],
          eids: list[str] | None = None) -> None:
    """An EvtxECmd-shaped CSV: one row per (day, event id)."""
    logs.mkdir(parents=True, exist_ok=True)
    with (logs / name).open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["RecordNumber", "TimeCreated", "EventId", "Channel", "Computer"])
        for i, d in enumerate(days):
            for eid in (eids or ["4624"]):
                w.writerow([i, f"{d} 09:00:00.0000000", eid, channel, "HOST-01"])


def _span(start: str, n: int, skip: set[str] | None = None) -> list[str]:
    d0 = date.fromisoformat(start)
    out = [(d0 + timedelta(days=i)).isoformat() for i in range(n)]
    return [d for d in out if d not in (skip or set())]


def _run(tmp_path: Path, build) -> list[dict]:
    logs = tmp_path / "CSVs" / "EventLogs"
    build(logs)
    out = tmp_path / "CSVs" / "SystemInfo"
    W.run(_Ctx(tmp_path, out))
    p = out / "log_coverage.csv"
    if not p.is_file():
        return []
    with p.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _by_kind(rows: list[dict], kind: str) -> dict[str, dict]:
    return {r["channel"]: r for r in rows if r["kind"] == kind}


# --------------------------------------------------------------------------- #
# The distinction the whole handler exists to make
# --------------------------------------------------------------------------- #
def test_a_channel_dark_while_its_siblings_logged_is_flagged(tmp_path):
    def build(logs):
        _evtx(logs, "evtx_security.csv", "Security",
              _span("2026-05-01", 30, skip=set(_span("2026-05-10", 6))))
        _evtx(logs, "evtx_system.csv", "System", _span("2026-05-01", 30))
        _evtx(logs, "evtx_application.csv", "Application", _span("2026-05-01", 30))

    sec = _by_kind(_run(tmp_path, build), "full dump")["Security"]
    assert sec["suspicious"] == "yes"
    assert sec["max_gap_days"] == "6"
    assert sec["gap_start_utc"] == "2026-05-10"
    assert "SILENT" in sec["verdict"] and "other channel(s) logged" in sec["verdict"]


def test_every_channel_dark_together_is_a_host_that_was_off(tmp_path):
    """The same six missing days, this time missing everywhere. A powered-off
    laptop must not read as six days of anti-forensics."""
    gap = set(_span("2026-05-10", 6))

    def build(logs):
        for f, ch in (("evtx_security.csv", "Security"), ("evtx_system.csv", "System")):
            _evtx(logs, f, ch, _span("2026-05-01", 30, skip=gap))

    rows = _by_kind(_run(tmp_path, build), "full dump")
    assert all(r["suspicious"] == "" for r in rows.values())
    assert "every channel dark" in rows["Security"]["verdict"]


def test_a_short_channel_is_reported_but_not_flagged(tmp_path):
    """A log that rotated out is a limit on the evidence, not tampering. It has
    to be said out loud -- it is the fact that inverts conclusions -- and it must
    not compete with real findings for attention."""
    def build(logs):
        _evtx(logs, "evtx_security.csv", "Security", _span("2026-05-21", 10))
        _evtx(logs, "evtx_system.csv", "System", _span("2026-05-01", 30))

    sec = _by_kind(_run(tmp_path, build), "full dump")["Security"]
    assert sec["suspicious"] == ""
    assert "starts 20d after" in sec["verdict"]
    assert sec["first_event_utc"] == "2026-05-21" and sec["span_days"] == "10"


def test_a_one_day_hole_is_a_quiet_saturday(tmp_path):
    def build(logs):
        _evtx(logs, "evtx_security.csv", "Security",
              _span("2026-05-01", 20, skip={"2026-05-09"}))
        _evtx(logs, "evtx_system.csv", "System", _span("2026-05-01", 20))

    sec = _by_kind(_run(tmp_path, build), "full dump")["Security"]
    assert sec["suspicious"] == "" and sec["verdict"] == "continuous"


def test_a_gap_is_measured_inside_the_span_not_at_its_edges(tmp_path):
    """A channel that stops on the day of collection has not gone silent, and one
    that starts late is a capacity question. Only interior holes are gaps."""
    assert W.widest_gap({date(2026, 5, 1), date(2026, 5, 2)}) == (0, None, None)
    gap, g0, g1 = W.widest_gap({date(2026, 5, 1), date(2026, 5, 8), date(2026, 5, 9)})
    assert (gap, g0, g1) == (6, date(2026, 5, 2), date(2026, 5, 7))


# --------------------------------------------------------------------------- #
# What it refuses to answer
# --------------------------------------------------------------------------- #
def test_a_filtered_dump_is_never_gap_analysed(tmp_path):
    """evtx_tsch.csv keeps five event IDs. Its holes are the filter's holes, and
    a channel silent between two scheduled-task events is the ordinary case."""
    def build(logs):
        _evtx(logs, "evtx_security.csv", "Security", _span("2026-05-01", 30))
        _evtx(logs, "evtx_tsch.csv", "TaskScheduler/Operational",
              ["2026-05-01", "2026-05-29"], eids=["106"])

    rows = _run(tmp_path, build)
    tsch = _by_kind(rows, "filtered dump")["TaskScheduler/Operational"]
    assert tsch["suspicious"] == "" and tsch["max_gap_days"] == ""
    assert "floor only" in tsch["verdict"]


def test_a_channel_that_was_not_collected_says_so(tmp_path):
    def build(logs):
        _evtx(logs, "evtx_security.csv", "Security", _span("2026-05-01", 5))

    absent = _by_kind(_run(tmp_path, build), "absent")
    assert set(absent) == {"system", "application", "sysmon", "defender"}
    assert "not collected" in absent["system"]["verdict"]
    assert absent["system"]["suspicious"] == ""


def test_nothing_parsed_means_the_parser_skips_rather_than_reports_zero(tmp_path):
    from artifact_engine.core.runner import HandlerSkip

    (tmp_path / "CSVs" / "EventLogs").mkdir(parents=True)
    with pytest.raises(HandlerSkip):
        W.run(_Ctx(tmp_path, tmp_path / "out"))


# --------------------------------------------------------------------------- #
# The events that describe the logging itself
# --------------------------------------------------------------------------- #
def test_a_cleared_log_is_flagged(tmp_path):
    def build(logs):
        _evtx(logs, "evtx_security.csv", "Security", _span("2026-05-01", 5),
              eids=["4624", "1102"])

    row = {r["kind"]: r for r in _run(tmp_path, build)}["event 1102"]
    assert row["suspicious"] == "yes" and "CLEARED" in row["verdict"]
    assert row["event_count"] == "5"


def test_the_absence_of_a_clear_event_is_written_down(tmp_path):
    """'No 1102' is a finding. A table that simply does not mention 1102 leaves
    the analyst to infer it from silence, which is the habit this whole parser
    exists to break."""
    def build(logs):
        _evtx(logs, "evtx_security.csv", "Security", _span("2026-05-01", 5))

    kinds = {r["kind"]: r for r in _run(tmp_path, build)}
    assert kinds["event 1102"]["verdict"].startswith("none found")
    assert kinds["event 1102"]["suspicious"] == ""
    assert "event 4719" in kinds and "event 1100" in kinds


def test_1102_from_the_rdp_client_channel_is_not_a_cleared_log(tmp_path):
    """evtx_rdpOut.csv deliberately keeps 1102, where it means a disconnect. Only
    the unfiltered Security dump is scanned for clear events."""
    def build(logs):
        _evtx(logs, "evtx_security.csv", "Security", _span("2026-05-01", 5))
        _evtx(logs, "evtx_rdpOut.csv", "TerminalServices-RDPClient/Operational",
              _span("2026-05-01", 5), eids=["1102"])

    flagged = [r for r in _run(tmp_path, build) if r["suspicious"] == "yes"]
    assert flagged == []


# --------------------------------------------------------------------------- #
# The report section
# --------------------------------------------------------------------------- #
def _db(path: Path, table: str, rows: list[dict]) -> Path:
    conn = sqlite3.connect(path)
    cols = list(rows[0])
    conn.execute(f'CREATE TABLE "{table}" ({", ".join(f_ + " TEXT" for f_ in cols)})')
    conn.executemany(f'INSERT INTO "{table}" VALUES ({",".join("?" * len(cols))})',
                     [[r[c] for c in cols] for r in rows])
    conn.commit()
    conn.close()
    return path


def test_the_report_prints_coverage_above_the_findings(tmp_path):
    from artifact_engine.core.detector import Machine
    from artifact_engine.core.report import build

    db = _db(tmp_path / "HOST-01.db", "log_coverage", [
        {"channel": "Security", "kind": "full dump", "first_event_utc": "2026-05-21",
         "last_event_utc": "2026-05-30", "span_days": "10", "days_with_events": "10",
         "event_count": "900", "max_gap_days": "", "gap_start_utc": "",
         "gap_end_utc": "", "verdict": "starts 20d after the host's earliest event",
         "suspicious": ""},
    ])
    m = Machine(name="HOST-01", path=tmp_path, os="windows", collector="kape",
                source="x", profile_id="win_kape")
    build(m, [], out_dir=tmp_path, db_path=db)
    text = (tmp_path / "report.txt").read_text(encoding="utf-8")
    assert "Log coverage" in text
    assert "2026-05-21 .. 2026-05-30" in text
    assert text.index("Log coverage") < text.index("Findings")


def test_a_machine_with_no_coverage_table_gets_no_section(tmp_path):
    """An absent measurement must not render as full coverage."""
    db = _db(tmp_path / "HOST-02.db", "persistence", [{"what": "x", "suspicious": ""}])
    assert coverage.read(db) == ("", [])
    assert coverage.render(*coverage.read(db)) == []


def test_the_linux_table_answers_the_same_question(tmp_path):
    """lin_log_integrity's `rotations` rows are the Linux coverage statement, so
    the section renders them rather than being Windows-only."""
    db = _db(tmp_path / "HOST-03.db", "log_integrity", [
        {"artifact": "auth.log", "status": "rotations",
         "detail": "99 archive(s), 2025-10-31 .. 2026-08-22", "suspicious": ""},
        {"artifact": "wtmp", "status": "truncated",
         "detail": "1000 bytes (not a multiple of 384)", "suspicious": "yes"},
    ])
    text = "\n".join(coverage.render(*coverage.read(db)))
    assert "99 archive(s)" in text
    assert "! wtmp" in text and "truncated" in text
