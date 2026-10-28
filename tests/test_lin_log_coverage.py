"""How far back Linux logging reaches, measured from the parsed tables (v0.7.168).

The Windows rules carried over -- dark while a sibling logged is a finding, dark
with everyone is a host that was off -- plus the one Linux needs: wtmp, btmp,
sudo and the web log record events, and a day without one is not a hole.
"""
from __future__ import annotations

import csv
import sqlite3
from datetime import date, timedelta
from pathlib import Path

import pytest

from artifact_engine.core import coverage
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import lin_log_coverage as L


class _Ctx:
    def __init__(self, evidence: Path, out: Path):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "root"
        self.log = None


def _days(start: str, n: int, skip: set[str] | None = None) -> list[str]:
    d0 = date.fromisoformat(start)
    out = [(d0 + timedelta(days=i)).isoformat() for i in range(n)]
    return [d for d in out if d not in (skip or set())]


def _csv(base: Path, rel: str, header: list[str], rows: list[list]) -> None:
    p = base / "CSVs" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def _log(base: Path, rel: str, days: list[str]) -> None:
    _csv(base, rel, ["timestamp", "time_utc", "detail"],
         [[f"{d} 09:00:00", f"{d} 09:00:00", "x"] for d in days])


def _run(tmp_path: Path) -> dict[str, dict]:
    out = tmp_path / "CSVs" / "SystemInfo"
    L.run(_Ctx(tmp_path, out))
    with (out / "art_log_coverage.csv").open(encoding="utf-8") as fh:
        return {r["channel"]: r for r in csv.DictReader(fh)}


def test_auth_dark_while_syslog_logged_is_flagged(tmp_path):
    _log(tmp_path, "EventLogs/art_log_syslog.csv", _days("2026-05-01", 30))
    _log(tmp_path, "EventLogs/art_log_auth.csv",
         _days("2026-05-01", 30, skip=set(_days("2026-05-10", 5))))
    got = _run(tmp_path)
    assert got["auth"]["suspicious"] == "yes"
    assert got["auth"]["verdict"].startswith("SILENT 5d") and "syslog" in got["auth"]["verdict"]
    assert got["syslog"]["suspicious"] == ""


def test_a_week_without_a_login_is_an_ordinary_week(tmp_path):
    """wtmp holds logins, not time. Measured, never gap-analysed."""
    _log(tmp_path, "EventLogs/art_log_syslog.csv", _days("2026-05-01", 30))
    _csv(tmp_path, "EventLogs/art_logins.csv", ["time_utc", "user", "source"],
         [["2026-05-01 08:00:00", "jdoe", "wtmp"], ["2026-05-29 08:00:00", "jdoe", "wtmp"],
          ["2026-05-03 08:00:00", "root", "btmp"],
          ["", "jdoe", "lastlog"]])
    got = _run(tmp_path)
    assert got["wtmp"]["kind"] == "event log" and got["wtmp"]["suspicious"] == ""
    assert (got["wtmp"]["first_event_utc"], got["wtmp"]["last_event_utc"]) == \
        ("2026-05-01", "2026-05-29")
    assert got["wtmp"]["days_with_events"] == "2" and got["wtmp"]["max_gap_days"] == ""
    assert got["btmp"]["event_count"] == "1"


def test_a_web_time_with_its_offset_is_counted_on_its_utc_day(tmp_path):
    _csv(tmp_path, "Web/art_web_access.csv", ["time", "ip"],
         [["2026-05-19 01:30:00 +0200", "10.0.0.5"]])
    got = _run(tmp_path)
    assert got["web access"]["first_event_utc"] == "2026-05-18"


def test_the_two_logs_every_host_writes_are_named_when_absent(tmp_path):
    _log(tmp_path, "EventLogs/art_log_cron.csv", _days("2026-05-01", 3))
    got = _run(tmp_path)
    assert got["syslog"]["kind"] == "absent" and got["auth"]["kind"] == "absent"
    assert "audit" not in got                    # no auditd is an ordinary host


def test_nothing_parsed_skips(tmp_path):
    with pytest.raises(HandlerSkip):
        L.run(_Ctx(tmp_path, tmp_path / "out"))


def test_the_report_prints_the_span_and_the_rotations_together(tmp_path):
    """Linux has both tables now: what the parsed logs span, and what /var/log
    kept. Printing only the first one found would hide the other."""
    db = tmp_path / "HOST-01.db"
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE art_log_coverage (channel, kind, first_event_utc, '
                 'last_event_utc, span_days, days_with_events, verdict, suspicious)')
    conn.execute("INSERT INTO art_log_coverage VALUES ('auth', 'full dump', '2026-05-01', "
                 "'2026-05-30', 30, 25, 'SILENT 5d while 1 other channel(s) logged: syslog', 'yes')")
    conn.execute("CREATE TABLE art_log_integrity (artifact, status, detail, suspicious)")
    conn.execute("INSERT INTO art_log_integrity VALUES ('auth.log', 'rotations', "
                 "'4 archive(s), 2026-05-01 .. 2026-05-30', '')")
    conn.commit()
    conn.close()
    text = "\n".join(coverage.render(coverage.read(db)))
    assert text.count("Log coverage") == 1
    assert "! auth" in text and "4 archive(s)" in text


def test_an_old_archive_across_a_gap_is_not_a_wiped_log(tmp_path):
    """/var/log keeps its last weeks plus the odd archive from long ago. syslog
    writing on two days of auth's twenty-day hole is that, not a wipe."""
    old = _days("2026-04-01", 3)
    recent = _days("2026-04-25", 10)
    _log(tmp_path, "EventLogs/art_log_syslog.csv", old + ["2026-04-10", "2026-04-15"] + recent)
    _log(tmp_path, "EventLogs/art_log_auth.csv", old + recent)
    got = _run(tmp_path)
    assert got["auth"]["suspicious"] == "" and got["auth"]["max_gap_days"] == "21"
    assert "not a hole" in got["auth"]["verdict"]
