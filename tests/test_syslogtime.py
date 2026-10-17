"""v0.7.147: UTC for syslog timestamps, which classic syslog writes without year
or zone. Synthetic acquisitions; hosts, users and addresses are invented."""
from __future__ import annotations

import csv
import logging
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from artifact_engine.handlers import lin_auth, lin_cron_log, lin_sudo
from artifact_engine.handlers._syslogtime import Clock

UAC_LOG = "2026-01-10 12:00:00 +0100 INF Unix-like Artifacts Collector 3.3.0\n"


def _host(tmp_path: Path, *, timezone: str = "", timedatectl: str = "", clock: str = "",
          uac_log: str = UAC_LOG) -> Path:
    ev = tmp_path / "ev"
    (ev / "[root]" / "etc" / "sysconfig").mkdir(parents=True)
    (ev / "[root]" / "var" / "log").mkdir(parents=True)
    (ev / "live_response" / "system").mkdir(parents=True)
    if timezone:
        (ev / "[root]" / "etc" / "timezone").write_text(timezone + "\n", encoding="utf-8")
    if timedatectl:
        (ev / "live_response" / "system" / "timedatectl_status.txt").write_text(
            f"               Local time: Sat 2026-01-10 12:00:00 CET\n"
            f"                Time zone: {timedatectl} (CET, +0100)\n", encoding="utf-8")
    if clock:
        (ev / "[root]" / "etc" / "sysconfig" / "clock").write_text(clock, encoding="utf-8")
    if uac_log:
        (ev / "uac.log").write_text(uac_log, encoding="utf-8")
    return ev


def test_a_line_after_the_acquisition_date_is_from_the_year_before(tmp_path):
    c = Clock(_host(tmp_path, timezone="Europe/Madrid"))
    now = c.bound(None)
    assert c.utc("Jan  9 10:00:00", now) == "2026-01-09 09:00:00"      # CET, +1
    assert c.utc("Dec 31 23:30:00", now) == "2025-12-31 22:30:00"      # year rolled back
    assert c.utc("Jul  1 12:00:00", now) == "2025-07-01 10:00:00"      # CEST, +2


def test_a_dateext_archive_is_bounded_by_its_own_rotation_day(tmp_path):
    """A two-year-old archive the host still keeps: the acquisition's year would
    put its lines two years late."""
    c = Clock(_host(tmp_path, timezone="Europe/Madrid"))
    b = c.bound(Path("secure-20240505.gz"))
    assert c.utc("Apr 30 08:00:00", b) == "2024-04-30 06:00:00"
    assert c.utc("May  5 23:00:00", b) == "2024-05-05 21:00:00"       # the rotation day itself


def test_rfc3339_carries_its_offset_and_needs_no_zone(tmp_path):
    c = Clock(_host(tmp_path))
    assert c.zone is None
    assert c.utc("2026-01-09T10:00:00.123456+01:00", None) == "2026-01-09 09:00:00"
    assert c.utc("Jan  9 10:00:00", c.bound(None)) == ""                # no zone: no guess
    assert c.utc("Jan  9 10:00:00", datetime(2026, 1, 10, tzinfo=timezone.utc)) == ""


def test_the_zone_comes_from_timezone_then_timedatectl_then_sysconfig(tmp_path):
    assert str(Clock(_host(tmp_path / "a", timezone="Europe/Madrid",
                           timedatectl="UTC")).zone) == "Europe/Madrid"
    assert str(Clock(_host(tmp_path / "b", timedatectl="America/New_York")).zone) \
        == "America/New_York"
    # SUSE: DEFAULT_TIMEZONE is the hardware clock's, not the system's
    assert str(Clock(_host(tmp_path / "c", clock='DEFAULT_TIMEZONE="US/Eastern"\n'
                                                 'TIMEZONE="Europe/Madrid"\n')).zone) \
        == "Europe/Madrid"
    assert Clock(_host(tmp_path / "d", clock='DEFAULT_TIMEZONE="US/Eastern"\n')).zone is None


def _csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _ctx(ev: Path, out: Path):
    return SimpleNamespace(evidence=ev, out=out, log=logging.getLogger("t"))


def test_auth_cron_and_sudo_rows_carry_utc(tmp_path):
    ev = _host(tmp_path, timedatectl="Europe/Madrid")
    log = ev / "[root]" / "var" / "log"
    # an archive kept from two years back: its own rotation day dates it
    (log / "secure-20240505").write_text(
        "May  1 20:00:00 HOST-01 sshd[7]: Invalid user admin from 10.0.0.7 port 4001\n",
        encoding="utf-8")
    (log / "secure").write_text(
        "Jan  9 10:00:00 HOST-01 sshd[7]: Invalid user test from 10.0.0.8 port 4002\n",
        encoding="utf-8")
    (log / "cron").write_text(
        "Jan  9 10:05:00 HOST-01 CROND[9]: (root) CMD (/usr/bin/true)\n", encoding="utf-8")
    (log / "sudo.log").write_text(
        "Jan  9 10:06:00 2026 : jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; "
        "COMMAND=/usr/bin/id\n", encoding="utf-8")
    out = tmp_path / "out"
    for h in (lin_auth, lin_cron_log, lin_sudo):
        h.run(_ctx(ev, out))
    assert [(r["timestamp"], r["time_utc"]) for r in _csv(out / "auth_log.csv")] == [
        ("May  1 20:00:00", "2024-05-01 18:00:00"), ("Jan  9 10:00:00", "2026-01-09 09:00:00")]
    assert [r["time_utc"] for r in _csv(out / "cron_log.csv")] == ["2026-01-09 09:05:00"]
    assert [(r["time_local"], r["time_utc"]) for r in _csv(out / "sudo_log.csv")] == [
        ("2026-01-09 10:06:00", "2026-01-09 09:06:00")]
