"""art_log_syslog.csv -- every syslog-format line under /var/log, chosen by content.
Synthetic host; names, hosts and addresses are invented."""
from __future__ import annotations

import csv
import gzip
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import lin_syslog

ARCHIVE = "Oct 11 23:59:58 HOST-01 sshd[812]: Accepted publickey for jdoe from 10.0.0.5 port 4242\n"
LIVE = (
    "Oct 12 10:00:01 HOST-01 CRON[900]: (root) CMD (run-parts /etc/cron.hourly)\n"
    "Oct 12 10:00:02 HOST-01 kernel: [ 12.345] eth0: link up\n"
    "  continuation of a multi-line message\n"
    "\n"
    "2026-10-12T10:00:03.123456+02:00 HOST-01 systemd[1]: Started x.service.\n"
)


def _write(base: Path, rel: str, text: str) -> None:
    f = base / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")


def _host(tmp_path: Path, zone: str = "Europe/Madrid") -> Path:
    ev = tmp_path / "ev"
    r = ev / "[root]"
    _write(r, "etc/timezone", zone + "\n")
    _write(ev, "uac.log", "2026-10-13 09:00:00 +0200 INFO uac started\n")
    log = r / "var" / "log"
    log.mkdir(parents=True)
    with gzip.open(log / "messages-20261012.gz", "wt", encoding="utf-8") as fh:
        fh.write(ARCHIVE)
    _write(log, "messages", LIVE)
    _write(log, "warn", "Oct 12 10:00:02 HOST-01 kernel: [ 12.345] eth0: link up\n")
    _write(log, "custom/fw.log", "Oct 12 11:00:00 HOST-01 fw[1]: drop\n")
    _write(log, "boot.log", "[  OK  ] Started x.service.\n[  OK  ] Reached target y.\n")
    (log / "wtmp").write_bytes(b"\x07\x00\x00\x00" + b"\x00" * 380)
    for owned in ("audit/audit.log", "httpd/error_log", "pods/x/0.log", "journal/x/sys.txt"):
        _write(log, owned, "Oct 12 10:00:00 HOST-01 x[1]: owned elsewhere\n")
    _write(log, "scc_host_261012/messages.txt", "Oct 12 10:00:00 HOST-01 x[1]: tool output\n")
    _write(log, "bundle.tar", "Oct 12 10:00:00 HOST-01 x[1]: archive\n")
    return ev


def _rows(tmp_path: Path, **kw) -> list[dict]:
    ev = _host(tmp_path, **kw)
    lin_syslog.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=logging.getLogger("t")))
    with open(tmp_path / "out" / "art_log_syslog.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_every_syslog_file_by_content_oldest_rotation_first(tmp_path):
    srcs = [r["file"].replace("\\", "/").removeprefix("[root]/var/log/") for r in _rows(tmp_path)]
    assert srcs == ["messages-20261012.gz"] + ["messages"] * 4 + ["warn", "custom/fw.log"]


def test_fields_and_utc(tmp_path):
    rows = _rows(tmp_path)
    r = rows[0]
    assert (r["time_local"], r["time_utc"], r["host"], r["program"], r["pid"]) == (
        "Oct 11 23:59:58", "2026-10-11 21:59:58", "HOST-01", "sshd", "812")
    assert r["message"] == "Accepted publickey for jdoe from 10.0.0.5 port 4242"
    k = rows[2]
    assert (k["program"], k["pid"], k["message"]) == ("kernel", "", "[ 12.345] eth0: link up")
    iso = rows[4]
    assert (iso["time_local"], iso["time_utc"], iso["program"], iso["pid"]) == (
        "2026-10-12T10:00:03.123456+02:00", "2026-10-12 08:00:03", "systemd", "1")


def test_a_line_that_is_not_syslog_keeps_only_the_message(tmp_path):
    r = _rows(tmp_path)[3]
    assert r["message"] == "  continuation of a multi-line message"
    assert not any(r[k] for k in ("time_local", "time_utc", "host", "program", "pid"))


def test_the_year_comes_from_the_archive_name_not_the_acquisition(tmp_path):
    """Dec 31 in an archive rotated 2026-01-01 is 2025, although the acquisition
    (January 2027) would make it 2026; the live file is bounded by the acquisition."""
    ev = tmp_path / "ev"
    r = ev / "[root]"
    _write(r, "etc/timezone", "UTC\n")
    _write(ev, "uac.log", "2027-01-05 09:00:00 +0000 INFO uac started\n")
    _write(r, "var/log/syslog-20260101", "Dec 31 23:00:00 HOST-01 a[1]: x\n")
    _write(r, "var/log/syslog", "Jan  4 08:00:00 HOST-01 a[1]: y\n")
    lin_syslog.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
    with open(tmp_path / "out" / "art_log_syslog.csv", encoding="utf-8", newline="") as fh:
        assert [x["time_utc"] for x in csv.DictReader(fh)] == ["2025-12-31 23:00:00", "2027-01-04 08:00:00"]


def test_no_zone_no_utc(tmp_path):
    rows = _rows(tmp_path, zone="")
    assert rows and not any(r["time_utc"] for r in rows if r["time_local"][:1].isalpha())


def test_no_syslog_file_skips(tmp_path):
    ev = tmp_path / "ev"
    _write(ev / "[root]", "var/log/boot.log", "[  OK  ] Started x.\n")
    with pytest.raises(HandlerSkip):
        lin_syslog.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
    assert not (tmp_path / "out" / "art_log_syslog.csv").exists()


def test_files_that_yield_no_line_write_nothing(tmp_path, monkeypatch):
    ev = _host(tmp_path)
    monkeypatch.setattr(lin_syslog, "iter_log_lines", lambda f: iter(()))
    lin_syslog.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
    assert not (tmp_path / "out" / "art_log_syslog.csv").exists()
