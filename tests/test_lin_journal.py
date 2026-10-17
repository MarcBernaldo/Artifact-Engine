"""journal.csv -- every systemd journal entry, not just the programs auth_log and
cron_log follow. Journal files are built byte by byte (test_journal.build);
hosts and users are invented."""
from __future__ import annotations

import csv
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_journal import T0, build

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import lin_journal


def _e(sec: int, **fields) -> tuple:
    return T0 + sec * 1_000_000, fields


SYSTEM = [
    _e(0, _BOOT_ID="b1", _HOSTNAME="HOST-01", SYSLOG_IDENTIFIER="sshd", _PID="812", _UID="0",
       _COMM="sshd", _SYSTEMD_UNIT="ssh.service", PRIORITY="6", _TRANSPORT="syslog",
       MESSAGE="Accepted publickey for jdoe from 10.0.0.5 port 4242"),
    _e(2, _BOOT_ID="b1", _HOSTNAME="HOST-01", _PID="1", _UID="0", _COMM="systemd",
       _SYSTEMD_UNIT="init.scope", PRIORITY="6", _TRANSPORT="journal", MESSAGE="Started x.service."),
    _e(4, _BOOT_ID="b1", _HOSTNAME="HOST-01", SYSLOG_IDENTIFIER="kernel", _TRANSPORT="kernel",
       PRIORITY="4", MESSAGE="line one\nline two"),
]
USER = [
    _e(1, _BOOT_ID="b1", _HOSTNAME="HOST-01", SYSLOG_IDENTIFIER="app", SYSLOG_PID="77", _UID="1000",
       _COMM="app", PRIORITY="3", _TRANSPORT="stdout", MESSAGE="user unit says hi"),
]


def _rows(tmp_path: Path, compact: bool = False) -> list[dict]:
    ev = tmp_path / "ev"
    jd = ev / "[root]" / "var" / "log" / "journal" / "0123456789abcdef"
    jd.mkdir(parents=True)
    (jd / "system.journal").write_bytes(build(SYSTEM, compact))
    (jd / "user-1000.journal").write_bytes(build(USER, compact))
    (jd / "notes.journal~").write_bytes(b"not a journal at all")
    lin_journal.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=logging.getLogger("t")))
    with open(tmp_path / "out" / "journal.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


@pytest.mark.parametrize("compact", [False, True])
def test_every_entry_of_every_file_in_time_order(tmp_path, compact):
    rows = _rows(tmp_path, compact)
    assert [(r["time_utc"], r["comm"], r["source"].replace("\\", "/").rsplit("/", 1)[-1]) for r in rows] == [
        ("2023-11-14 22:13:20.000000", "sshd", "system.journal"),
        ("2023-11-14 22:13:21.000000", "app", "user-1000.journal"),
        ("2023-11-14 22:13:22.000000", "systemd", "system.journal"),
        ("2023-11-14 22:13:24.000000", "", "system.journal"),
    ]


def test_fields_go_to_their_columns(tmp_path):
    r = _rows(tmp_path)[0]
    assert {k: r[k] for k in ("boot_id", "host", "identifier", "pid", "uid", "unit", "priority",
                              "transport", "message")} == {
        "boot_id": "b1", "host": "HOST-01", "identifier": "sshd", "pid": "812", "uid": "0",
        "unit": "ssh.service", "priority": "6", "transport": "syslog",
        "message": "Accepted publickey for jdoe from 10.0.0.5 port 4242"}


def test_syslog_pid_when_there_is_no_pid_and_messages_on_one_line(tmp_path):
    rows = _rows(tmp_path)
    assert (rows[1]["pid"], rows[1]["uid"], rows[1]["identifier"]) == ("77", "1000", "app")
    assert (rows[2]["identifier"], rows[2]["pid"]) == ("", "1")
    assert rows[3]["message"] == "line one line two"


def test_only_damaged_journal_files_write_nothing(tmp_path):
    jd = tmp_path / "ev" / "[root]" / "var" / "log" / "journal" / "x"
    jd.mkdir(parents=True)
    (jd / "system.journal").write_bytes(b"\0" * 4096)
    lin_journal.run(SimpleNamespace(evidence=tmp_path / "ev", out=tmp_path / "out", log=None))
    assert not (tmp_path / "out" / "journal.csv").exists()


def test_no_journal_skips(tmp_path):
    ev = tmp_path / "ev"
    (ev / "[root]" / "var" / "log").mkdir(parents=True)
    with pytest.raises(HandlerSkip):
        lin_journal.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
