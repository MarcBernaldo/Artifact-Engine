"""syslog.csv, its journal rows -- every systemd journal entry, not just the
programs auth_log and cron_log follow, less the ones a syslog file already holds.
Journal files are built byte by byte (test_journal.build); hosts and users are
invented."""
from __future__ import annotations

import csv
import logging
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_journal import T0, build

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import lin_syslog


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


def _journal_dir(ev: Path) -> Path:
    jd = ev / "[root]" / "var" / "log" / "journal" / "0123456789abcdef"
    jd.mkdir(parents=True)
    return jd


def _run(ev: Path, out: Path) -> list[dict]:
    lin_syslog.run(SimpleNamespace(evidence=ev, out=out, log=logging.getLogger("t")))
    with open(out / "syslog.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _rows(tmp_path: Path, compact: bool = False) -> list[dict]:
    ev = tmp_path / "ev"
    jd = _journal_dir(ev)
    (jd / "system.journal").write_bytes(build(SYSTEM, compact))
    (jd / "user-1000.journal").write_bytes(build(USER, compact))
    (jd / "notes.journal~").write_bytes(b"not a journal at all")
    return _run(ev, tmp_path / "out")


@pytest.mark.parametrize("compact", [False, True])
def test_every_entry_of_every_file_in_time_order(tmp_path, compact):
    rows = _rows(tmp_path, compact)
    assert [(r["time_utc"], r["comm"], r["source"],
             r["file"].replace("\\", "/").rsplit("/", 1)[-1]) for r in rows] == [
        ("2023-11-14 22:13:20.000000", "sshd", "journal", "system.journal"),
        ("2023-11-14 22:13:21.000000", "app", "journal", "user-1000.journal"),
        ("2023-11-14 22:13:22.000000", "systemd", "journal", "system.journal"),
        ("2023-11-14 22:13:24.000000", "", "journal", "system.journal"),
    ]


def test_fields_go_to_their_columns(tmp_path):
    r = _rows(tmp_path)[0]
    assert {k: r[k] for k in ("boot_id", "host", "program", "pid", "uid", "unit", "priority",
                              "transport", "message", "time_local")} == {
        "boot_id": "b1", "host": "HOST-01", "program": "sshd", "pid": "812", "uid": "0",
        "unit": "ssh.service", "priority": "6", "transport": "syslog",
        "message": "Accepted publickey for jdoe from 10.0.0.5 port 4242", "time_local": ""}


def test_syslog_pid_when_there_is_no_pid_and_messages_on_one_line(tmp_path):
    rows = _rows(tmp_path)
    assert (rows[1]["pid"], rows[1]["uid"], rows[1]["program"]) == ("77", "1000", "app")
    assert (rows[2]["program"], rows[2]["pid"]) == ("", "1")
    assert rows[3]["message"] == "line one line two"


def _with_syslog(tmp_path: Path, lines: str, span: tuple[int, int] | None = (0, 4),
                 entries=SYSTEM) -> list[dict]:
    """The journal above beside a syslog file in UTC; `span` is the journal
    header's first/last entry time (seconds after T0), None to leave it 0."""
    ev = tmp_path / "ev"
    jd = _journal_dir(ev)
    data = bytearray(build(entries))
    if span:
        struct.pack_into("<QQ", data, 184, T0 + span[0] * 1_000_000, T0 + span[1] * 1_000_000)
    (jd / "system.journal").write_bytes(bytes(data))
    (ev / "[root]" / "etc").mkdir(parents=True)
    (ev / "[root]" / "etc" / "timezone").write_text("UTC\n", encoding="utf-8")
    (ev / "[root]" / "var" / "log" / "messages").write_text(lines, encoding="utf-8")
    return _run(ev, tmp_path / "out")


# T0 is 2023-11-14 22:13:20 UTC
SSHD = "2023-11-14T22:13:21+00:00 HOST-01 sshd[812]: Accepted publickey for jdoe from 10.0.0.5 port 4242\n"


def test_a_journal_entry_rsyslog_already_wrote_is_one_row(tmp_path):
    """Forwarded to rsyslog a second later: the syslog line stays, the journal's
    copy goes; the entries no syslog line holds stay."""
    rows = _with_syslog(tmp_path, SSHD)
    assert [(r["source"], r["program"]) for r in rows] == \
        [("syslog", "sshd"), ("journal", ""), ("journal", "kernel")]
    assert rows[0]["file"].replace("\\", "/").endswith("var/log/messages")


def test_only_the_same_program_and_message_within_a_second_is_the_same_event(tmp_path):
    late = SSHD.replace("22:13:21", "22:13:23")                  # 3 s after the entry
    other = SSHD.replace("sshd[812]", "sshd-x[812]")             # another program
    remote = SSHD.replace("HOST-01", "HOST-02")                  # another machine's line
    rows = _with_syslog(tmp_path, late + other + remote)
    assert sum(r["source"] == "journal" and r["program"] == "sshd" for r in rows) == 1


def test_syslog_lines_before_the_journal_are_not_held(tmp_path, caplog):
    """What is held is bounded by the journal's period: a year of older lines is
    never in it, so nothing of it is left unmatched at the end."""
    old = "".join(SSHD.replace("2023-11-14T22:13:21", f"2022-11-{d:02d}T10:00:00")
                  for d in range(1, 29))
    with caplog.at_level("DEBUG", logger="t"):
        rows = _with_syslog(tmp_path, old + SSHD)
    assert sum(r["source"] == "journal" and r["program"] == "sshd" for r in rows) == 0
    assert "0 line(s) left unmatched" in caplog.text


def test_the_span_comes_from_the_entries_not_the_header(tmp_path):
    """Seen on a real host: an active journal file whose header gave one time for
    its first and last entry, the entries spread over days. A header saying the
    journal starts or ends anywhere else changes nothing."""
    for i, span in enumerate([(-60, -60), (90000, 90000), (7200, 10)]):
        rows = _with_syslog(tmp_path / str(i), SSHD.replace("22:13:21", "23:13:21"),
                            span=span, entries=[_e(3601, **SYSTEM[0][1])])
        assert [r["source"] for r in rows] == ["syslog"], span


def test_an_entry_older_than_the_first_one_widens_the_span(tmp_path):
    """Seen on a real host: the clock set back after boot, entries two hours older
    than the file's first one came later in it. The span starts at the oldest."""
    late_first = [_e(7200, **SYSTEM[1][1]), _e(1, **SYSTEM[0][1])]
    rows = _with_syslog(tmp_path, SSHD, span=None, entries=late_first)
    assert sum(r["source"] == "journal" and r["program"] == "sshd" for r in rows) == 0


def test_a_syslog_line_rsyslog_wrote_as_localhost_is_this_machine(tmp_path):
    """Seen on a real host: rsyslog wrote `localhost` on all its lines. Those stand
    for the journal's entries; another machine's name still does not."""
    rows = _with_syslog(tmp_path, SSHD.replace("HOST-01", "localhost"))
    assert [(r["source"], r["program"]) for r in rows] == \
        [("syslog", "sshd"), ("journal", ""), ("journal", "kernel")]


def test_a_journal_file_with_no_entry_bounds_nothing(tmp_path):
    """An empty journal file says nothing of the span: it does not widen what is
    held to every line."""
    assert lin_syslog._span([]) == (0, -1)
    jd = _journal_dir(tmp_path / "ev")
    (jd / "empty.journal").write_bytes(build([]))
    assert lin_syslog._span([jd / "empty.journal"]) == (0, -1)
    rows = _with_syslog(tmp_path / "x", SSHD, span=None)       # the header's 0 does not matter
    assert sum(r["program"] == "sshd" for r in rows) == 1


def test_one_syslog_line_stands_for_one_journal_entry(tmp_path):
    """Thirty identical events the journal holds, one line rsyslog kept (rate
    limiting): the other twenty-nine stay. The host matches on its first label."""
    burst = [_e(1, _HOSTNAME="host-01.example.local", SYSLOG_IDENTIFIER="sshd", _PID="9",
                MESSAGE="Accepted publickey for jdoe from 10.0.0.5 port 4242")] * 30
    rows = _with_syslog(tmp_path, SSHD, entries=burst)
    assert [r["source"] for r in rows].count("journal") == 29


def test_only_damaged_journal_files_write_nothing(tmp_path):
    jd = _journal_dir(tmp_path / "ev")
    (jd / "system.journal").write_bytes(b"\0" * 4096)
    lin_syslog.run(SimpleNamespace(evidence=tmp_path / "ev", out=tmp_path / "out", log=None))
    assert not (tmp_path / "out" / "syslog.csv").exists()


def test_no_journal_and_no_syslog_skips(tmp_path):
    ev = tmp_path / "ev"
    (ev / "[root]" / "var" / "log").mkdir(parents=True)
    with pytest.raises(HandlerSkip):
        lin_syslog.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
