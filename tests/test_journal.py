"""v0.7.138: the systemd journal reader and the auth/cron_log fallback to it.
Journal files are built here byte by byte; hosts, users and addresses are invented."""
from __future__ import annotations

import csv
import logging
import lzma
import mmap
import struct
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_engine.handlers import _journal, lin_auth, lin_cron_log

T0 = 1_700_000_000_000_000          # 2023-11-14 22:13:20 UTC, in microseconds


def _pad(b: bytes) -> bytes:
    return b + b"\0" * (-len(b) % 8)


def build(entries, compact: bool = False, xz: frozenset = frozenset()) -> bytes:
    """A journal file holding `entries` [(realtime_us, {field: value})]. Each
    distinct FIELD=value is one DATA object listing its entries: the first in
    `entry_offset`, the rest in a chain of three-slot ENTRY_ARRAYs that hold one
    entry each (two in the last), unused slots zero -- so the chain is walked
    past empty slots to its end. A payload
    whose field is in `xz` is stored XZ-compressed."""
    header_size = 256
    dpay = 72 if compact else 64
    payloads: dict[bytes, list[int]] = {}
    for i, (_, fields) in enumerate(entries):
        for k, v in fields.items():
            payloads.setdefault(f"{k}={v}".encode(), []).append(i)

    def stored(p: bytes) -> tuple[int, bytes]:
        return (1, lzma.compress(p)) if p.split(b"=")[0].decode() in xz else (0, p)

    off = header_size
    data_off = {}
    for p in payloads:
        data_off[p] = off
        off += len(_pad(b"\0" * (dpay + len(stored(p)[1]))))
    item = 4 if compact else 16
    entry_off = []
    for _, fields in entries:
        entry_off.append(off)
        off += len(_pad(b"\0" * (64 + item * len(fields))))       # objects are 8-aligned
    slot = 4 if compact else 8
    arrays: dict[bytes, list[tuple[int, list[int]]]] = {}
    for p, idx in payloads.items():
        rest = [entry_off[i] for i in idx[1:]]
        chunks = [rest[i:i + 1] for i in range(len(rest) - 2)] + ([rest[-2:]] if len(rest) >= 2 else
                                                                  [rest] if rest else [])
        arrays[p] = []
        for c in chunks:
            arrays[p].append((off, c))
            off += len(_pad(b"\0" * (24 + slot * 3)))
    tail = off

    out = bytearray(off)
    out[0:8] = b"LPKSHHRH"
    struct.pack_into("<I", out, 12, 16 if compact else 0)
    struct.pack_into("<Q", out, 88, header_size)
    struct.pack_into("<Q", out, 136, tail)
    for p, at in data_off.items():
        flags, body = stored(p)
        size = dpay + len(body)
        out[at], out[at + 1] = 1, flags
        struct.pack_into("<Q", out, at + 8, size)
        chain = arrays[p]
        struct.pack_into("<QQQ", out, at + 40, entry_off[payloads[p][0]],
                         chain[0][0] if chain else 0, len(payloads[p]))
        out[at + dpay: at + size] = body
        for n, (a_at, items) in enumerate(chain):
            out[a_at] = 6
            struct.pack_into("<Q", out, a_at + 8, 24 + slot * 3)
            struct.pack_into("<Q", out, a_at + 16, chain[n + 1][0] if n + 1 < len(chain) else 0)
            for j, e in enumerate(items):
                struct.pack_into("<I" if compact else "<Q", out, a_at + 24 + j * slot, e)
    for (rt, fields), at in zip(entries, entry_off):
        out[at] = 3
        struct.pack_into("<Q", out, at + 8, 64 + item * len(fields))
        struct.pack_into("<QQ", out, at + 16, 1, rt)
        for j, (k, v) in enumerate(fields.items()):
            d = data_off[f"{k}={v}".encode()]
            struct.pack_into("<I" if compact else "<Q", out, at + 64 + j * item, d)
    return bytes(out)


def _e(sec: int, ident: str, msg: str, host: str = "HOST-01", pid: str = "42") -> tuple:
    return T0 + sec * 1_000_000, {"_HOSTNAME": host, "SYSLOG_IDENTIFIER": ident,
                                  "_PID": pid, "MESSAGE": msg}


SSH_OK = "Accepted publickey for jdoe from 10.0.0.5 port 50022 ssh2"
ENTRIES = [
    _e(0, "sshd", SSH_OK),
    _e(1, "systemd", "Started Session 1 of User jdoe."),
    _e(2, "sshd", "Failed password for root from 10.0.0.6 port 4000 ssh2"),
    _e(3, "sudo", "jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/bin/id"),
    _e(4, "CRON", "(root) CMD (/tmp/.x/run.sh)"),
    _e(5, "sshd", "Invalid user admin from 10.0.0.7 port 4001"),
    _e(6, "sshd", "Invalid user test from 10.0.0.8 port 4002"),
    _e(7, "crontab", "(jdoe) REPLACE (jdoe)"),
]


def _host(tmp_path: Path, files: dict[str, bytes], text: dict[str, str] | None = None) -> Path:
    ev = tmp_path / "ev"
    jd = ev / "[root]" / "var" / "log" / "journal" / "0123456789abcdef"
    jd.mkdir(parents=True)
    for name, data in files.items():
        (jd / name).write_bytes(data)
    for name, body in (text or {}).items():
        (ev / "[root]" / "var" / "log" / name).write_text(body, encoding="utf-8")
    return ev


def _run(handler, ev: Path, tmp_path: Path, name: str) -> list[dict]:
    ctx = SimpleNamespace(evidence=ev, out=tmp_path / "out", log=logging.getLogger("t"))
    handler.run(ctx)
    f = tmp_path / "out" / name
    if not f.exists():
        return []
    with open(f, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


@pytest.mark.parametrize("compact", [False, True])
def test_lines_of_the_wanted_programs_only_in_time_order(tmp_path, compact):
    root = _host(tmp_path, {"system.journal": build(ENTRIES, compact)}) / "[root]"
    st: Counter = Counter()
    lines = list(_journal.syslog_lines(root, lambda i: i == "sshd", st))
    assert lines == [
        f"2023-11-14T22:13:20.000000+00:00 HOST-01 sshd[42]: {SSH_OK}",
        "2023-11-14T22:13:22.000000+00:00 HOST-01 sshd[42]: Failed password for root from 10.0.0.6 port 4000 ssh2",
        "2023-11-14T22:13:25.000000+00:00 HOST-01 sshd[42]: Invalid user admin from 10.0.0.7 port 4001",
        "2023-11-14T22:13:26.000000+00:00 HOST-01 sshd[42]: Invalid user test from 10.0.0.8 port 4002",
    ]
    assert st["files"] == 1 and st["entries"] == 4


def test_files_are_merged_by_time_and_non_journals_ignored(tmp_path):
    a = build([_e(0, "sshd", "Invalid user a from 10.0.0.1 port 1"),
               _e(9, "sshd", "Invalid user c from 10.0.0.3 port 3")])
    b = build([_e(5, "sshd", "Invalid user b from 10.0.0.2 port 2")], compact=True)
    root = _host(tmp_path, {"system@x.journal": a, "user-1000.journal": b,
                            "broken.journal~": b"not a journal", "empty.journal": b""}) / "[root]"
    st: Counter = Counter()
    users = [ln.split("Invalid user ")[1][0] for ln in _journal.syslog_lines(root, {"sshd"}.__contains__, st)]
    assert users == ["a", "b", "c"]
    assert st["files"] == 2 and st["not_journal"] == 1 and st["unreadable"] == 1


def test_an_xz_compressed_message_is_decoded(tmp_path):
    root = _host(tmp_path, {"s.journal": build(ENTRIES[:1], xz=frozenset({"MESSAGE"}))}) / "[root]"
    assert list(_journal.syslog_lines(root, {"sshd"}.__contains__))[0].endswith(SSH_OK)


def test_an_identifier_quoted_inside_a_message_is_not_a_program(tmp_path):
    ent = [_e(0, "logger", "SYSLOG_IDENTIFIER=sshd Invalid user x from 10.0.0.9 port 1")]
    root = _host(tmp_path, {"s.journal": build(ent)}) / "[root]"
    assert list(_journal.syslog_lines(root, {"sshd"}.__contains__)) == []


def test_a_quoted_identifier_behind_bytes_that_look_like_an_object_is_not_one(tmp_path):
    # the 64 bytes before the quoted identifier start like an object header (an
    # ENTRY, size exactly up to the identifier's end): only a DATA object counts
    forged = "\x03" + "\x00" * 7 + "V" + "\x00" * 7 + "." * 48     # size 0x56 = 64 + 22
    ent = [_e(0, "logger", forged + "SYSLOG_IDENTIFIER=sshd")]
    data = build(ent)
    with_forgery = data.index(b"SYSLOG_IDENTIFIER=sshd", data.index(b"MESSAGE="))
    assert (with_forgery - 64) % 8 == 0 and data[with_forgery - 64] == 3
    path = tmp_path / "s.journal"
    path.write_bytes(data)
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        assert set(_journal._File(mm).identifiers()) == {"logger"}


def test_auth_reads_the_journal_when_the_host_has_no_text_family(tmp_path):
    ev = _host(tmp_path, {"system.journal": build(ENTRIES)})
    rows = _run(lin_auth, ev, tmp_path, "auth_log.csv")
    assert [(r["timestamp"], r["host"], r["event"], r["user"], r["source"]) for r in rows] == [
        ("2023-11-14T22:13:20.000000+00:00", "HOST-01", "ssh_accepted", "jdoe", "10.0.0.5"),
        ("2023-11-14T22:13:22.000000+00:00", "HOST-01", "ssh_failed", "root", "10.0.0.6"),
        ("2023-11-14T22:13:23.000000+00:00", "HOST-01", "sudo", "jdoe", ""),
        ("2023-11-14T22:13:25.000000+00:00", "HOST-01", "ssh_invalid_user", "admin", "10.0.0.7"),
        ("2023-11-14T22:13:26.000000+00:00", "HOST-01", "ssh_invalid_user", "test", "10.0.0.8"),
    ]


def test_auth_never_reads_the_journal_beside_a_text_family(tmp_path):
    text = {"auth.log": f"Nov 14 22:13:20 HOST-01 sshd[7]: {SSH_OK}\n"}
    ev = _host(tmp_path, {"system.journal": build(ENTRIES)}, text)
    rows = _run(lin_auth, ev, tmp_path, "auth_log.csv")
    assert [(r["timestamp"], r["event"]) for r in rows] == [("Nov 14 22:13:20", "ssh_accepted")]


def test_sshd_session_is_read_as_sshd(tmp_path):
    ev = _host(tmp_path, {"system.journal": build([_e(0, "sshd-session", SSH_OK)])})
    assert [r["event"] for r in _run(lin_auth, ev, tmp_path, "auth_log.csv")] == ["ssh_accepted"]


def test_cron_log_reads_the_journal_when_there_is_no_cron_or_syslog(tmp_path):
    ev = _host(tmp_path, {"system.journal": build(ENTRIES, compact=True)})
    rows = _run(lin_cron_log, ev, tmp_path, "cron_log.csv")
    assert [(r["timestamp"], r["kind"], r["user"], r["detail"], r["suspicious"]) for r in rows] == [
        ("2023-11-14T22:13:24.000000+00:00", "exec", "root", "/tmp/.x/run.sh", "yes"),
        ("2023-11-14T22:13:27.000000+00:00", "crontab_replace", "jdoe", "jdoe", ""),
    ]


def test_cron_log_never_reads_the_journal_beside_syslog(tmp_path):
    text = {"syslog": "Nov 14 22:13:24 HOST-01 CRON[9]: (root) CMD (/usr/bin/true)\n"}
    ev = _host(tmp_path, {"system.journal": build(ENTRIES)}, text)
    rows = _run(lin_cron_log, ev, tmp_path, "cron_log.csv")
    assert [r["detail"] for r in rows] == ["/usr/bin/true"]


def test_no_journal_and_no_logs_writes_nothing(tmp_path):
    ev = tmp_path / "ev"
    (ev / "[root]" / "var" / "log").mkdir(parents=True)
    assert _run(lin_auth, ev, tmp_path, "auth_log.csv") == []
    assert _run(lin_cron_log, ev, tmp_path, "cron_log.csv") == []
