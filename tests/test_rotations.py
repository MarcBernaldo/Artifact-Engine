"""Rotated logs: the window an artifact actually covers.

A parser that reads only the file being written now reports on the hours since
the last rotation. On a distro whose logrotate uses `dateext` -- SUSE and RHEL
both do -- that used to be every archive on the host, because the only rotation
suffix the engine recognised was Debian's `.1` / `.2.gz`. The result was not an
error anywhere: auth.csv simply started after the intrusion did.
"""
from __future__ import annotations

import gzip
import logging
import lzma
import struct
from pathlib import Path

import pytest

from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import _lincommon as L


def _ctx(evidence: Path, out: Path) -> ParserContext:
    return ParserContext(
        evidence=evidence, out=out, tools=evidence, assets=evidence,
        machine_name="host", volume="live", log=logging.getLogger("aeng.test"),
    )


def _touch(d: Path, *names: str) -> list[Path]:
    d.mkdir(parents=True, exist_ok=True)
    out = []
    for n in names:
        p = d / n
        p.write_text("", encoding="utf-8")
        out.append(p)
    return out


# --------------------------------------------------------------------------- #
# sort_rotations
# --------------------------------------------------------------------------- #
def test_dated_rotations_are_read_oldest_first_and_the_live_file_last(tmp_path):
    """The dateext failure is not a near miss like `.10` sorting between `.1` and
    `.2` -- a plain sort puts the CURRENT file FIRST, ahead of every archive, so
    the rows come out newest-then-oldest and an overlapping tail never lines up."""
    files = _touch(tmp_path, "messages", "messages-20260826.xz",
                   "messages-20260519.xz", "messages-20260731.xz")
    assert [f.name for f in L.sort_rotations(files)] == [
        "messages-20260519.xz", "messages-20260731.xz", "messages-20260826.xz",
        "messages"]


def test_numbered_rotations_still_sort_by_age_not_by_name(tmp_path):
    files = _touch(tmp_path, "auth.log", "auth.log.1", "auth.log.2.gz", "auth.log.10.gz")
    assert [f.name for f in L.sort_rotations(files)] == [
        "auth.log.10.gz", "auth.log.2.gz", "auth.log.1", "auth.log"]


def test_a_directory_with_both_conventions_still_ends_on_the_live_file(tmp_path):
    """A host whose logrotate config changed carries both. Nothing in the names
    says which era came first, so the order BETWEEN the groups is a convention --
    but the file being written now is the newest thing there under either."""
    files = _touch(tmp_path, "syslog", "syslog.1", "syslog-20260519.gz")
    ordered = [f.name for f in L.sort_rotations(files)]
    assert ordered[-1] == "syslog"
    assert set(ordered[:-1]) == {"syslog.1", "syslog-20260519.gz"}


def test_a_rotation_suffix_is_recognised_and_a_lookalike_is_not():
    assert L.is_rotation("messages-20260519.xz")
    assert L.is_rotation("auth.log.2.gz")
    assert not L.is_rotation("auth.log")
    assert not L.is_rotation("crontab")          # `cron*` also globs this
    assert not L.is_rotation("report-20260519.csv")   # dated, but not a rotation

    assert L.rotation_date("messages-20260519.xz") == "2026-05-19"
    assert L.rotation_date("auth.log.2.gz") == ""      # numbered: carries no date


# --------------------------------------------------------------------------- #
# auth
# --------------------------------------------------------------------------- #
def test_auth_reads_dated_archives_not_just_the_hours_since_the_last_rotation(tmp_path):
    """The measured cost of the old filter: on a dateext host the parser saw the
    current file and nothing else, so a case worked days after the intrusion had
    an auth.csv whose first row was later than the activity being investigated."""
    from artifact_engine.handlers import lin_auth
    log = tmp_path / "[root]" / "var" / "log"
    log.mkdir(parents=True)

    def line(month, day, src):
        return (f"2026-{month:02d}-{day:02d}T06:31:05+02:00 app01 sshd[1]: "
                f"Failed password for root from {src} port 22 ssh2\n")

    with lzma.open(log / "messages-20260519.xz", "wt", encoding="utf-8") as fh:
        fh.write(line(5, 18, "10.0.0.5"))
    with gzip.open(log / "messages-20260731.gz", "wt", encoding="utf-8") as fh:
        fh.write(line(7, 30, "10.0.0.6"))
    (log / "messages").write_text(line(8, 26, "10.0.0.7"), encoding="utf-8")

    out = tmp_path / "CSVs"
    lin_auth.run(_ctx(tmp_path, out))
    body = (out / "auth.csv").read_text(encoding="utf-8").splitlines()[1:]

    assert [r.split(",")[4] for r in body] == ["10.0.0.5", "10.0.0.6", "10.0.0.7"], \
        "the incident window lives in the archive, and it is read in time order"


def test_auth_still_prefers_the_dedicated_log_over_the_general_syslog(tmp_path):
    """Reading every rotation must not become reading every FAMILY: on RHEL/SUSE
    `messages` is the general syslog and can be gigabytes, so it is only scanned
    when there is no dedicated auth log to scan instead."""
    from artifact_engine.handlers import lin_auth
    log = tmp_path / "[root]" / "var" / "log"
    log.mkdir(parents=True)
    ok = ("2026-05-18T06:31:05+02:00 app01 sshd[1]: "
          "Failed password for root from 10.0.0.5 port 22 ssh2\n")
    (log / "secure").write_text(ok, encoding="utf-8")
    (log / "messages-20260519.xz").write_bytes(b"not even xz")

    out = tmp_path / "CSVs"
    lin_auth.run(_ctx(tmp_path, out))          # would raise if `messages` were read
    assert "10.0.0.5" in (out / "auth.csv").read_text(encoding="utf-8")


def test_a_large_archive_set_says_so_instead_of_looking_hung(tmp_path, monkeypatch, caplog):
    """Not a cap -- it still reads everything. A cap would have to guess which end
    of a year of archive the incident is in, and it would guess the recent end,
    which is the end the analyst already has."""
    from artifact_engine.handlers import lin_auth
    log = tmp_path / "[root]" / "var" / "log"
    log.mkdir(parents=True)
    (log / "auth.log").write_text(
        "2026-05-18T06:31:05+02:00 app01 sshd[1]: "
        "Failed password for root from 10.0.0.5 port 22 ssh2\n", encoding="utf-8")
    monkeypatch.setattr(lin_auth, "_LOUD_BYTES", 1)

    with caplog.at_level(logging.INFO, logger="aeng"):
        lin_auth.run(_ctx(tmp_path, tmp_path / "CSVs"))
    assert any("auth: reading" in r.message for r in caplog.records)
    assert "10.0.0.5" in (tmp_path / "CSVs" / "auth.csv").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# wtmp / btmp
# --------------------------------------------------------------------------- #
_REC = 384


def _utmp(user: str, host: str, sec: int, ut_type: int = 7) -> bytes:
    """One `struct utmp` record, x86-64 layout (the fields lin_wtmp reads)."""
    r = bytearray(_REC)
    struct.pack_into("<i", r, 0, ut_type)
    r[8:8 + 5] = b"pts/0"
    r[44:44 + len(user)] = user.encode()
    r[76:76 + len(host)] = host.encode()
    struct.pack_into("<i", r, 340, sec)
    return bytes(r)


def test_btmp_rotations_are_read_because_btmp_is_the_brute_force_artifact(tmp_path):
    """btmp is what the lateral graph builds `brute_success` out of. Reading only
    the live file means a spray from three weeks ago never reaches the graph, and
    the graph's silence then reads as "no brute force against this host"."""
    from artifact_engine.handlers import lin_btmp
    log = tmp_path / "[root]" / "var" / "log"
    log.mkdir(parents=True)
    (log / "btmp-20260519").write_bytes(_utmp("root", "10.0.0.5", 1_747_000_000))
    (log / "btmp").write_bytes(_utmp("admin", "10.0.0.7", 1_756_000_000))

    out = tmp_path / "CSVs"
    lin_btmp.run(_ctx(tmp_path, out))
    body = (out / "btmp.csv").read_text(encoding="utf-8").splitlines()[1:]
    assert [r.split(",")[1] for r in body] == ["root", "admin"]   # oldest first


def test_a_compressed_utmp_rotation_is_decompressed_not_read_as_records(tmp_path):
    """The trap the glob opens: a compressed archive read as raw bytes does not
    fail, it yields records made of gzip's output. Garbage rows in a login
    history are worse than a missing file -- nothing downstream can tell."""
    from artifact_engine.handlers import lin_wtmp
    log = tmp_path / "[root]" / "var" / "log"
    log.mkdir(parents=True)
    with gzip.open(log / "wtmp-20260519.gz", "wb") as fh:
        fh.write(_utmp("jdoe", "10.0.0.5", 1_747_000_000))
    (log / "wtmp").write_bytes(_utmp("root", "10.0.0.7", 1_756_000_000))

    out = tmp_path / "CSVs"
    lin_wtmp.run(_ctx(tmp_path, out))
    body = (out / "wtmp.csv").read_text(encoding="utf-8").splitlines()[1:]
    assert [r.split(",")[1] for r in body] == ["jdoe", "root"]


def test_a_record_split_across_two_reads_is_carried_not_dropped(tmp_path, monkeypatch):
    """A decompressed stream hands back whatever it has, not whole records. The
    old chunk loop dropped the tail of each read, which on a raw file never
    happened and on a compressed one would misalign everything after it."""
    from artifact_engine.handlers import lin_wtmp
    log = tmp_path / "[root]" / "var" / "log"
    log.mkdir(parents=True)
    users = [f"user{i}" for i in range(6)]
    (log / "wtmp").write_bytes(
        b"".join(_utmp(u, "10.0.0.5", 1_756_000_000 + i) for i, u in enumerate(users)))
    monkeypatch.setattr(lin_wtmp, "_CHUNK", 100)      # deliberately not a multiple of 384

    out = tmp_path / "CSVs"
    lin_wtmp.run(_ctx(tmp_path, out))
    body = (out / "wtmp.csv").read_text(encoding="utf-8").splitlines()[1:]
    assert [r.split(",")[1] for r in body] == users


# --------------------------------------------------------------------------- #
# log_integrity
# --------------------------------------------------------------------------- #
@pytest.fixture
def integrity_case(tmp_path) -> Path:
    log = tmp_path / "[root]" / "var" / "log"
    log.mkdir(parents=True)
    (log / "auth.log").write_text("May 18 06:31:05 app01 sshd[1]: x\n", encoding="utf-8")
    (log / "auth.log-20260519").write_text("", encoding="utf-8")       # wiped archive
    with gzip.open(log / "auth.log-20260731.gz", "wt", encoding="utf-8") as fh:
        fh.write("May 18 06:31:05 app01 sshd[1]: x\n")
    (log / "wtmp").write_bytes(b"\x00" * _REC)
    (log / "wtmp-20260519").write_bytes(b"\x00" * 100)                 # torn archive
    return tmp_path


def test_how_far_back_the_host_logs_is_reported(integrity_case):
    """The row that decides how a quiet log is read. A host holding a day and a
    host holding a year both produce an auth.csv, and only one of them has
    anything to say about an intrusion from last month."""
    from artifact_engine.handlers import lin_log_integrity
    out = integrity_case / "CSVs"
    lin_log_integrity.run(_ctx(integrity_case, out))
    text = (out / "log_integrity.csv").read_text(encoding="utf-8")
    assert "auth.log,rotations,\"2 archive(s), 2026-05-19 .. 2026-07-31\"," in text


def test_a_wiped_or_torn_archive_is_flagged_the_same_as_a_live_one(integrity_case):
    from artifact_engine.handlers import lin_log_integrity
    out = integrity_case / "CSVs"
    lin_log_integrity.run(_ctx(integrity_case, out))
    text = (out / "log_integrity.csv").read_text(encoding="utf-8")
    assert "auth.log-20260519,empty,0 bytes,yes" in text
    assert "wtmp-20260519,truncated,100 bytes (not a multiple of 384),yes" in text


def test_a_healthy_archive_does_not_add_a_row_per_rotation(integrity_case):
    """A host with a year of rotations must add ONE row here, not three hundred:
    a coverage line that is buried is a coverage line nobody reads."""
    from artifact_engine.handlers import lin_log_integrity
    out = integrity_case / "CSVs"
    lin_log_integrity.run(_ctx(integrity_case, out))
    lines = (out / "log_integrity.csv").read_text(encoding="utf-8").splitlines()
    # Not vacuous: the archives WERE looked at (the coverage row proves it), and
    # the healthy one still says nothing.
    assert any(",rotations," in line for line in lines)
    assert not any(line.startswith("auth.log-20260731") for line in lines), \
        "a compressed archive has no meaningful size, and a healthy one has no news"
