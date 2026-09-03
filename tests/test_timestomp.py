"""Timestamps that contradict each other, and the crowd that explains most of them.

Both handlers face the same trap from opposite directions: the naive rule
(ctime long after mtime, or $SI older than $FN) is true of a large share of a
healthy machine, because that is exactly what installing a package or copying a
file does. A detector that reports it is a detector nobody reads.

These tests pin what each handler does INSTEAD -- Windows requires the forged
timestamp to buy something, Linux requires the file to be alone in its crowd --
and pin the two ways that could quietly go wrong: an install burying a real drop
that happened the same afternoon, and a bounded table that stops without saying
it stopped.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import lin_timestomp as L
from artifact_engine.handlers import win_timestomp as W
from artifact_engine.handlers._topn import TopN


class _Ctx:
    def __init__(self, evidence: Path, out: Path):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "C"
        self.log = None


def _out(tmp_path: Path) -> list[dict]:
    p = tmp_path / "out" / "timestomp.csv"
    if not p.is_file():
        return []
    with p.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# Windows: $MFT
# --------------------------------------------------------------------------- #
_MFT_COLS = ["ParentPath", "FileName", "Extension", "FileSize", "IsDirectory",
             "SI<FN", "uSecZeros", "Copied", "Created0x10", "Created0x30",
             "LastModified0x10", "LastRecordChange0x10"]


def _mft(tmp_path: Path, rows: list[dict]) -> None:
    d = tmp_path / "CSVs" / "Filesystem"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "MFT.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_MFT_COLS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in _MFT_COLS})


def _entry(parent: str, name: str, **kw) -> dict:
    base = {"ParentPath": parent, "FileName": name,
            "Extension": Path(name).suffix, "FileSize": "1024",
            "IsDirectory": "False", "SI<FN": "False", "uSecZeros": "False",
            "Copied": "False",
            "Created0x10": "2020-01-01 00:00:00.0000000",
            "Created0x30": "2020-01-01 00:00:00.0000000",
            "LastModified0x10": "2020-01-01 00:00:00.0000000",
            "LastRecordChange0x10": "2020-01-01 00:00:00.0000000"}
    base.update(kw)
    return base


def _win(tmp_path: Path, rows: list[dict]) -> list[dict]:
    _mft(tmp_path, rows)
    W.run(_Ctx(tmp_path, tmp_path / "out"))
    return _out(tmp_path)


def test_a_stomped_binary_in_a_writable_directory_is_flagged(tmp_path):
    rows = _win(tmp_path, [
        _entry(".\\Windows\\Temp", "svchost.exe", **{"SI<FN": "True"}),
    ])
    assert len(rows) == 1
    assert rows[0]["suspicious"] == "yes"
    assert rows[0]["location"] == "writable"
    assert "si_before_fn" in rows[0]["indicators"]


def test_the_same_shape_in_a_system_directory_is_reported_but_not_flagged(tmp_path):
    """An installer that copies files preserving their times produces SI<FN by
    the thousand. WinSxS is full of them, and flagging those makes the column
    useless rather than valuable."""
    rows = _win(tmp_path, [
        _entry(".\\Windows\\WinSxS\\amd64_x", "comctl32.dll", **{"SI<FN": "True"}),
    ])
    assert len(rows) == 1
    assert rows[0]["suspicious"] == "" and rows[0]["location"] == "system"


def test_a_file_with_no_contradiction_is_not_reported_at_all(tmp_path):
    assert _win(tmp_path, [_entry(".\\Windows\\Temp", "clean.exe")]) == []


def test_a_document_in_a_writable_directory_with_no_indicator_is_not_reported(tmp_path):
    assert _win(tmp_path, [_entry(".\\Users\\jdoe\\Downloads", "notes.txt")]) == []


def test_a_data_file_in_a_system_directory_is_not_reported_on_windows(tmp_path):
    """SI<FN on a system .txt is an installer's copy. Emitting it turns the table
    into a census of the volume, which is how a good column stays unread."""
    assert _win(tmp_path, [
        _entry(r".\Windows\System32\drivers\etc", "hosts.txt",
               **{"SI<FN": "True"}),
    ]) == []


def test_a_multi_year_delta_is_a_finding_on_its_own(tmp_path):
    rows = _win(tmp_path, [
        _entry(".\\Users\\jdoe\\Downloads", "update.exe",
               LastModified0x10="2016-02-03 10:00:00.0000000",
               LastRecordChange0x10="2026-05-19 11:22:33.0000000"),
    ])
    assert rows[0]["suspicious"] == "yes"
    assert int(rows[0]["delta_days"]) > 3000


def test_directories_are_not_files_that_were_stomped(tmp_path):
    assert _win(tmp_path, [
        _entry(".\\Windows\\Temp", "staging", Extension="", IsDirectory="True",
               **{"SI<FN": "True"}),
    ]) == []


def test_no_mft_csv_skips_rather_than_writing_an_empty_table(tmp_path):
    with pytest.raises(HandlerSkip):
        W.run(_Ctx(tmp_path, tmp_path / "out"))


# --------------------------------------------------------------------------- #
# Linux: bodyfile
# --------------------------------------------------------------------------- #
_BODY_COLS = ["name", "inode", "mode", "uid", "gid", "size",
              "atime_utc", "mtime_utc", "ctime_utc", "crtime_utc"]


def _body(tmp_path: Path, rows: list[dict]) -> None:
    d = tmp_path / "CSVs" / "Filesystem"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "bodyfile.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_BODY_COLS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in _BODY_COLS})


def _inode(name: str, mtime: str, ctime: str, mode: str = "-/-rwxr-xr-x",
           crtime: str = "") -> dict:
    return {"name": name, "inode": "1", "mode": mode, "uid": "0", "gid": "0",
            "size": "1024", "atime_utc": mtime, "mtime_utc": mtime,
            "ctime_utc": ctime, "crtime_utc": crtime}


def _lin(tmp_path: Path, rows: list[dict]) -> list[dict]:
    _body(tmp_path, rows)
    L.run(_Ctx(tmp_path, tmp_path / "out"))
    return _out(tmp_path)


def test_touch_r_leaves_the_ctime_behind_and_that_is_the_finding(tmp_path):
    rows = _lin(tmp_path, [
        _inode("/tmp/.x/run", "2019-03-01 09:00:00", "2026-05-19 11:22:33"),
    ])
    assert len(rows) == 1
    assert rows[0]["suspicious"] == "yes" and int(rows[0]["delta_days"]) > 2500


def test_a_package_install_is_a_crowd_and_is_not_flagged(tmp_path):
    """dpkg and rpm restore the mtime the package was built with, so every file
    they write has this exact shape. Two hundred of them in one day under /usr is
    an install, and calling it tampering would bury the one that is not."""
    crowd = [_inode(f"/usr/bin/tool{i}", "2019-03-01 09:00:00", "2026-05-19 11:22:33")
             for i in range(250)]
    rows = _lin(tmp_path, crowd)
    assert rows and all(r["suspicious"] == "" for r in rows)
    assert "install or an unpack" in rows[0]["note"]


def test_a_drop_on_the_same_afternoon_as_an_install_is_still_flagged(tmp_path):
    """The crowd is counted per (day, top-level directory), not per day. An
    unattended-upgrades timer running the same afternoon must not bury a drop --
    and an attacker does not have to arrange that coincidence."""
    rows = _lin(tmp_path, [
        *[_inode(f"/usr/bin/tool{i}", "2019-03-01 09:00:00", "2026-05-19 11:22:33")
          for i in range(250)],
        _inode("/tmp/.x/run", "2019-03-01 09:00:00", "2026-05-19 14:00:00"),
    ])
    dropped = [r for r in rows if r["path"] == "/tmp/.x/run"]
    assert dropped and dropped[0]["suspicious"] == "yes"


def test_a_file_modified_before_it_was_born_is_flagged(tmp_path):
    rows = _lin(tmp_path, [
        _inode("/home/jdoe/.cache/x", "2019-03-01 09:00:00", "2026-05-19 11:22:33",
               crtime="2026-05-19 11:22:33"),
    ])
    assert rows[0]["suspicious"] == "yes"
    assert "mtime_before_birth" in rows[0]["indicators"]


def test_a_data_file_in_a_system_directory_is_not_reported(tmp_path):
    """Not writable, not executable: a forged timestamp there buys nothing, and
    /usr/share is where the install crowd lives."""
    assert _lin(tmp_path, [
        _inode("/usr/share/doc/x/README", "2019-03-01 09:00:00",
               "2026-05-19 11:22:33", mode="-/-rw-r--r--"),
    ]) == []


def test_a_directory_is_not_an_executable(tmp_path):
    assert _lin(tmp_path, [
        _inode("/usr/lib/x", "2019-03-01 09:00:00", "2026-05-19 11:22:33",
               mode="d/drwxr-xr-x"),
    ]) == []


def test_no_bodyfile_skips_rather_than_writing_an_empty_table(tmp_path):
    with pytest.raises(HandlerSkip):
        L.run(_Ctx(tmp_path, tmp_path / "out"))


# --------------------------------------------------------------------------- #
# The bound, and what it admits
# --------------------------------------------------------------------------- #
def test_the_table_says_how_many_rows_it_did_not_write(tmp_path, monkeypatch):
    """A table that stops at its cap without saying so reads as a machine with
    exactly that many matches -- the same mistake as a truncated archive reading
    as a quiet host."""
    monkeypatch.setattr(L, "_CAP", 3)
    rows = _lin(tmp_path, [
        _inode(f"/tmp/x{i}", "2019-03-01 09:00:00", f"2026-05-{10 + i:02d} 11:00:00")
        for i in range(10)
    ])
    cap = [r for r in rows if r["indicators"] == "cap"]
    assert len(rows) == 4 and cap
    assert "10 file(s) matched" in cap[0]["note"]


def test_the_bound_keeps_the_best_rows_not_the_first_ones(tmp_path):
    """The interesting row is whichever has the largest disagreement, and nothing
    says it arrives early in a multi-million-row scan."""
    top = TopN(2)
    for i in range(100):
        top.add((0, -i), f"row-{i}")
    assert top.best() == ["row-99", "row-98"]
    assert top.total == 100 and top.dropped == 98
