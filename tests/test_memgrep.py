"""The raw-memory half of `aeng sweep` (v0.7.108). Every image is synthetic."""

import argparse
import csv
import logging

import pytest

from artifact_engine.core import memgrep as M
from artifact_engine.core import memory
from artifact_engine.core import sweep as S


def _u16(s: str) -> bytes:
    return s.encode("utf-16-le")


def _image(path, parts) -> bytes:
    data = b"".join(parts)
    path.write_bytes(data)
    return data


@pytest.mark.parametrize("chunk", [7, 16, 33, 1 << 20])
def test_every_occurrence_is_found_once_whatever_the_chunk(tmp_path, chunk):
    img = tmp_path / "x.raw"
    filler = bytes(range(0x80, 0x100)) * 3
    data = _image(img, [filler, b"evil.example.local", filler[:5], _u16("EVIL.example.local"),
                        filler[:11], b"\x00Evil.Example.Local\x00", filler])
    r = M.search(img, ["evil.example.local"], chunk=chunk)
    got = [(h.encoding, h.offset) for h in r.hits]
    assert sorted(got) == sorted([("ascii", data.index(b"evil.")),
                                  ("utf16le", data.index(_u16("EVIL"))),
                                  ("ascii", data.index(b"Evil."))])
    assert r.counts == {"evil.example.local": 3}


def test_a_value_inside_a_longer_one_is_not_a_hit(tmp_path):
    img = tmp_path / "x.raw"
    _image(img, [b"\x00\x0010.0.0.50\x00", b"\x00110.0.0.5\x00", b"\x00jdoe2\x00",
                 _u16("xjdoe"), b"\xff\xff", b"[10.0.0.5]", b"\x00", _u16("jdoe"), b"\x00\x00"])
    r = M.search(img, ["10.0.0.5", "jdoe"], chunk=8)
    assert [(h.needle, h.encoding) for h in r.hits] == [("10.0.0.5", "ascii"), ("jdoe", "utf16le")]


def test_the_context_is_readable_text(tmp_path):
    img = tmp_path / "x.raw"
    _image(img, [b"\x01" * 100, _u16(r"cmd /c whoami > C:\out.txt"), b"\x01" * 100])
    (h,) = M.search(img, ["whoami"]).hits
    assert r"cmd /c whoami > C:\out.txt" in h.context and "\x01" not in h.context


def test_a_value_seen_thousands_of_times_is_listed_up_to_the_cap_and_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "MAX_LISTED", 5)
    img = tmp_path / "x.raw"
    _image(img, [b" cdn.example.local " * 40])
    r = M.search(img, ["cdn.example.local"], chunk=64)
    assert len(r.hits) == 5 and r.counts["cdn.example.local"] == 40


def test_a_long_ioc_list_finds_what_a_short_one_does(tmp_path, monkeypatch):
    img = tmp_path / "x.raw"
    _image(img, [b"\x00abab\x00ab\xff\xff", _u16("needle-7"), b"\x00needle-71\x00"])
    needles = [f"needle-{i}" for i in range(80)] + ["ab", "abab"]
    few = M.search(img, needles, chunk=9)
    monkeypatch.setattr(M, "_FIND_LIMIT", 0)            # the alternation path
    many = M.search(img, needles, chunk=9)
    assert [(h.needle, h.offset) for h in few.hits] == [(h.needle, h.offset) for h in many.hits]
    assert {h.needle for h in many.hits} == {"ab", "abab", "needle-7", "needle-71"}
    assert sum(h.needle == "ab" for h in many.hits) == 1     # only the free-standing one


def test_overlapping_occurrences_are_each_found(tmp_path, monkeypatch):
    img = tmp_path / "x.raw"
    _image(img, [b" x-x-x "])
    monkeypatch.setattr(M, "_FIND_LIMIT", 0)
    assert [h.offset for h in M.search(img, ["x-x"]).hits] == [1, 3]


def test_an_image_that_cannot_be_read_is_an_error(tmp_path):
    r = M.search(tmp_path / "gone.raw", ["x"])
    assert r.error and not r.hits


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "MIN_IMAGE_BYTES", 1)
    (tmp_path / "HOST-01.mem").write_bytes(b"\x00" * 50 + _u16("payload.example.local") + b"\x00" * 9)
    return tmp_path


def test_the_sweep_reads_the_images_only_when_asked(case):
    assert not S.sweep(case, ["payload.example.local"]).hits
    r = S.sweep(case, ["payload.example.local", "absent.example.local"], memory=True)
    (h,) = r.hits
    assert (h.machine, h.table, h.column) == ("HOST-01_memory", "memory_image", "utf16le @0x32")
    assert r.searched == ["HOST-01_memory"] and r.images == ["HOST-01_memory"] and r.clean


def test_an_unreadable_image_is_a_machine_not_searched(case, monkeypatch):
    monkeypatch.setattr(M, "search", lambda image, needles: M.ImageResult(error="PermissionError: locked"))
    r = S.sweep(case, ["payload.example.local"], memory=True)
    assert not r.clean and r.unreadable == [("HOST-01_memory", "memory image: PermissionError: locked")]


def test_the_record_says_how_many_were_not_listed(case, tmp_path, monkeypatch):
    monkeypatch.setattr(M, "MAX_LISTED", 1)
    (case / "HOST-01.mem").write_bytes(b" beacon.example.local " * 3)
    out = tmp_path / "sweep.csv"
    with pytest.MonkeyPatch.context():
        rc = __import__("artifact_engine.cli", fromlist=["cli"]).cmd_sweep(argparse.Namespace(
            path=str(case), value=["beacon.example.local"], ioc_file=[], csv=str(out),
            verbose=False, include_collection=False, memory=True))
    assert rc == 0
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert ["hit", "beacon.example.local", "HOST-01_memory"] == rows[1][:3]
    assert rows[2][:4] == ["unlisted", "beacon.example.local", "HOST-01_memory", "memory_image"]
    assert rows[2][5].startswith("2 more")


def test_a_case_with_only_an_image_is_searched_not_refused(case, caplog):
    from artifact_engine import cli
    with caplog.at_level(logging.INFO, logger="aeng"):
        rc = cli.cmd_sweep(argparse.Namespace(
            path=str(case), value=["payload.example.local"], ioc_file=[], csv=None,
            verbose=False, include_collection=False, memory=True))
    assert rc == 0 and "1 hit(s)" in " ".join(r.message for r in caplog.records)


def test_several_processes_find_what_one_does(tmp_path):
    img = tmp_path / "x.raw"
    _image(img, [b"\x00" * 13, b"evil.example.local", b"\x00" * 7, _u16("evil.example.local")] * 5)
    one = M.search(img, ["evil.example.local"], chunk=10, workers=1)
    two = M.search(img, ["evil.example.local"], chunk=10, workers=2)
    assert one.counts == two.counts == {"evil.example.local": 10}
    assert [(h.encoding, h.offset) for h in one.hits] == [(h.encoding, h.offset) for h in two.hits]


def test_the_console_names_a_memory_value_once_not_per_offset(case, caplog, monkeypatch):
    from artifact_engine import cli
    (case / "HOST-01.mem").write_bytes(b" beacon.example.local " * 30)
    with caplog.at_level(logging.INFO, logger="aeng"):
        cli.cmd_sweep(argparse.Namespace(
            path=str(case), value=["beacon.example.local"], ioc_file=[], csv=None,
            verbose=False, include_collection=False, memory=True))
    lines = [r.message for r in caplog.records if "beacon.example.local in" in r.message]
    assert lines == ["        beacon.example.local in memory_image.ascii x30"]


def test_the_listed_hits_are_the_earliest(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "MAX_LISTED", 2)
    img = tmp_path / "x.raw"
    data = _image(img, [b"\xff\xff", _u16("jdoe"), b"\xff\xff jdoe \xff\xff", _u16("jdoe"),
                        b"\xff\xff jdoe \xff"])
    r = M.search(img, ["jdoe"])          # one range: the merge must sort
    assert [h.offset for h in r.hits] == [2, data.index(b" jdoe ") + 1]
    assert r.counts["jdoe"] == 4


def test_a_name_continued_by_an_accented_letter_is_another_name(tmp_path):
    img = tmp_path / "x.raw"
    _image(img, [b"\x00", "jdoeé".encode(), b"\x00\x00", _u16("jdoeé"), b"\x00\x00",
                 "蒃".encode("utf-16-le"), _u16("jdoe"), b"\x00\x00"])
    (h,) = M.search(img, ["jdoe"]).hits                # binary beside it is not a letter
    assert h.encoding == "utf16le"


def test_a_folded_byte_does_not_make_another_letter_match(tmp_path):
    img = tmp_path / "x.raw"
    _image(img, [b"\x00\x00", _u16("šódź"), b"\x00\x00", _u16("Łódź"), b"\x00\x00"])
    (h,) = M.search(img, ["Łódź"]).hits           # U+0141 lowered bytewise is U+0161
    assert h.offset == 2 + len(_u16("šódź")) + 2


def test_memory_asked_of_a_case_without_images_says_so(tmp_path, caplog):
    import sqlite3

    from artifact_engine import cli
    (tmp_path / "HOST-01.mem").write_bytes(b"too small to be an image")
    (tmp_path / "HOST-02").mkdir()
    with sqlite3.connect(tmp_path / "HOST-02" / "HOST-02.db") as conn:
        conn.execute("CREATE TABLE t (v TEXT)")
    conn.close()
    with caplog.at_level(logging.INFO, logger="aeng"):
        cli.cmd_sweep(argparse.Namespace(
            path=str(tmp_path), value=["x"], ioc_file=[], csv=None,
            verbose=False, include_collection=False, memory=True))
    assert "memory was NOT searched" in " ".join(r.message for r in caplog.records)


def test_the_record_says_how_many_images_were_read(case):
    r = S.sweep(case, ["absent.example.local"], memory=True)
    assert S.csv_rows(r, ["absent.example.local"])[0][5] == \
        "searched 1 machine(s), 1 memory image(s) read"
