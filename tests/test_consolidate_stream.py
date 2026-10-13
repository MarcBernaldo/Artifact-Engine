"""v0.7.127: a big CSV reaches the .db in slices, and the table is the one a
whole read gives -- same columns, rows, values and SQLite storage classes."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from artifact_engine.core import consolidate as C


def _dump(conn: sqlite3.Connection, name: str):
    cols = [c[1] for c in conn.execute(f"PRAGMA table_info({C._q(name)})")]
    decl = conn.execute(f"PRAGMA table_info({C._q(name)})").fetchall()
    sel = ", ".join(f"{C._q(c)}, typeof({C._q(c)})" for c in cols)
    return decl, conn.execute(f"SELECT {sel} FROM {C._q(name)}").fetchall()


def _both(tmp_path: Path, text: str):
    src = tmp_path / "artifact.csv"
    src.write_text(text, encoding="utf-8")
    whole = sqlite3.connect(":memory:")
    wrote, _ = C._to_db(whole, "t", C._read_csv(src))
    assert wrote
    sliced = sqlite3.connect(":memory:")
    assert C._stream_to_db(sliced, "t", src) is not None
    return _dump(whole, "t"), _dump(sliced, "t")


@pytest.fixture(autouse=True)
def _tiny_slices(monkeypatch):
    monkeypatch.setattr(C, "_STREAM_ROWS", 2)      # every boundary is exercised
    monkeypatch.setattr(C, "_STREAM_BYTES", 0)


def test_a_column_digits_first_and_text_later_keeps_its_leading_zeros(tmp_path):
    """Each slice deciding for itself, the first declares the column INTEGER and
    SQLite stores a later `0001` as 1."""
    whole, sliced = _both(tmp_path, "id,name\n1,a\n2,b\n0001,c\nX-9,d\n")
    assert sliced == whole
    assert ("0001", "text") in [(r[0], r[1]) for r in sliced[1]]


def test_ints_with_a_blank_further_down_are_floats_as_whole(tmp_path):
    whole, sliced = _both(tmp_path, "size,n\n1,a\n2,b\n,c\n4,d\n")
    assert sliced == whole


def test_true_false_with_an_empty_slice_are_stored_as_whole(tmp_path):
    whole, sliced = _both(tmp_path, "InUse,n\nTrue,a\nFalse,b\n,c\n,d\nTrue,e\n")
    assert sliced == whole


def test_a_number_past_int64_keeps_the_whole_table_as_text(tmp_path):
    whole, sliced = _both(tmp_path, "FileId,n\n1,a\n2,b\n18446744073709551615,c\n")
    assert sliced == whole
    assert all(r[1] == "text" for r in sliced[1])


def test_build_streams_a_big_csv_into_the_db(tmp_path):
    from artifact_engine.core.detector import Machine

    host = tmp_path / "HOST-01"
    (host / "CSVs" / "Filesystem").mkdir(parents=True)
    (host / "CSVs" / "Filesystem" / "MFT.csv").write_text(
        "EntryNumber,FileName,InUse\n" + "".join(f"{i},f{i:04d},True\n" for i in range(9)),
        encoding="utf-8")
    m = Machine(name="HOST-01", os="windows", collector="kape", profile_id="windows_kape",
                path=host)
    assert C.build(m, emit_xlsx=False) == []
    conn = sqlite3.connect(host / "HOST-01.db")
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    assert len(tables) == 1
    rows = conn.execute(f"SELECT * FROM {C._q(tables[0])}").fetchall()
    conn.close()
    assert rows == [(i, f"f{i:04d}", 1) for i in range(9)]


# Found by review: combinations whose whole-file answer depends on the values,
# not on the kinds the slices inferred. Each must still equal the whole read.
def test_a_negative_next_to_a_value_past_int64_is_read_as_whole(tmp_path):
    whole, sliced = _both(tmp_path, "Id,n\n-1,a\n-2,b\n18446744073709551615,c\n")
    assert sliced == whole


def test_a_value_past_int64_next_to_a_blank_is_read_as_whole(tmp_path):
    whole, sliced = _both(tmp_path, "Id,n\n18446744073709551615,a\n3,b\n,c\n")
    assert sliced == whole


def test_booleans_next_to_numbers_are_read_as_whole(tmp_path):
    whole, sliced = _both(tmp_path, "Flag,n\nTrue,a\nFalse,b\n1.5,c\n")
    assert sliced == whole


def test_booleans_with_blanks_inside_a_slice_stay_integers(tmp_path):
    """A slice holding True and a blank infers object; taken for text, the .db
    would hold 'True' where a whole read stores 1."""
    whole, sliced = _both(tmp_path, "x,n\nTrue,a\n,b\nFalse,c\nTrue,d\n")
    assert sliced == whole
    assert (1, "integer") in [(r[0], r[1]) for r in sliced[1]]


def test_booleans_with_blanks_next_to_text_are_text_as_whole(tmp_path):
    whole, sliced = _both(tmp_path, "x,n\nTrue,a\n,b\nmaybe,c\nFalse,d\n")
    assert sliced == whole
