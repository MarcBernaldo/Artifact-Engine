"""tests/museum_layout.py puts museum samples where a KAPE collection has them."""

from pathlib import Path

import museum_layout as M  # tests/ is on the path: no package, pytest's rootdir


def _touch(root: Path, rel: str, data: bytes = b"x") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def test_samples_land_where_a_collector_puts_them(tmp_path):
    src, case = tmp_path / "src", tmp_path / "case"
    _touch(src, "Windows/Registry/Win10/HOST01/SYSTEM")
    _touch(src, "Windows/Registry/Win10/HOST01/SYSTEM.LOG1")
    _touch(src, "Windows/Registry/Win10/HOST01/jdoe/NTUSER.DAT")
    _touch(src, "Windows/Prefetch/Win10/HOST01/CMD.EXE-0BD30981.pf")
    _touch(src, "Windows/NTFSArtifacts/MFT/Win10/HOST01/$MFT")
    _touch(src, "Windows/SRUM/Win10/HOST01/HOST01_SRUM.7z")
    _touch(src, "Windows/SRUM/Win10/HOST01/README.md")
    placed = M.lay_out(src, tmp_path / "none", case)
    vol = case / "HOST01-Win10_kape" / "C"
    assert placed == {"HOST01-Win10_kape": 5}
    for rel in ("Windows/System32/config/SYSTEM", "Windows/System32/config/SYSTEM.LOG1",
                "Users/jdoe/NTUSER.DAT", "Windows/prefetch/CMD.EXE-0BD30981.pf", "$MFT"):
        assert (vol / rel).is_file(), rel
    assert not list((vol / "Windows/System32").glob("sru/*"))   # archives and notes stay


def test_the_dirty_and_the_later_snapshot_win_whole(tmp_path):
    src, work, case = tmp_path / "src", tmp_path / "work", tmp_path / "case"
    base = "Windows/SRUM/Win10/HOST01"
    _touch(work, f"{base}/A/Clean/SRUDB.dat", b"clean")
    _touch(work, f"{base}/A/Clean/SRU00001.log", b"clean")
    _touch(work, f"{base}/A/Dirty/SRUDB.dat", b"dirty")
    _touch(work, f"{base}/Snap/SRU/SRUDB.dat", b"early")
    _touch(work, f"{base}/Snap/SRU/SRU00009.log", b"early")
    _touch(work, f"{base}/Snap_1DayLater/SRU/SRUDB.dat", b"later")
    M.lay_out(src, work, case)
    sru = case / "HOST01-Win10_kape" / "C" / "Windows/System32/sru"
    # one copy of the database, and no log from a snapshot it did not come from
    assert (sru / "SRUDB.dat").read_bytes() in (b"dirty", b"later")
    assert sorted(p.name for p in sru.iterdir()) == ["SRUDB.dat"]


def test_a_clean_copy_alone_is_kept(tmp_path):
    work, case = tmp_path / "work", tmp_path / "case"
    _touch(work, "Windows/SRUM/Win10/HOST01/Clean/SRUDB.dat", b"clean")
    M.lay_out(tmp_path / "src", work, case)
    assert (case / "HOST01-Win10_kape/C/Windows/System32/sru/SRUDB.dat").read_bytes() == b"clean"
