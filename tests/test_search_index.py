"""art_search_index: SIDR on the evidence first; a repaired temp copy only when it fails."""

import logging
import subprocess
from pathlib import Path

import pytest

from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import win_search_index as H

_DB = "ProgramData/Microsoft/Search/Data/Applications/Windows"


@pytest.fixture
def case(tmp_path, monkeypatch):
    """A volume with a Windows.edb, and a fake SIDR that reads it only once it is
    repaired. Returns (ctx, evidence db dir, calls as (argv, cwd))."""
    db = tmp_path / "C" / _DB
    db.mkdir(parents=True)
    (db / "Windows.edb").write_bytes(b"torn")
    (db / "MSS.log").write_bytes(b"log")
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "sidr.exe").write_bytes(b"")
    calls: list[tuple[list[str], str | None]] = []
    repaired: set[Path] = set()

    def fake_run(argv, timeout=None, cwd=None):
        calls.append((list(argv), cwd))
        if "/p" in argv:
            repaired.add(Path(argv[argv.index("/p") + 1]).parent)
            return 0, "", ""
        if argv[0].endswith("sidr.exe"):
            out, where = Path(argv[argv.index("-o") + 1]), Path(argv[-1])
            edb = where / "Windows.edb"
            if where not in repaired and edb.exists() and edb.read_bytes() == b"torn":
                (out / "LAB_PC_File_Report_20260101_115959.1.csv").write_text(
                    "a\n", encoding="utf-8")
                return 101, "", "thread 'main' panicked at 'wrong checksum'"
            (out / "LAB_PC_File_Report_20260101_120000.25.csv").write_text(
                "a\n1\n", encoding="utf-8")
        return 0, "", ""

    monkeypatch.setattr(H.procs, "run", fake_run)
    out = tmp_path / "out"
    ctx = ParserContext(evidence=tmp_path / "C", out=out, tools=tools, assets=tmp_path,
                        machine_name="HOST-01", volume="C", log=logging.getLogger("aeng.test"))
    return ctx, db, calls


def _sidr(calls):
    return [Path(a[-1]) for a, _ in calls if a[0].endswith("sidr.exe")]


def test_a_torn_database_is_read_from_a_repaired_copy(case, caplog):
    ctx, db, calls = case
    with caplog.at_level(logging.WARNING, logger="aeng.test"):
        H.run(ctx)
    first, copy = _sidr(calls)
    assert first == db and copy != db and not copy.exists()   # a temp copy, cleaned up
    # every esentutl call works on the copy, from the copy
    ese = [(a, cwd) for a, cwd in calls if not a[0].endswith("sidr.exe")]
    assert {a[1] for a, _ in ese} == {"/r", "/p"}
    for a, cwd in ese:
        assert Path(cwd) == copy
        assert all(Path(x) == copy or copy in Path(x).parents for x in a[2:] if ":" in x)
        assert all(str(db) not in x for x in a)
    r = next(a for a, _ in ese if a[1] == "/r")
    assert Path(r[r.index("/d") + 1]) == copy             # not the path the logs recorded
    assert (db / "Windows.edb").read_bytes() == b"torn"    # the evidence is untouched
    # only the repaired run's table reaches the case, named for neither host nor clock
    assert [f.name for f in ctx.out.iterdir()] == ["File_Report.csv"]
    assert "repaired copy" in caplog.text


def test_a_readable_database_is_read_where_it_lies(case):
    ctx, db, calls = case
    (db / "Windows.edb").write_bytes(b"dirty but whole")
    H.run(ctx)
    assert len(calls) == 1 and _sidr(calls) == [db]        # no copy, no esentutl
    assert [f.name for f in ctx.out.iterdir()] == ["File_Report.csv"]


def test_a_sqlite_index_is_never_opened_in_place(case):
    """SQLite writes a -shm beside a WAL database it opens."""
    ctx, db, calls = case
    (db / "Windows.edb").unlink()
    (db / "Windows.db").write_bytes(b"sqlite")
    H.run(ctx)
    assert _sidr(calls) and db not in _sidr(calls)


def test_a_first_run_killed_by_its_timeout_leaves_nothing(case, monkeypatch):
    ctx, _db, _calls = case

    def hangs(argv, timeout=None, cwd=None):
        (Path(argv[argv.index("-o") + 1]) / "LAB_PC_File_Report_20260101_1.csv").write_text(
            "a\n", encoding="utf-8")
        raise subprocess.TimeoutExpired(argv, timeout)

    monkeypatch.setattr(H.procs, "run", hangs)
    with pytest.raises(subprocess.TimeoutExpired):
        H.run(ctx)
    assert ctx.out.is_dir() and not any(ctx.out.iterdir())


def test_leftovers_that_cannot_be_cleared_fail_the_run(case, monkeypatch):
    ctx, _db, calls = case
    monkeypatch.setattr(H.shutil, "rmtree", lambda *a, **k: None)
    with pytest.raises(RuntimeError, match="could not clear"):
        H.run(ctx)
    assert len(_sidr(calls)) == 1


def test_a_copy_that_still_fails_is_an_error(case, monkeypatch):
    ctx, _db, _calls = case
    monkeypatch.setattr(H.procs, "run", lambda argv, timeout=None, cwd=None:
                        (101, "", "panicked") if argv[0].endswith("sidr.exe") else (0, "", ""))
    with pytest.raises(RuntimeError, match="repaired copy"):
        H.run(ctx)
