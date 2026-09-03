r"""The collector's own copy of the disk, and keeping it out of the answer.

A triage collector pointed at the volume it is collecting writes every artifact
twice, and the second copy is recorded in the $MFT (or the bodyfile) exactly like
the first. A search for a filename then returns the real hit next to its
duplicate, and a path under the operator's output folder reads as activity at
that path.

These tests pin the shape that identifies it -- a directory whose children are the
volume's own root -- and, more importantly, the two things it must NOT do with
that identification: hide `Windows.old`, which is real evidence of the previous
install, and hide anything at all without saying how much it hid.
"""
from __future__ import annotations

import argparse
import csv
import logging
import sqlite3
from pathlib import Path

import pytest

from artifact_engine.core import coverage, sweep
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import lin_collection as L
from artifact_engine.handlers import win_collection as W


class _Ctx:
    def __init__(self, evidence: Path, out: Path):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "C"
        self.log = None


def _out(tmp_path: Path) -> list[dict]:
    p = tmp_path / "out" / "collection_artifacts.csv"
    if not p.is_file():
        return []
    with p.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# Windows: $MFT
# --------------------------------------------------------------------------- #
_MFT_COLS = ["ParentPath", "FileName", "IsDirectory", "Created0x10"]

_ROOTS = ["Windows", "Users", "ProgramData", "$Recycle.Bin"]


def _mft(tmp_path: Path, rows: list[tuple]) -> None:
    d = tmp_path / "CSVs" / "Filesystem"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "MFT.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(_MFT_COLS)
        w.writerows(rows)


def _dirs(parent: str, names: list[str], created: str = "2026-05-19 10:00:00.0000000"):
    return [(parent, n, "True", created) for n in names]


def _win(tmp_path: Path, rows: list[tuple]) -> list[dict]:
    _mft(tmp_path, rows)
    W.run(_Ctx(tmp_path, tmp_path / "out"))
    return _out(tmp_path)


def _volume() -> list[tuple]:
    """A plain volume: the roots at the root, and nothing mirrored."""
    return _dirs(".", _ROOTS) + [(".\\Windows", "System32", "True", "2020-01-01 00:00:00.0000000")]


def test_a_directory_holding_the_volumes_own_root_is_the_collection(tmp_path):
    rows = _win(tmp_path, _volume() + _dirs(".\\Users\\jdoe\\Downloads\\tout\\C", _ROOTS))
    trees = [r for r in rows if r["kind"] == "mirrored_tree"]
    assert len(trees) == 1
    assert trees[0]["path"].endswith("tout\\C")
    assert trees[0]["exclude"] == "yes"
    assert "windows" in trees[0]["evidence"] and "users" in trees[0]["evidence"]


def test_a_plain_volume_produces_no_table_at_all(tmp_path):
    assert _win(tmp_path, _volume()) == []


def test_one_folder_called_users_is_not_a_copy_of_the_volume(tmp_path):
    """Three markers is the bar. A single `Users` under an application directory
    is a folder, and treating it as a mirrored volume would hide the tree it
    sits in from every search."""
    assert _win(tmp_path, _volume() + _dirs(".\\Apps\\myapp", ["Users"])) == []


def test_windows_old_is_named_and_never_hidden(tmp_path):
    """An in-place upgrade leaves exactly this shape, and what it holds is the
    host before the upgrade -- the opposite of a duplicate."""
    rows = _win(tmp_path, _volume() + _dirs(".\\Windows.old", _ROOTS))
    old = [r for r in rows if r["kind"] == "os_upgrade"]
    assert len(old) == 1
    assert old[0]["exclude"] == "", "the previous install is evidence, not a copy"
    assert "previous Windows install" in old[0]["note"]


def test_a_tree_identified_by_shape_alone_says_so(tmp_path):
    """A backup and a mounted image look the same. Hiding one by default is a
    defensible choice only if the report says why it was hidden."""
    rows = _win(tmp_path, _volume() + _dirs(".\\Backup\\2026\\C", _ROOTS))
    assert "SHAPE alone" in rows[0]["note"]


def test_a_named_collector_turns_the_shape_into_an_identification(tmp_path):
    rows = _win(tmp_path, _volume()
                + _dirs(".\\Users\\jdoe\\Desktop", ["KAPE"])
                + _dirs(".\\Users\\jdoe\\Desktop\\KAPE\\out\\C", _ROOTS))
    tree = [r for r in rows if r["kind"] == "mirrored_tree"][0]
    assert "under KAPE" in tree["evidence"]
    assert "SHAPE alone" not in tree["note"]


def test_a_collector_directory_is_reported_but_not_hidden(tmp_path):
    """An attacker's tools sit in the operator's folder as easily as anywhere."""
    rows = _win(tmp_path, _volume() + _dirs(".\\Users\\jdoe\\Desktop", ["KAPE"]))
    assert [r["kind"] for r in rows] == ["tool_dir"]
    assert rows[0]["exclude"] == ""


def test_the_tree_carries_the_window_it_was_written_in(tmp_path):
    """When the collection is on the disk, its own files date the acquisition."""
    tree = ".\\Users\\jdoe\\Downloads\\tout\\C"
    rows = _win(tmp_path, _volume()
                + _dirs(tree, _ROOTS, created="2026-05-19 10:15:00.0000000")
                + [(tree + "\\Windows", "x.evtx", "False", "2026-05-19 10:31:00.0000000")])
    tf = [r for r in rows if r["kind"] == "mirrored_tree"][0]
    assert tf["first_created_utc"].startswith("2026-05-19 10:15")
    assert tf["last_created_utc"].startswith("2026-05-19 10:31")
    assert int(tf["entries"]) == 5


def test_no_mft_csv_skips(tmp_path):
    with pytest.raises(HandlerSkip):
        W.run(_Ctx(tmp_path, tmp_path / "out"))


# --------------------------------------------------------------------------- #
# Linux: bodyfile
# --------------------------------------------------------------------------- #
_BODY_COLS = ["name", "inode", "mode", "uid", "gid", "size",
              "atime_utc", "mtime_utc", "ctime_utc", "crtime_utc"]

_LROOTS = ["etc", "usr", "var", "home", "root"]


def _body(tmp_path: Path, entries: list[tuple[str, bool]]) -> None:
    d = tmp_path / "CSVs" / "Filesystem"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "bodyfile.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(_BODY_COLS)
        for name, is_dir in entries:
            mode = "d/drwxr-xr-x" if is_dir else "-/-rw-r--r--"
            w.writerow([name, "1", mode, "0", "0", "1024", "", "",
                        "2026-05-19 10:15:00", "2026-05-19 10:15:00"])


def _lin(tmp_path: Path, entries: list[tuple[str, bool]]) -> list[dict]:
    _body(tmp_path, entries)
    L.run(_Ctx(tmp_path, tmp_path / "out"))
    return _out(tmp_path)


def _fs() -> list[tuple[str, bool]]:
    return [(f"/{n}", True) for n in _LROOTS]


def test_a_uac_tree_left_on_the_host_is_the_collection(tmp_path):
    rows = _lin(tmp_path, _fs() + [(f"/tmp/uac-HOST-01/[root]/{n}", True) for n in _LROOTS])
    trees = [r for r in rows if r["kind"] == "mirrored_tree"]
    assert len(trees) == 1 and trees[0]["exclude"] == "yes"
    assert trees[0]["path"] == "/tmp/uac-HOST-01/[root]"


def test_three_root_names_are_not_a_filesystem(tmp_path):
    """`bin`, `lib` and `etc` under an application directory is not unusual, and
    hiding that directory would hide whatever else is in it."""
    assert _lin(tmp_path, _fs() + [("/opt/app/" + n, True) for n in ("bin", "lib", "etc")]) == []


def test_a_plain_filesystem_produces_no_table(tmp_path):
    assert _lin(tmp_path, _fs()) == []


def test_no_bodyfile_skips(tmp_path):
    with pytest.raises(HandlerSkip):
        L.run(_Ctx(tmp_path, tmp_path / "out"))


# --------------------------------------------------------------------------- #
# What the sweep does with it
# --------------------------------------------------------------------------- #
def _case(tmp_path: Path, collection: list[dict] | None = None) -> Path:
    """A one-machine case whose MFT table holds the same filename twice: once
    where it lives, once under the collector's output."""
    case = tmp_path / "CASE-01"
    (case / "HOST-01").mkdir(parents=True)
    db = case / "HOST-01" / "HOST-01.db"
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE "MFT" ("ParentPath" TEXT, "FileName" TEXT)')
    conn.executemany('INSERT INTO "MFT" VALUES (?, ?)', [
        (".\\Windows\\Temp", "beacon.exe"),
        (".\\Users\\jdoe\\Downloads\\tout\\C\\Windows\\Temp", "beacon.exe"),
    ])
    if collection is not None:
        cols = list(collection[0])
        conn.execute(f'CREATE TABLE "collection_artifacts" '
                     f'({", ".join(f_ + " TEXT" for f_ in cols)})')
        conn.executemany(
            f'INSERT INTO "collection_artifacts" VALUES ({",".join("?" * len(cols))})',
            [[r[c] for c in cols] for r in collection])
    conn.commit()
    conn.close()
    return case


_TREE = [{"kind": "mirrored_tree", "path": ".\\Users\\jdoe\\Downloads\\tout\\C",
          "exclude": "yes"}]


def test_the_collectors_copy_is_dropped_from_a_sweep(tmp_path):
    got = sweep.sweep(_case(tmp_path, _TREE), ["beacon.exe"])
    assert len(got.hits) == 1
    assert "tout" not in got.hits[0].context
    assert got.hidden == {"HOST-01": 1}


def test_a_hidden_hit_is_counted_not_forgotten(tmp_path, caplog):
    """"No hits" while three were hidden is a wrong answer, not a tidier one."""
    from artifact_engine import cli

    case = _case(tmp_path, _TREE)
    with caplog.at_level(logging.INFO, logger="aeng"):
        cli.cmd_sweep(argparse.Namespace(path=str(case), value=["beacon.exe"],
                                         verbose=False, include_collection=False))
    said = " ".join(r.message for r in caplog.records)
    assert "1 row(s) hidden" in said and "--include-collection" in said


def test_include_collection_puts_them_back(tmp_path):
    got = sweep.sweep(_case(tmp_path, _TREE), ["beacon.exe"], include_collection=True)
    assert len(got.hits) == 2 and not got.hidden


def test_a_row_the_parser_did_not_mark_is_never_hidden(tmp_path):
    """`Windows.old` and the operator's tool directory live in the same table and
    carry no `exclude`. Hiding them would hide the previous install."""
    rows = [{"kind": "os_upgrade", "path": ".\\Users\\jdoe\\Downloads\\tout\\C",
             "exclude": ""}]
    got = sweep.sweep(_case(tmp_path, rows), ["beacon.exe"])
    assert len(got.hits) == 2 and not got.hidden


def test_a_machine_without_the_table_sweeps_exactly_as_before(tmp_path):
    got = sweep.sweep(_case(tmp_path, None), ["beacon.exe"])
    assert len(got.hits) == 2 and not got.hidden


def test_the_report_names_the_copies_it_hides(tmp_path):
    from artifact_engine.core.detector import Machine
    from artifact_engine.core.report import build

    case = _case(tmp_path, [{
        "kind": "mirrored_tree", "path": ".\\Users\\jdoe\\Downloads\\tout\\C",
        "entries": "48211", "first_created_utc": "2026-05-19 10:15:00",
        "last_created_utc": "2026-05-19 10:31:00", "evidence": "users, windows",
        "exclude": "yes", "note": "a copy of this volume", "suspicious": ""}])
    db = case / "HOST-01" / "HOST-01.db"
    m = Machine(name="HOST-01", path=db.parent, os="windows", collector="kape",
                source="x", profile_id="win_kape")
    build(m, [], out_dir=db.parent, db_path=db)
    text = (db.parent / "report.txt").read_text(encoding="utf-8")
    assert "Collection artifacts" in text
    assert "48211 entries" in text
    assert "--include-collection" in text
    assert text.index("Collection artifacts") < text.index("Findings")


def test_a_machine_that_was_not_collected_onto_itself_gets_no_block(tmp_path):
    assert coverage.render_collection([]) == []
