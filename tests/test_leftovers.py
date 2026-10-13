"""v0.7.128: a machine detected over what a failed or partial extraction left on
disk says so, in its report.txt and in run-summary -- it is parsed like any
other tree, and its report used to read like a clean triage of a quiet host."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from artifact_engine.core import extractor as E
from artifact_engine.core import leftovers
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.core.runner import ParserRun


def _m(name: str, path: Path) -> Machine:
    path.mkdir(parents=True, exist_ok=True)
    return Machine(name, "windows", "kape", "windows_kape", path, "src",
                   [Volume("live", path, True)])


def _r(name: str, dest: Path, **kw) -> E.ExtractResult:
    return E.ExtractResult(archive=Path(name), dest=dest, ok=kw.pop("ok", True), **kw)


def test_a_machine_inside_a_failed_destination_is_over_it(tmp_path):
    m = _m("HOST-01", tmp_path / "HOST-01" / "C")
    over = leftovers.machines_over(
        [_r("HOST-01.zip", tmp_path / "HOST-01", ok=False, error="rc=2")], [m], tmp_path)
    [hit] = over[id(m)]
    assert (hit["archive"], hit["status"], hit["detail"]) == ("HOST-01.zip", "failed", "rc=2")


def test_a_nested_partial_archive_marks_the_machine_around_it(tmp_path):
    m = _m("HOST-02", tmp_path / "HOST-02")
    inner = tmp_path / "HOST-02" / "nested"
    over = leftovers.machines_over(
        [_r("nested.tar.gz", inner, partial=True, warning_detail="cut short")], [m], tmp_path)
    assert [a["status"] for a in over[id(m)]] == ["partial"]


def test_whole_archives_and_unrelated_machines_are_not_marked(tmp_path):
    a, b = _m("HOST-01", tmp_path / "HOST-01"), _m("HOST-02", tmp_path / "HOST-02")
    over = leftovers.machines_over(
        [_r("HOST-01.zip", tmp_path / "HOST-01"),
         _r("HOST-03.zip", tmp_path / "HOST-03", ok=False, error="x")], [a, b], tmp_path)
    assert over == {}


def test_a_machine_at_the_case_root_is_not_marked_by_every_archive(tmp_path):
    root_m = Machine("HOST-09", "windows", "liveresponse", "lr", tmp_path, "src",
                     [Volume("live", tmp_path, True)])
    over = leftovers.machines_over(
        [_r("HOST-03.zip", tmp_path / "HOST-03", ok=False, error="x")], [root_m], tmp_path)
    assert over == {}


def test_run_reports_the_machine_built_over_a_failed_extraction(tmp_path, monkeypatch):
    """End to end through cmd_run: report.txt opens with the warning, and
    run-summary names the machine under the acquisition."""
    from artifact_engine import cli
    from artifact_engine.core import pipeline, scheduler

    m = _m("HOST-01", tmp_path / "HOST-01")
    monkeypatch.setattr(E, "extract_all", lambda *a, **k: [
        _r("HOST-01.zip", tmp_path / "HOST-01", ok=False, error="rc=2: not an archive")])
    monkeypatch.setattr(pipeline, "detect", lambda *a, **k: [m])
    monkeypatch.setattr(scheduler, "run_all",
                        lambda *a, **k: [(m, [ParserRun("p", "live", "ok", 1.0, "")])])

    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)
    assert cli.cmd_run(args) == cli.EXIT_INCOMPLETE

    rep = (tmp_path / "HOST-01" / "report.txt").read_text(encoding="utf-8")
    assert "did NOT extract whole" in rep and "HOST-01.zip: failed" in rep
    assert rep.index("did NOT extract whole") < rep.index("Parser execution")
    summary = json.loads((tmp_path / "run-summary.json").read_text(encoding="utf-8"))
    [acq] = summary["incomplete_acquisitions"]
    assert acq["machines"] == [m.display or m.name]
    assert "detected and parsed as: " in (tmp_path / "run-summary.txt").read_text(
        encoding="utf-8")


# Found by review (v0.7.128).
def test_a_broken_velociraptor_zip_marks_the_kape_volume_beside_it(tmp_path):
    m = _m("HOST-01", tmp_path / "HOST-01" / "C")
    lr = tmp_path / "HOST-01" / "Velociraptor" / "LiveResponse"
    over = leftovers.machines_over(
        [_r("LiveResponse.zip", lr, ok=False, error="x")], [m], tmp_path)
    assert [a["archive"] for a in over[id(m)]] == ["LiveResponse.zip"]


def test_same_named_acquisitions_are_told_apart_by_destination(tmp_path):
    a = _m("HOST-01", tmp_path / "HOST-01" / "C")
    _m("HOST-02", tmp_path / "HOST-02" / "C")
    acqs = [_r("LiveResponse.zip", tmp_path / h / "Velociraptor" / "LiveResponse",
               ok=False, error="not a zip") for h in ("HOST-01", "HOST-03")]
    over = leftovers.machines_over(acqs, [a], tmp_path)
    incomplete = E.incomplete_acquisitions(acqs)
    leftovers.name_machines(incomplete, acqs, over, [a])
    assert [e.get("machines") for e in incomplete] == [[a.display or a.name], None]


def test_a_drop_folder_run_marks_its_own_root_machine(tmp_path):
    root = tmp_path / "weblogs-fw01"
    m = Machine("fw01", "network", "weblogs", "weblogs", root, "src",
                [Volume("live", root, True)])
    root.mkdir()
    over = leftovers.machines_over(
        [_r("export.zip", root / "export", ok=False, error="x")], [m], root)
    assert id(m) in over


def test_a_failed_extraction_is_not_adopted_once_its_leftovers_are_parsed(tmp_path):
    """Run 1 fails and writes no marker; its leftovers are parsed. Run 2 used to
    find results there, adopt the tree and record the acquisition as whole."""
    z = tmp_path / "HOST-01.zip"
    z.write_bytes(b"PK\x03\x04 not really a zip")
    dest = tmp_path / "HOST-01"
    first = E._extract_one(z, dest, None)
    assert not first.ok
    (dest / "C" / "CSVs").mkdir(parents=True)          # the leftovers were parsed

    again = E._extract_one(z, dest, None)
    assert not again.ok and "failed in an earlier run" in again.error
    assert not (dest / E.MARKER).exists()
    assert [a["status"] for a in E.incomplete_acquisitions([again])] == ["failed"]


def test_a_run_pointed_at_one_collection_marks_its_volume(tmp_path):
    """`-p HOST-01`: the root IS the collection, its Velociraptor folder at the root."""
    m = _m("HOST-01", tmp_path / "C")
    over = leftovers.machines_over(
        [_r("LiveResponse.zip", tmp_path / "Velociraptor" / "LiveResponse", ok=False,
            error="x")], [m], tmp_path)
    assert id(m) in over
