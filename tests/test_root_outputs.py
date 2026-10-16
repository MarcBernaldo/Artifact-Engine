"""v0.7.132: a machine detected AT the case root writes its outputs there, and
the next run's phase 0 recorded them as originals. Phase 0 now reads the names
from that machine's own run.json and skips exactly those, at the root only."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from artifact_engine.core import hashing
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.core.runner import ParserRun


def _recorded(root: Path) -> list[str]:
    with open(root / hashing.TRACES_CSV, encoding="utf-8", newline="") as fh:
        rows = list(csv.reader(fh))
    return sorted(r[0] for r in rows[1:] if r)


def _outputs_of(root: Path, name: str = "HOST-01") -> None:
    """What an earlier run left at a root that IS the machine -- any version."""
    (root / "run.json").write_text(json.dumps({"machine": name, "runs": []}), encoding="utf-8")
    for n in ("report.txt", "findings.csv", f"{name}.db", f"{name}.xlsx",
              f".{name}.consolidated", f".{name}.aeng-merge.db"):
        (root / n).write_bytes(b"o")


def test_a_root_machines_outputs_are_not_originals(tmp_path):
    (tmp_path / "evidence.bin").write_bytes(b"e")
    _outputs_of(tmp_path)

    entries = hashing.generate_traces(tmp_path, operator="t")

    assert [e.rel_path for e in entries] == ["evidence.bin"]


def test_the_same_names_below_the_root_are_still_evidence(tmp_path):
    _outputs_of(tmp_path)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "report.txt").write_text("evidence", encoding="utf-8")
    (tmp_path / "sub" / "HOST-01.db").write_bytes(b"evidence")

    entries = hashing.generate_traces(tmp_path, operator="t")

    assert sorted(e.rel_path for e in entries) == [
        str(Path("sub") / "HOST-01.db"), str(Path("sub") / "report.txt")]


def test_without_an_engine_run_json_nothing_is_excluded(tmp_path):
    """A `run.json` that is not the engine's -- or none at all -- names nothing."""
    (tmp_path / "report.txt").write_text("evidence", encoding="utf-8")
    (tmp_path / "run.json").write_text('{"something": "else"}', encoding="utf-8")

    entries = hashing.generate_traces(tmp_path, operator="t")

    assert sorted(e.rel_path for e in entries) == ["report.txt", "run.json"]


def test_a_second_run_over_a_root_machine_records_no_outputs(tmp_path, monkeypatch):
    """End to end through cmd_run, twice, with the real run.json writer."""
    from artifact_engine import cli
    from artifact_engine.core import extractor, pipeline, scheduler

    (tmp_path / "evidence.bin").write_bytes(b"e")
    m = Machine("HOST-01", "windows", "kape", "windows_kape", tmp_path, "src",
                [Volume("live", tmp_path, True)])
    m.display = "HOST-01"

    def run_all(*a, **k):
        results = [(m, [ParserRun("p", "live", "ok", 1.0, "")])]
        scheduler.write_manifests(results)
        return results

    monkeypatch.setattr(extractor, "extract_all", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "detect", lambda *a, **k: [m])
    monkeypatch.setattr(scheduler, "run_all", run_all)
    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)

    cli.cmd_run(args)
    assert (tmp_path / "report.txt").is_file() and (tmp_path / "run.json").is_file()
    cli.cmd_run(args)

    assert _recorded(tmp_path) == ["evidence.bin"]


def _run_json(folder: Path, name: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "run.json").write_text(json.dumps({"machine": name, "runs": []}),
                                     encoding="utf-8")


def test_a_live_volume_merged_with_its_snapshots_at_the_root(tmp_path):
    """Found by review: `<root>/C` + `<root>/VSS1` merge into one unit whose
    outputs land in their parent -- the root -- with no run.json there."""
    _run_json(tmp_path / "C", "HOST-01")
    _run_json(tmp_path / "VSS1", "HOST-01_VSS1")
    for n in ("HOST-01.db", "report.txt", "findings.csv", ".HOST-01.consolidated",
              ".HOST-01.aeng-merge.db"):
        (tmp_path / n).write_bytes(b"o")
    (tmp_path / "evidence.bin").write_bytes(b"e")

    entries = hashing.generate_traces(tmp_path, operator="t")

    assert [e.rel_path for e in entries if Path(e.rel_path).parent == Path(".")] \
        == ["evidence.bin"]


def test_an_ordinary_case_root_excludes_nothing(tmp_path):
    """Machines one level down without snapshots write inside their own folders."""
    _run_json(tmp_path / "HOST-01", "HOST-01")
    _run_json(tmp_path / "HOST-02", "HOST-02")
    assert hashing.root_machine_outputs(tmp_path) == set()


def test_names_match_without_case(tmp_path):
    """NTFS keeps a file's old casing when it is overwritten."""
    _run_json(tmp_path, "host-01")
    (tmp_path / "HOST-01.xlsx").write_bytes(b"o")
    (tmp_path / "evidence.bin").write_bytes(b"e")

    entries = hashing.generate_traces(tmp_path, operator="t")

    assert [e.rel_path for e in entries] == ["evidence.bin"]
