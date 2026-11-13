"""AE-108: what a run did not cover reaches its verdict."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from artifact_engine import cli
from artifact_engine.core import extractor, gaps, lateral, memory, pipeline, report
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.core.runner import ParserRun


def _one_machine(root: Path):
    m = Machine("HOST-00", "linux", "uac", "linux_uac", root / "HOST-00", "src",
                [Volume("live", root / "HOST-00", True)])
    return [(m, [ParserRun("p", "live", "ok", 1.0, "")])]


def test_anything_not_covered_makes_the_run_incomplete(tmp_path):
    s = report.build_run_summary(tmp_path, _one_machine(tmp_path), not_covered=[
        {"what": "lateral graph", "detail": "lateral_movement.csv not written"}])
    assert s["status"] == "incomplete" and s["not_covered"]
    assert "NOT covered" in (tmp_path / "run-summary.txt").read_text(encoding="utf-8")


def test_a_lateral_output_not_written_is_collected():
    gaps.reset()

    def locked(p):
        raise PermissionError(13, "open in another program")

    assert not lateral._write_out(Path("lateral_movement.csv"), locked)
    assert [g["what"] for g in gaps.taken()] == ["lateral graph"]


def test_a_memory_image_left_out_is_collected(tmp_path):
    gaps.reset()
    image = tmp_path / "HOST-01.raw"
    with image.open("wb") as fh:
        fh.truncate(64 * 1024 * 1024)
    (tmp_path / "HOST-01_memory").mkdir()
    (tmp_path / "HOST-01_memory" / "notes.txt").write_text("x", encoding="utf-8")
    assert memory.stage_images(tmp_path) == []
    assert [g["what"] for g in gaps.taken()] == ["memory image"]


def test_a_dropped_manifest_is_collected(tmp_path):
    from artifact_engine.registry import load_parsers

    gaps.reset()
    (tmp_path / "bad.yaml").write_text("id: [unclosed\n", encoding="utf-8")
    (tmp_path / "invalid.yaml").write_text("id: x\n", encoding="utf-8")
    load_parsers([tmp_path])
    assert sorted(g["detail"].split(":")[0] for g in gaps.taken()) == ["bad.yaml", "invalid.yaml"]


def test_the_run_hands_what_it_collected_to_its_verdict(tmp_path, monkeypatch):
    def detect(*a, **k):
        gaps.add("memory image", "HOST-01.raw: not analysed")
        return []

    monkeypatch.setattr(extractor, "extract_all", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "detect", detect)
    gaps.add("stale", "from an earlier run in this process")
    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)
    cli.cmd_run(args)
    got = json.loads((tmp_path / "run-summary.json").read_text(encoding="utf-8"))
    assert [g["what"] for g in got["not_covered"]] == ["memory image"]



def test_an_event_log_left_unstaged_is_collected(tmp_path):
    from artifact_engine.core.detector import _EVTX_LOGS_SUBPATH, prepare_evtx_drops

    gaps.reset()
    drop = tmp_path / "evtx-caso"
    logs = drop / _EVTX_LOGS_SUBPATH
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"ElfFile\0A")
    (drop / "Security.evtx").write_bytes(b"ElfFile\0B")
    prepare_evtx_drops([Machine("evtx-caso", "windows", "evtx", "windows_evtx", drop, "src",
                                [Volume("live", drop, True)])])
    assert [g["what"] for g in gaps.taken()] == ["event log"]


def test_a_memory_unit_detection_did_not_reach_is_collected(tmp_path, monkeypatch):
    from artifact_engine.config import Config
    from artifact_engine.core import detector, memory_os

    gaps.reset()
    unit = tmp_path / "HOST-01_memory"
    unit.mkdir()
    monkeypatch.setattr(memory, "stage_images", lambda root: [unit])
    monkeypatch.setattr(memory_os, "classify_units", lambda units: None)
    monkeypatch.setattr(detector, "detect_machines", lambda *a, **k: [])
    pipeline.detect(tmp_path, Config(), [], stage_drops=True)
    assert [g["what"] for g in gaps.taken()] == ["memory image"]


def test_aeng_lateral_that_cannot_write_its_files_is_incomplete(tmp_path, monkeypatch):
    m = _one_machine(tmp_path)[0][0]

    def graph(*a, **k):
        gaps.add("lateral graph", "lateral_movement.csv not written")
        return {"hosts": 0, "edges": 0, "suspicious": 0}

    monkeypatch.setattr(pipeline, "detect", lambda *a, **k: [m])
    monkeypatch.setattr(pipeline, "lateral_graph", graph)
    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False)
    assert cli.cmd_lateral(args) == cli.EXIT_INCOMPLETE
