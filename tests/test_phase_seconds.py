"""AE-112: run-summary says how long each phase took -- what consolidation costs
on a real case could not be read from anything a run left."""
from __future__ import annotations

import json

from artifact_engine import cli
from artifact_engine.core import report


def test_a_run_leaves_how_long_each_phase_took(tmp_path, monkeypatch):
    case = tmp_path / "case"
    case.mkdir()
    monkeypatch.chdir(tmp_path)
    cli.main(["run", "-p", str(case)])
    summary = json.loads((case / "run-summary.json").read_text(encoding="utf-8"))
    phases = summary["phase_seconds"]
    assert list(phases)[:2] == ["start", "phase 0 (integrity)"]
    assert "phase 4 (consolidation)" in phases and "phase 5 (lateral graph)" in phases
    assert all(isinstance(s, float) and s >= 0 for s in phases.values())
    assert "Time per phase:" in (case / "run-summary.txt").read_text(encoding="utf-8")


def test_a_phase_entered_twice_adds_up():
    phase = {"entered": [("a", 0.0), ("b", 1.0), ("a", 3.0), ("c", 3.5)]}
    assert cli._phase_seconds(phase) == {"a": 1.5, "b": 2.0}


def test_the_stub_has_the_key_empty(tmp_path):
    report.write_stub(tmp_path, "running", "phase 3 (parsing)")
    stub = json.loads((tmp_path / "run-summary.json").read_text(encoding="utf-8"))
    assert stub["phase_seconds"] == {}
