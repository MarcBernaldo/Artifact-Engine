"""v0.7.126: run-summary names the run's slowest parser x machine tasks."""
from __future__ import annotations

import json
from pathlib import Path

from artifact_engine.core import report
from artifact_engine.core.detector import Machine
from artifact_engine.core.runner import ParserRun


def _machine(name: str) -> Machine:
    m = Machine(name=name, os="windows", collector="kape", profile_id="windows_kape",
                path=Path("."))
    m.display = name
    return m


def test_the_slowest_tasks_are_named_longest_first_and_cached_ones_are_not(tmp_path):
    runs_a = [ParserRun(f"p{i}", "C", "ok", float(i), "") for i in range(12)]
    runs_a.append(ParserRun("mft", "C", "cached", 999.0, "already parsed"))
    runs_b = [ParserRun("hayabusa", "C", "error", 50.5, "boom")]
    report.build_run_summary(tmp_path, [(_machine("HOST-01"), runs_a),
                                        (_machine("HOST-02"), runs_b)])

    got = json.loads((tmp_path / "run-summary.json").read_text(encoding="utf-8"))
    tasks = got["slowest_tasks"]
    assert len(tasks) == report.SLOWEST_TASKS
    assert tasks[0] == {"machine": "HOST-02", "parser": "hayabusa", "seconds": 50.5,
                        "status": "error"}
    assert [t["parser"] for t in tasks[1:]] == [f"p{i}" for i in range(11, 2, -1)]
    assert all(t["parser"] != "mft" for t in tasks), "a cached task took no time"

    text = (tmp_path / "run-summary.txt").read_text(encoding="utf-8")
    assert "Slowest tasks this run (top 10):" in text
    assert "hayabusa" in text and "(error)" in text
