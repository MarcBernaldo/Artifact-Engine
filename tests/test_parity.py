"""The comparison CI leans on, checked here so a green build means something.

`tests/parity.py` is the only thing standing between "the two legs agree" and
"nobody looked". A comparator that always passes is this project's cardinal sin
wearing a CI badge, so the cases below are mostly about what it must NOT let
through -- and the recipe is checked against the profile it has to match, because
a generator that drifts produces a case neither leg detects and two summaries
that agree on nothing at all.
"""
from __future__ import annotations

import json
from pathlib import Path

import parity
import yaml

from artifact_engine.config import DATA_DIR


def _report(**over) -> dict:
    base = {
        "case_version": parity.CASE_VERSION,
        "summary": {"status": "complete", "machines": 1,
                    "totals": {"ok": 15, "cached": 0, "skipped": 29, "errors": 0}},
        "tables": {"a/CSVs/EventLogs/auth.csv": 17, "lateral_movement.csv": 5},
    }
    base.update(over)
    return base


def _files(tmp_path: Path, a: dict, b: dict) -> tuple[Path, Path]:
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    first.write_text(json.dumps(a), encoding="utf-8")
    second.write_text(json.dumps(b), encoding="utf-8")
    return first, second


# --------------------------------------------------------------------------- #
# What it must let through, and what it must not
# --------------------------------------------------------------------------- #
def test_two_identical_reports_agree(tmp_path, capsys):
    assert parity.compare(*_files(tmp_path, _report(), _report())) == 0
    assert "agree" in capsys.readouterr().out


def test_a_row_count_that_moved_is_named(tmp_path, capsys):
    """The reason the report carries row counts at all. Both legs can report `ok`
    for a parser and disagree about what it found -- a case-folding difference, a
    path flavour, a locale -- and a status-only comparison would pass. Zero rows
    reading as no attack is the failure this whole repository is organised
    against; it must not reach a green build."""
    moved = _report(tables={"a/CSVs/EventLogs/auth.csv": 14, "lateral_movement.csv": 5})

    assert parity.compare(*_files(tmp_path, _report(), moved)) == 1
    said = capsys.readouterr().out
    assert "auth.csv" in said and "17" in said and "14" in said


def test_a_table_present_on_only_one_leg_is_named(tmp_path, capsys):
    """The other half of the same failure: not a smaller table, an absent one."""
    fewer = _report(tables={"lateral_movement.csv": 5})

    assert parity.compare(*_files(tmp_path, _report(), fewer)) == 1
    assert "missing on the second" in capsys.readouterr().out


def test_a_status_that_disagrees_is_named(tmp_path, capsys):
    other = _report(summary={"status": "incomplete", "machines": 1,
                             "totals": {"ok": 14, "cached": 0, "skipped": 29,
                                        "errors": 1}})

    assert parity.compare(*_files(tmp_path, _report(), other)) == 1
    assert "complete" in capsys.readouterr().out


def test_a_different_recipe_is_refused_rather_than_compared(tmp_path, capsys):
    """Two cases, not two readings of one. Comparing them would produce a diff
    that is real and means nothing."""
    assert parity.compare(*_files(tmp_path, _report(),
                                  _report(case_version=parity.CASE_VERSION + 1))) == 1
    assert "different case recipes" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# What it is net of
# --------------------------------------------------------------------------- #
def test_the_moment_and_the_machine_are_not_compared():
    """Parity is claimed net of duration, platform and timestamps -- every one of
    which differs on every run and none of which is an answer about the case."""
    windows = {
        "schema_version": 1, "status": "complete",
        "engine": {"version": "9.9.9", "python": "3.13.14", "os": "Windows",
                   "os_release": "11"},
        "generated": "A", "started_at": "A", "finished_at": "B",
        "duration_seconds": 2.3,
        "per_machine": [{"machine": "m", "ok": 15, "time_s": 2.3,
                         "slowest": "yara (1s)"}],
        "tools": {"tools_needed": 0, "archiver_present": True},
    }
    linux = {
        "schema_version": 1, "status": "complete",
        "engine": {"version": "9.9.9", "python": "3.13.2", "os": "Linux",
                   "os_release": "6.8.0"},
        "generated": "C", "started_at": "C", "finished_at": "D",
        "duration_seconds": 4.2,
        "per_machine": [{"machine": "m", "ok": 15, "time_s": 4.2,
                         "slowest": "sigma (2s)"}],
        "tools": {"tools_needed": 0, "archiver_present": False},
    }

    assert parity._prune(windows) == parity._prune(linux)


def test_the_engine_version_is_still_compared():
    """Net of the machine, not net of the build. Two summaries written by
    different versions of this tool are not each other's control either."""
    a = {"engine": {"version": "9.9.9", "os": "Windows"}}
    b = {"engine": {"version": "9.9.10", "os": "Linux"}}

    assert parity._prune(a) != parity._prune(b)


# --------------------------------------------------------------------------- #
# The recipe, against the profile it has to match
# --------------------------------------------------------------------------- #
def test_the_case_it_builds_is_one_the_uac_profile_detects(tmp_path):
    """A generator that drifts from `linux_uac.yaml` builds a case neither leg
    detects: both would report zero machines, agree perfectly, and prove
    nothing."""
    profile = yaml.safe_load(
        (DATA_DIR / "profiles" / "linux_uac.yaml").read_text(encoding="utf-8"))
    marker = profile["detect"]["all_of"][0]["exists"]
    named_by = profile["machine_name"]["file"]

    acq = parity.build(tmp_path / "case")

    assert (acq / marker).is_file(), f"the profile detects on {marker}"
    assert (acq / named_by).is_file(), f"the machine is named from {named_by}"


def test_the_case_carries_no_value_from_a_real_one(tmp_path):
    """Invented on purpose, and asserted rather than trusted: this file is
    committed, so anything in it is published. The addresses are documentation
    ranges and the names are placeholders -- see "Case data never becomes text"
    in CLAUDE.md."""
    acq = parity.build(tmp_path / "case")
    text = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                     for p in acq.rglob("*") if p.is_file())

    assert parity.ATTACKER.startswith("198.51.100."), "RFC 5737 documentation range"
    assert parity.PEER.startswith("10."), "RFC 1918"
    assert parity.HOST in text and parity.USER in text
