"""An acquisition with a hole in it must not read as a clean triage.

The failure this exists for leaves no error anywhere. A tarball cut short
mid-write extracts to a partial tree; every parser under it finds no input,
self-gates, and is counted as `skipped` -- the same count an artifact gets when
the machine's distro simply does not have it. The run ends

    OK 2 | skipped 37 | errors 0        Errors: none        exit 0

which is exactly what a clean triage of a quiet host looks like. Nothing on the
screen, in run-summary.txt, or in the exit code says the archive was truncated.
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

import pytest

from artifact_engine.core import extractor as E


def _result(name: str, dest: Path, **kw) -> E.ExtractResult:
    return E.ExtractResult(archive=Path(name), dest=dest, ok=kw.pop("ok", True), **kw)


# --------------------------------------------------------------------------- #
# What counts as incomplete
# --------------------------------------------------------------------------- #
def test_a_partial_or_failed_archive_is_incomplete(tmp_path):
    rows = E.incomplete_acquisitions([
        _result("whole.tar.gz", tmp_path),
        _result("cut.tar.gz", tmp_path, partial=True, warnings=True,
                warning_detail="unexpected end of data"),
        _result("broken.zip", tmp_path, ok=False, error="rc=2: not an archive"),
    ])
    assert [(r["archive"], r["status"]) for r in rows] == [
        ("cut.tar.gz", "partial"), ("broken.zip", "failed")]
    assert rows[0]["detail"] == "unexpected end of data"


def test_a_warning_alone_is_not_a_hole(tmp_path):
    """7-Zip finishing the job with complaints is a different claim, and a signal
    that also fires on the ordinary case stops being read at all."""
    assert E.incomplete_acquisitions([
        _result("noisy.tar.gz", tmp_path, warnings=True,
                warning_detail="cannot set modification time")]) == []


# --------------------------------------------------------------------------- #
# Surviving the re-run
# --------------------------------------------------------------------------- #
def test_the_news_survives_the_next_run(tmp_path):
    """Extraction is the one phase a later run does not repeat -- the marker
    short-circuits it. So a truncated acquisition that is only reported by the run
    that extracted it is reported once, on the day nobody was reading, and never
    again for the rest of the case."""
    dest = tmp_path / "HOST-01"
    dest.mkdir()
    E._mark_done(dest / E.MARKER, E.EXTRACT_PARTIAL, "unexpected end of data")

    again = E._extract_one(tmp_path / "HOST-01.tar.gz", dest, seven=None)
    assert again.ok and again.partial
    assert again.warning_detail == "unexpected end of data"
    assert E.incomplete_acquisitions([again])[0]["status"] == "partial"


def test_a_marker_from_before_this_existed_still_means_ok(tmp_path):
    """Every case already on disk carries the one-word marker. Reading those as
    anything but a clean extraction would flag every finished case in the
    archive."""
    dest = tmp_path / "HOST-01"
    dest.mkdir()
    (dest / E.MARKER).write_text("ok", encoding="utf-8")

    assert E.read_marker(dest) == ("ok", "")
    r = E._extract_one(tmp_path / "HOST-01.tar.gz", dest, seven=None)
    assert r.ok and not r.partial and not r.warnings


def test_an_unmarked_destination_reads_as_unknown(tmp_path):
    assert E.read_marker(tmp_path / "nope") == ("", "")


# --------------------------------------------------------------------------- #
# Where it has to show up
# --------------------------------------------------------------------------- #
@pytest.fixture
def summary_root(tmp_path) -> Path:
    from artifact_engine.core import report
    report.build_run_summary(tmp_path, [], incomplete=[
        {"archive": "HOST-01.tar.gz", "status": "partial",
         "detail": "unexpected end of data"}])
    return tmp_path


def test_the_run_summary_says_the_counts_cannot_be_read_at_face_value(summary_root):
    text = (summary_root / "run-summary.txt").read_text(encoding="utf-8")
    assert "HOST-01.tar.gz: partial" in text
    assert "did NOT extract whole: 1" in text
    assert "not a finding about the machine" in text


def test_a_clean_run_says_so_rather_than_staying_silent(tmp_path):
    """Absence of a warning is not the same as a stated all-clear -- the second
    one survives being read months later by somebody who does not know which
    version of the tool wrote the file."""
    from artifact_engine.core import report
    report.build_run_summary(tmp_path, [])
    assert "did NOT extract whole: none" in \
        (tmp_path / "run-summary.txt").read_text(encoding="utf-8")


def test_the_summary_json_carries_it_too(summary_root):
    import json
    data = json.loads((summary_root / "run-summary.json").read_text(encoding="utf-8"))
    assert data["incomplete_acquisitions"][0]["archive"] == "HOST-01.tar.gz"


# --------------------------------------------------------------------------- #
# Exit code
# --------------------------------------------------------------------------- #
def test_a_truncated_acquisition_does_not_exit_clean(tmp_path, monkeypatch, caplog):
    """A script chaining off a triage cannot see a console warning. If the exit
    code is 0, whatever runs next has been told the case was triaged whole."""
    from artifact_engine import cli
    from artifact_engine.core import report

    monkeypatch.setattr(
        report, "build_run_summary",
        lambda r, x, incomplete=None: {"machines": 0, "per_machine": [],
                                       "totals": {"ok": 2, "skipped": 37, "errors": 0}})
    monkeypatch.setattr(E, "extract_all", lambda *a, **k: [
        _result("HOST-01.tar.gz", tmp_path, partial=True, warnings=True,
                warning_detail="unexpected end of data")])

    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)
    with caplog.at_level(logging.WARNING, logger="aeng"):
        rc = cli.cmd_run(args)

    assert rc == cli.EXIT_INCOMPLETE == 2
    said = " ".join(r.message for r in caplog.records)
    assert "did NOT extract whole" in said and "HOST-01.tar.gz" in said


def test_a_whole_acquisition_still_exits_clean(tmp_path, monkeypatch):
    from artifact_engine import cli
    from artifact_engine.core import report

    monkeypatch.setattr(
        report, "build_run_summary",
        lambda r, x, incomplete=None: {"machines": 0, "per_machine": [],
                                       "totals": {"ok": 2, "skipped": 37, "errors": 0}})
    monkeypatch.setattr(E, "extract_all",
                        lambda *a, **k: [_result("HOST-01.tar.gz", tmp_path)])

    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)
    assert cli.cmd_run(args) == 0
