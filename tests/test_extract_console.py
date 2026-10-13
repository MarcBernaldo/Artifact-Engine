"""v0.7.123: phase 1 names on the console only what failed or is not whole."""
from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path

from artifact_engine import cli
from artifact_engine.core import extractor
from artifact_engine.core.extractor import ExtractResult


def _zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"hello")


def test_a_second_run_reads_the_marker_and_says_so(tmp_path):
    _zip(tmp_path / "HOST-01.zip")
    first = extractor.extract_all(tmp_path)
    again = extractor.extract_all(tmp_path)
    assert [r.reused for r in first] == [False]
    assert [r.reused for r in again] == [True]


def test_the_console_holds_failures_and_holes_and_the_log_holds_the_rest(tmp_path):
    console, log = io.StringIO(), logging.getLogger("aeng")
    to_console = logging.StreamHandler(console)
    to_file = logging.FileHandler(tmp_path / "aeng-run.log", encoding="utf-8")
    saved = log.level
    log.setLevel(logging.DEBUG)
    log.addHandler(to_console)
    log.addHandler(to_file)
    a = Path("x")
    results = [
        ExtractResult(Path("clean.zip"), a, ok=True),
        ExtractResult(Path("grew.zip"), a, ok=True, warnings=True,
                      warning_detail="data after the end of the payload"),
        ExtractResult(Path("before.zip"), a, ok=True, reused=True),
        ExtractResult(Path("cut.tar.gz"), a, ok=True, warnings=True, partial=True,
                      warning_detail="unexpected end of archive"),
        ExtractResult(Path("broken.7z"), a, ok=False, error="cannot open"),
    ]
    try:
        cli._report_extraction(results, 1.0)
    finally:
        log.removeHandler(to_console)
        log.removeHandler(to_file)
        to_file.close()
        log.setLevel(saved)

    shown = console.getvalue()
    for name in ("clean.zip", "grew.zip", "before.zip"):
        assert name not in shown, shown
    assert "FAILED broken.7z: cannot open" in shown
    assert "INCOMPLETE cut.tar.gz: unexpected end of archive" in shown
    assert "4/5 extracted, 1 by an earlier run, 1 with warnings -> aeng-run.log" in shown

    written = (tmp_path / "aeng-run.log").read_text(encoding="utf-8")
    for name in ("clean.zip", "grew.zip", "before.zip"):
        assert name in written, written
    assert "data after the end of the payload" in written
