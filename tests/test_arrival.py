"""An archive still being copied must not be opened as if it had arrived.

MEASURED before this existed, on a synthetic acquisition written at 60% of its
length and then whole: with a 7-Zip on the host the zip came out `partial` with 37
of 60 members and the tar.gz with none, and both stayed that way after the copy
finished, because extraction is the phase a later run does not repeat. Phase 0,
append-only, would have kept the hash of the truncated file. Every name below is
invented.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import logging
import os
import zipfile
from pathlib import Path

import pytest

from artifact_engine.core import arrival, extractor, hashing, report


def _zip_bytes(members: int = 60) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(members):
            zf.writestr(f"notes/file{i:03}.txt", os.urandom(4_000))
    return buf.getvalue()


def _seal(archive: Path, whole: bytes, text: str | None = None) -> Path:
    seal = arrival.seal_of(archive)
    body = text if text is not None else f"{hashlib.sha256(whole).hexdigest()}  {archive.name}\n"
    seal.write_text(body, encoding="utf-8")
    return seal


def _later(path: Path, seconds: float) -> float:
    st = path.stat()
    return max(st.st_mtime, st.st_ctime) + seconds


def _traces(root: Path) -> str:
    csv_path = root / hashing.TRACES_CSV
    return csv_path.read_text(encoding="utf-8") if csv_path.is_file() else ""


# --------------------------------------------------------------------------- #
# Sealed
# --------------------------------------------------------------------------- #
def test_a_sealed_archive_cut_short_is_not_opened_and_is_once_it_is_whole(tmp_path):
    whole = _zip_bytes()
    acq = tmp_path / "HOST-01.zip"
    acq.write_bytes(whole[: len(whole) * 6 // 10])
    seal = _seal(acq, whole)

    first = arrival.survey(tmp_path)
    assert [(a.archive.name, a.state) for a in first] == [("HOST-01.zip", arrival.MISMATCH)]
    hold = arrival.held(first)
    assert hold == {acq, seal}
    hashing.generate_traces(tmp_path, hold=hold)
    assert extractor.extract_all(tmp_path, hold=hold) == []
    assert not (tmp_path / "HOST-01").exists()
    assert "HOST-01.zip" not in _traces(tmp_path)

    acq.write_bytes(whole)
    second = arrival.survey(tmp_path)
    assert [a.state for a in second] == [arrival.READY]
    hashing.generate_traces(tmp_path, hold=arrival.held(second), hashed=arrival.hashes(second))
    assert hashlib.sha256(whole).hexdigest() in _traces(tmp_path)
    [result] = extractor.extract_all(tmp_path, hold=arrival.held(second))
    assert result.ok and not result.partial
    assert len(list((tmp_path / "HOST-01" / "notes").iterdir())) == 60
    assert arrival.survey(tmp_path) == [], "an opened archive was asked again"


def test_a_sealed_archive_is_not_read_before_it_settles(tmp_path, monkeypatch):
    """A large upload would otherwise be hashed whole on every pass of the timer."""
    acq = tmp_path / "HOST-02.zip"
    acq.write_bytes(b"x" * 10)
    _seal(acq, b"x" * 10)
    monkeypatch.setattr(hashing, "sha256_file",
                        lambda p: pytest.fail("hashed a file that is still changing"))

    [a] = arrival.survey(tmp_path, settle_seconds=300, now=_later(acq, 10))

    assert a.state == arrival.WAITING


def test_a_seal_that_holds_no_hash_is_not_trusted(tmp_path):
    acq = tmp_path / "HOST-03.zip"
    acq.write_bytes(b"x")
    _seal(acq, b"x", text="pending\n")

    [a] = arrival.survey(tmp_path)

    assert a.state == arrival.MISMATCH and "holds no SHA-256" in a.detail


@pytest.mark.parametrize("form", ["{h}  HOST-04.zip\n", "\ufeff{H} *HOST-04.zip\r\n", "\n{h}\n"])
def test_a_seal_is_read_in_the_forms_tools_write_it(tmp_path, form):
    acq = tmp_path / "HOST-04.zip"
    acq.write_bytes(b"whole")
    digest = hashlib.sha256(b"whole").hexdigest()
    _seal(acq, b"whole", text=form.format(h=digest, H=digest.upper()))

    [a] = arrival.survey(tmp_path)

    assert a.ready and a.sha256 == digest


# --------------------------------------------------------------------------- #
# Settled
# --------------------------------------------------------------------------- #
def test_an_unsealed_archive_waits_until_it_has_been_still(tmp_path):
    acq = tmp_path / "HOST-05.tar.gz"
    acq.write_bytes(b"still arriving")

    [young] = arrival.survey(tmp_path, settle_seconds=300, now=_later(acq, 10))
    [settled] = arrival.survey(tmp_path, settle_seconds=300, now=_later(acq, 301))

    assert young.state == arrival.WAITING and "300 s" in young.detail
    assert settled.ready


def test_with_no_settle_window_an_unsealed_archive_is_opened_at_once(tmp_path):
    (tmp_path / "HOST-06.zip").write_bytes(b"x")

    assert [a.ready for a in arrival.survey(tmp_path)] == [True]


@pytest.mark.parametrize("sealed", [False, True])
def test_with_no_settle_window_a_timestamp_ahead_of_the_clock_is_no_reason_to_wait(
        tmp_path, sealed):
    """MEASURED on Windows under Python 3.10: a file just written carried an mtime
    later than `time.time()` read after it in 452 of 3000 writes, so its age came
    out negative and a run with no settle window left it waiting. A share does the
    same with a file server whose clock runs ahead of this host's."""
    acq = tmp_path / "HOST-09.zip"
    acq.write_bytes(b"x")
    if sealed:
        _seal(acq, b"x")

    [a] = arrival.survey(tmp_path, settle_seconds=0, now=_later(acq, -5))

    assert a.ready


# --------------------------------------------------------------------------- #
# What is asked
# --------------------------------------------------------------------------- #
def _nested_zip(*names: str) -> bytes:
    """A zip holding `names[0]`, which holds `names[1]`, and so on down to a readme."""
    def pack(name: str, payload: bytes) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(name, payload)
        return buf.getvalue()

    data = pack("readme.txt", b"x")
    for name in reversed(names):
        data = pack(name, data)
    return data


def test_what_came_out_of_an_extraction_is_not_asked_again(tmp_path):
    drop = tmp_path / "weblogs-site"
    drop.mkdir()
    logs = drop / "logs.zip"
    logs.write_bytes(_nested_zip("mid.zip", "deep.zip"))

    assert arrival.delivered(tmp_path) == [logs], "a drop-folder archive was not asked"
    extractor.extract_drops(tmp_path)

    # `deep.zip` sits inside an extraction and was never opened itself: it came out
    # of an archive that had arrived, so it is not a delivery.
    assert (drop / "logs" / "mid" / "deep.zip").is_file()
    assert arrival.delivered(tmp_path) == []


# --------------------------------------------------------------------------- #
# What the run says
# --------------------------------------------------------------------------- #
def test_an_archive_not_yet_arrived_keeps_the_run_incomplete_and_is_named(tmp_path):
    waiting = [{"archive": "HOST-07.zip", "status": arrival.WAITING,
                "detail": "changed 3 s ago"}]

    summary = report.build_run_summary(tmp_path, [], waiting=waiting)

    assert summary["status"] == "incomplete"
    assert summary["waiting_acquisitions"] == waiting
    assert "HOST-07.zip" in (tmp_path / "run-summary.txt").read_text(encoding="utf-8")


def test_a_run_leaves_a_half_copied_archive_alone_and_opens_it_once_whole(tmp_path, caplog):
    from artifact_engine import cli

    case = tmp_path / "case"
    case.mkdir()
    whole = _zip_bytes()
    acq = case / "HOST-08.zip"
    acq.write_bytes(whole[: len(whole) // 2])
    _seal(acq, whole)
    args = argparse.Namespace(path=str(case), config=None, verbose=False, force=False)

    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert cli.cmd_run(args) == cli.EXIT_INCOMPLETE
    assert not (case / "HOST-08").exists(), "extracted while it was still arriving"
    assert "HOST-08.zip" not in _traces(case), "hashed while it was still arriving"
    assert "NOT opened yet" in " ".join(r.getMessage() for r in caplog.records)

    acq.write_bytes(whole)
    assert cli.cmd_run(args) == 0
    assert (case / "HOST-08" / extractor.MARKER).is_file()
    assert hashlib.sha256(whole).hexdigest() in _traces(case)
