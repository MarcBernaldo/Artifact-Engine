"""An acquisition with a hole in it must not read as a clean triage.

The failure this exists for leaves no error anywhere. A tarball cut short
mid-write extracts to a partial tree; a parser whose input was cut out of it
finds nothing, self-gates, and is counted as `skipped` -- the same count an
artifact gets when the machine's distro simply does not have it, while the
parsers whose artifacts survived the cut run normally. The run ends

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
def _one_machine(tmp_path):
    """One triaged machine for the stubs below: `build_run_summary` calls a run
    that detected NO machine incomplete, which is not what these tests are about."""
    from artifact_engine.core.detector import Machine, Volume
    from artifact_engine.core.runner import ParserRun

    m = Machine("HOST-01", "linux", "uac", "linux_uac", tmp_path / "HOST-01", "src",
                [Volume("live", tmp_path / "HOST-01", True)])
    return [(m, [ParserRun("p", "live", "ok", 1.0, "")])]


def test_a_truncated_acquisition_does_not_exit_clean(tmp_path, monkeypatch, caplog):
    """A script chaining off a triage cannot see a console warning. If the exit
    code is 0, whatever runs next has been told the case was triaged whole."""
    from artifact_engine import cli
    from artifact_engine.core import report

    # Delegates, and overrides only the counts this test is about. `status` has
    # to stay the real one: the exit code is derived from it now, so a stub that
    # invented it would be testing the stub.
    _real = report.build_run_summary

    def _counts(r, x, **kw):
        # one machine, so the verdict under test is the ACQUISITION's and not a
        # run that detected nothing, which is incomplete in its own right.
        # `**kw`, not the signature spelled out: a stub that restates it is a
        # stub that fails when a field is added, in a test about something else.
        out = _real(r, x or _one_machine(tmp_path), **kw)
        out["totals"] = {"ok": 2, "cached": 0, "skipped": 37, "errors": 0}
        return out

    monkeypatch.setattr(report, "build_run_summary", _counts)
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

    # Delegates, and overrides only the counts this test is about. `status` has
    # to stay the real one: the exit code is derived from it now, so a stub that
    # invented it would be testing the stub.
    _real = report.build_run_summary

    def _counts(r, x, **kw):
        # one machine, so the verdict under test is the ACQUISITION's and not a
        # run that detected nothing, which is incomplete in its own right.
        # `**kw`, not the signature spelled out: a stub that restates it is a
        # stub that fails when a field is added, in a test about something else.
        out = _real(r, x or _one_machine(tmp_path), **kw)
        out["totals"] = {"ok": 2, "cached": 0, "skipped": 37, "errors": 0}
        return out

    monkeypatch.setattr(report, "build_run_summary", _counts)
    monkeypatch.setattr(E, "extract_all",
                        lambda *a, **k: [_result("HOST-01.tar.gz", tmp_path)])

    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)
    assert cli.cmd_run(args) == 0


# --------------------------------------------------------------------------- #
# Which claim a complaint is making (v0.7.86)
# --------------------------------------------------------------------------- #
# 7-Zip exits 2 -- fatal -- both for an archive cut in half and for a member that
# grew between being listed and being read. The second is the ordinary state of a
# live acquisition. Reading the exit code made the ordinary case say the archive
# had a hole in it, which is this file's own docstring working in reverse: the
# verdict stopped meaning anything because it fired on everything.
_OPEN_FILE = ("There are some data after the end of the payload data : "
              "C\\ProgramData\\Agent\\logs\\agent.lck")
_CUT_SHORT = "Unexpected end of data : uac-HOST-01-linux-20260101000000.tar"


def test_a_file_copied_while_it_was_open_is_not_a_hole_in_the_archive():
    """The one this version exists for. An agent holds a .lck open, the registry
    holds DEFAULT.LOG1, OneDrive holds a .db-wal: the collector copies them and
    7-Zip says it read past the size the archive declared. Every member is on
    disk. Nothing below is reading a fragment."""
    assert E._claim(_OPEN_FILE) == E.EXTRACT_DAMAGED


def test_an_archive_cut_short_is_still_a_hole():
    assert E._claim(_CUT_SHORT) == E.EXTRACT_PARTIAL


def test_a_damaged_nested_container_loses_the_subtree_under_it():
    """The member is on disk and unreadable, and this engine would have recursed
    INTO it -- so everything it held is absent from the tree, which is the one
    claim `partial` makes. Asked of the case where the archiver DID finish, since
    that is the only case where a checksum failure can mean anything smaller."""
    for m in ("Data Error : LiveResponse.zip",
              "Data Error : inner/uac-HOST-01-linux.tar",
              "Data Error : nested.tar.gz"):
        assert E._claim(m, finished=True) == E.EXTRACT_PARTIAL, m


def test_a_damaged_member_nothing_would_have_extracted_costs_that_file_only():
    """A rotated log, a package-database backup, a journal segment: compressed,
    but not a container this engine opens (see CONTAINER_KINDS). A corrupt one is
    one bad file, not a missing subtree -- once the archiver has reached the end
    of the archive, which is what makes "nothing is missing" sayable at all."""
    for m in ("Data Error : [root]/var/log/syslog.1.gz",
              "Data Error : [root]/var/log/journal/seg.xz",
              "Data Error : uac.log"):
        assert E._claim(m, finished=True) == E.EXTRACT_DAMAGED, m


def test_a_truncated_zip_is_not_read_as_a_damaged_member():
    """Found by review, and it is the direction that matters. A cut .zip says
    `Unexpected end of archive` on one line and `CRC Failed : <member>` on
    another -- about the member it was reading when the data ran out. Keep only
    the second and a cut archive describes itself in the words a whole-but-corrupt
    one uses, so the run came out `complete` over an acquisition missing three of
    its eight members."""
    out = ("ERRORS:\nUnexpected end of archive\n"
           "ERROR: CRC Failed : src/file4.bin\n")
    detail = E._seven_errors(out)
    assert "Unexpected end" in detail, (
        "the line that says the archive stopped early must survive the filter; "
        "it carries none of the other keywords")
    assert E._claim(detail) == E.EXTRACT_PARTIAL


def test_a_checksum_failure_is_a_hole_unless_the_archiver_finished():
    """The same sentence, two meanings, and only the exit code separates them: a
    member that failed its checksum in an archive 7-Zip read to the end is a bad
    file, and the identical message under a FATAL exit is the member the data ran
    out on. Unknowable from the text, so the unsafe reading is not assumed --
    which is also what reading it back out of a marker has to do."""
    msg = "Data Error : C/Windows/System32/winevt/Logs/System.evtx"
    assert E._claim(msg, finished=True) == E.EXTRACT_DAMAGED
    assert E._claim(msg) == E.EXTRACT_PARTIAL


def test_a_container_whose_name_holds_a_colon_is_still_a_container_too():
    """A member name may legally contain " : " on Linux. The suffix then lands in
    a part the subject-reader drops, and the claim would fail towards "only a bad
    file" -- the one direction this classification must not fail in."""
    assert E._claim("Data Error : [root]/tmp/collected : final.tar",
                    finished=True) == E.EXTRACT_PARTIAL
    assert E._claim("Data Error : [root]/tmp/final.tar : collected",
                    finished=True) == E.EXTRACT_PARTIAL
    # And the message whose second part is a TARGET rather than a name is still
    # answered before the container test is reached.
    assert E._claim("Dangerous link path was ignored : etc/a.conf : ../b.tar") \
        == E.EXTRACT_WARNED


def test_a_message_nobody_classified_claims_the_worst():
    """The lists are what has been seen on real acquisitions, not everything
    7-Zip can say. An unclassified message is not evidence of a whole archive,
    and a new 7-Zip wording must not quietly downgrade a real hole."""
    assert E._claim("Unsupported compression method : a.bin") == E.EXTRACT_PARTIAL
    assert E._claim("Something nobody has met yet") == E.EXTRACT_PARTIAL


def test_a_fatal_exit_that_said_nothing_claims_the_worst():
    assert E._claim("") == E.EXTRACT_PARTIAL
    assert E._claim("   ") == E.EXTRACT_PARTIAL


def test_a_link_left_out_on_purpose_is_not_a_claim_about_the_tree():
    assert E._claim("Dangerous link path was ignored : etc/a.conf : ../a.conf") \
        == E.EXTRACT_WARNED


def test_the_worst_claim_in_one_detail_is_the_one_that_counts():
    assert E._claim(f"{_OPEN_FILE} | {_CUT_SHORT}") == E.EXTRACT_PARTIAL
    assert E._claim(f"{_CUT_SHORT} | {_OPEN_FILE}") == E.EXTRACT_PARTIAL


def test_a_detail_that_does_not_account_for_the_whole_output_says_so():
    """Found by review. Four messages and a length were a DISPLAY cap and had
    become verdict-bearing: four files open during the collection ahead of a real
    `Unexpected end of data` discarded the one line that mattered, and the result
    was 89 characters -- under any length test, so nothing noticed. The writer
    marks it now, in the text, which is the only part that survives into a
    marker."""
    out = "\n".join([f"ERROR: Data Error : C/a/{i}.lck" for i in range(1, 5)]
                    + ["ERROR: Unexpected end of data : HOST-01.zip"])
    detail = E._seven_errors(out)
    assert detail.endswith(E._CUT_MARK)
    assert E._claim(detail) == E.EXTRACT_PARTIAL
    assert E._claim(detail, finished=True) == E.EXTRACT_PARTIAL


def test_the_mark_survives_the_marker_and_a_length_would_not_have():
    """Found by review: the cap signal used to BE the length, and `read_marker`
    strips the line it reads. A cut landing on a space came back one character
    short of the cap, so the same evidence read as a hole in the run that
    extracted it and as a bad file on every run after it."""
    detail = E._seven_errors("\n".join(
        f"ERROR: Data Error : {'y' * 100}{i}.zip" for i in range(4)))
    assert detail.endswith(E._CUT_MARK)
    assert E._claim(detail.strip()) == E.EXTRACT_PARTIAL
    assert E._claim(f"  {detail}  ".strip()) == E.EXTRACT_PARTIAL


def test_the_name_of_a_member_does_not_decide_the_claim_about_the_archive():
    """Everything past the first ` : ` is a path out of the acquisition. A file
    called `unavailable.log`, or a folder called `cannot open`, would otherwise
    make the ordinary complaint ABOUT that file read as a hole -- this version's
    own noise, back through a filename nobody chose."""
    for name in ("C:/logs/unavailable.log", "C:/cannot open/a.lck",
                 "C:/x/unexpected end of data.txt", "C:/headers error/b.tmp"):
        msg = f"There are some data after the end of the payload data : {name}"
        assert E._claim(msg) == E.EXTRACT_DAMAGED, name


def test_a_detail_that_fits_is_read_message_by_message():
    """The mark is the whole signal, so it must not appear on a detail that says
    everything the output said -- or the commonest real detail on a live
    acquisition would be a hole on its shape alone."""
    detail = E._seven_errors(f"ERROR: {_OPEN_FILE}\n")
    assert not detail.endswith(E._CUT_MARK)
    assert len(detail) <= E._DETAIL_CAP
    assert E._claim(detail) == E.EXTRACT_DAMAGED


# --------------------------------------------------------------------------- #
# A verdict an older engine wrote
# --------------------------------------------------------------------------- #
def test_a_hole_recorded_by_an_older_engine_is_re_read_not_re_extracted(tmp_path):
    """Extraction is the one phase a later run does not repeat, so a verdict in a
    marker outlives the reading that produced it. Without re-reading, every case
    extracted before this version keeps reporting a hole over a lock file for as
    long as the case exists, and the only fix is to delete the tree and extract
    the archive again -- the whole acquisition, to correct a sentence."""
    dest = tmp_path / "HOST-01"
    dest.mkdir()
    E._mark_done(dest / E.MARKER, E.EXTRACT_PARTIAL, _OPEN_FILE)

    assert E.read_marker(dest) == (E.EXTRACT_DAMAGED, _OPEN_FILE)
    r = E._extract_one(tmp_path / "HOST-01.zip", dest, seven=None)
    assert r.ok and r.damaged and not r.partial
    assert E.incomplete_acquisitions([r]) == []
    assert E.damaged_acquisitions([r])[0]["archive"] == "HOST-01.zip"


def test_a_recorded_hole_nobody_can_classify_stays_a_hole(tmp_path):
    """The re-read only ever downgrades what the messages account for. A detail
    written by the collision path or the native tar reader is prose, not a 7-Zip
    message, and those acquisitions really are short."""
    dest = tmp_path / "HOST-02"
    dest.mkdir()
    E._mark_done(dest / E.MARKER, E.EXTRACT_PARTIAL,
                 "2 member(s) dropped: the destination already holds that name")

    assert E.read_marker(dest)[0] == E.EXTRACT_PARTIAL
    assert E._extract_one(tmp_path / "HOST-02.zip", dest, seven=None).partial


def test_a_recorded_warning_is_never_re_read_upwards(tmp_path):
    """A recorded `warnings` was written by a 7-Zip that read the archive to its
    end: there is no hole there to discover, and promoting one would be this
    engine inventing a claim the extraction never made."""
    dest = tmp_path / "HOST-03"
    dest.mkdir()
    E._mark_done(dest / E.MARKER, E.EXTRACT_WARNED, _CUT_SHORT)

    assert E.read_marker(dest) == (E.EXTRACT_WARNED, _CUT_SHORT)
    r = E._extract_one(tmp_path / "HOST-03.zip", dest, seven=None)
    assert r.warnings and not r.partial and not r.damaged


# --------------------------------------------------------------------------- #
# Through 7-Zip itself
# --------------------------------------------------------------------------- #
def _seven_saying(monkeypatch, tmp_path, rc: int, message: str, produce=True):
    def _run(cmd, **kw):
        if produce:
            (tmp_path / "out").mkdir(parents=True, exist_ok=True)
            (tmp_path / "out" / "a.txt").write_text("x", encoding="utf-8")
        return rc, f"ERROR: {message}", ""

    monkeypatch.setattr(E.procs, "run", _run)
    return E._extract_with_7z(tmp_path / "7z.exe", tmp_path / "a.zip", tmp_path / "out")


def test_the_exit_code_does_not_decide_the_claim(tmp_path, monkeypatch):
    """Both of these are rc=2. One acquisition is short and one is not, and the
    old code could not tell them apart because it never read the message."""
    assert _seven_saying(monkeypatch, tmp_path, 2, _OPEN_FILE)[0] == E.EXTRACT_DAMAGED
    assert _seven_saying(monkeypatch, tmp_path, 2, _CUT_SHORT)[0] == E.EXTRACT_PARTIAL


def test_a_damaged_member_is_said_under_the_mild_exit_code_too(tmp_path, monkeypatch):
    assert _seven_saying(monkeypatch, tmp_path, 1, _OPEN_FILE)[0] == E.EXTRACT_DAMAGED
    assert _seven_saying(monkeypatch, tmp_path, 1,
                         "Cannot set modification time")[0] == E.EXTRACT_WARNED


def test_a_fatal_exit_nothing_in_the_output_accounts_for_is_not_a_warning(
        tmp_path, monkeypatch):
    """Found by review. `_claim` can answer `warnings` -- a deliberately skipped
    link says nothing about the tree -- and returning that from the FATAL branch
    put the acquisition in neither list and printed it nowhere. A quiet verdict
    over a fatal extraction is the one outcome this file exists to prevent."""
    status, _ = _seven_saying(
        monkeypatch, tmp_path, 2,
        "Dangerous link path was ignored : etc/a.conf : ../a.conf")
    assert status == E.EXTRACT_PARTIAL


def test_a_recorded_hole_is_never_re_read_below_damaged(tmp_path):
    """Same cause, read from a marker: a recorded `partial` whose detail says
    only that a link was skipped must not come back as a warning, which no list
    in the run summary carries."""
    dest = tmp_path / "HOST-04"
    dest.mkdir()
    E._mark_done(dest / E.MARKER, E.EXTRACT_PARTIAL,
                 "Dangerous link path was ignored : etc/a.conf : ../a.conf")

    assert E.read_marker(dest)[0] == E.EXTRACT_PARTIAL


def test_a_fatal_exit_with_nothing_on_disk_is_still_a_failed_acquisition(
        tmp_path, monkeypatch):
    """Classifying the message must not turn an archive that produced NOTHING
    into a whole tree with a bad file in it."""
    (tmp_path / "out").mkdir()
    with pytest.raises(RuntimeError):
        _seven_saying(monkeypatch, tmp_path, 2, _OPEN_FILE, produce=False)


# --------------------------------------------------------------------------- #
# What the verdict turns on
# --------------------------------------------------------------------------- #
def test_an_acquisition_is_reported_under_one_claim_and_not_two(tmp_path):
    """A result can carry both flags -- a truncated archive that also holds a
    member read past its size. It is short, which is the bigger claim, and
    listing it twice would make the smaller list look like more than it is."""
    both = _result("cut.tar.gz", tmp_path, partial=True, damaged=True, warnings=True,
                   warning_detail=f"{_OPEN_FILE} | {_CUT_SHORT}")
    assert E.incomplete_acquisitions([both])[0]["status"] == "partial"
    assert E.damaged_acquisitions([both]) == []


def test_a_damaged_member_does_not_make_the_run_incomplete(tmp_path):
    """MEASURED on three real cases: of eighteen acquisitions reported as not
    whole, eight were this. One whole case was `incomplete` on nothing else at
    all -- a verdict a script branches on, saying a case was not triaged whole
    because an agent had a log file open during the collection."""
    from artifact_engine.core import report
    out = report.build_run_summary(
        tmp_path, _one_machine(tmp_path),
        damaged=[{"archive": "HOST-01.zip", "status": "damaged",
                  "detail": _OPEN_FILE}])
    assert out["status"] == "complete"
    assert out["damaged_acquisitions"][0]["archive"] == "HOST-01.zip"


def test_the_run_summary_says_which_of_the_two_claims_it_is_making(tmp_path):
    """Printed under the block above it and never merged into it: one says the
    acquisition is short, this one says a named file in it is wrong. A parser over
    a damaged member does not fail -- it reports, and the table it writes carries
    nothing saying the bytes beneath it were already wrong."""
    from artifact_engine.core import report
    report.build_run_summary(tmp_path, _one_machine(tmp_path),
                             damaged=[{"archive": "HOST-01.zip", "status": "damaged",
                                       "detail": _OPEN_FILE}])
    text = (tmp_path / "run-summary.txt").read_text(encoding="utf-8")
    assert "HOST-01.zip: damaged" in text
    assert "not a faithful copy: 1" in text
    assert "extracted WHOLE" in text
    assert "did NOT extract whole: none" in text


def test_a_run_whose_only_complaint_is_an_open_lock_file_exits_clean(
        tmp_path, monkeypatch, caplog):
    """The end of it: a script chaining off the triage is told the case was
    triaged whole, because it was."""
    from artifact_engine import cli
    from artifact_engine.core import report

    _real = report.build_run_summary

    def _counts(r, x, **kw):
        out = _real(r, x or _one_machine(tmp_path), **kw)
        out["totals"] = {"ok": 40, "cached": 0, "skipped": 6, "errors": 0}
        return out

    monkeypatch.setattr(report, "build_run_summary", _counts)
    monkeypatch.setattr(E, "extract_all", lambda *a, **k: [
        _result("HOST-01.zip", tmp_path, damaged=True, warnings=True,
                warning_detail=_OPEN_FILE)])

    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False,
                              force=False)
    with caplog.at_level(logging.INFO, logger="aeng"):
        assert cli.cmd_run(args) == 0
    said = " ".join(r.message for r in caplog.records)
    assert "did NOT extract whole" not in said
    assert "not a faithful copy" in said and "HOST-01.zip" in said
