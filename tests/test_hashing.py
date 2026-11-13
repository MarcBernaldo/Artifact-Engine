import hashlib
from pathlib import Path

from artifact_engine.core import extractor, hashing


def test_a_later_delivery_is_hashed_and_appended(tmp_path):
    """Evidence arriving after the first run used to be skipped entirely: the
    phase bailed out the moment traces.txt existed, so a second delivery got
    extracted and parsed while the custody record still claimed to describe the
    whole case. An incomplete record that does not say so is worse than none."""
    (tmp_path / "first.zip").write_bytes(b"one")
    hashing.generate_traces(tmp_path, operator="jdoe")
    first_txt = (tmp_path / hashing.TRACES_TXT).read_text(encoding="utf-8")

    (tmp_path / "second.zip").write_bytes(b"two")
    added = hashing.generate_traces(tmp_path, operator="jdoe")

    assert [e.rel_path for e in added] == ["second.zip"], "the new original was not hashed"
    csv_txt = (tmp_path / hashing.TRACES_CSV).read_text(encoding="utf-8")
    assert "first.zip" in csv_txt and "second.zip" in csv_txt
    assert csv_txt.count("rel_path,size_bytes") == 1, "header repeated mid-file"

    txt = (tmp_path / hashing.TRACES_TXT).read_text(encoding="utf-8")
    assert txt.startswith(first_txt), "existing custody lines were rewritten"
    assert "Added:" in txt, "the later delivery has no dated section of its own"


def test_nothing_new_leaves_the_record_untouched(tmp_path):
    """Re-running with no new evidence must not append an empty section, and must
    not re-hash what is already recorded."""
    (tmp_path / "eq.zip").write_bytes(b"same")
    hashing.generate_traces(tmp_path, operator="jdoe")
    before = (tmp_path / hashing.TRACES_TXT).read_bytes()

    assert hashing.generate_traces(tmp_path, operator="jdoe") == []
    assert (tmp_path / hashing.TRACES_TXT).read_bytes() == before


def test_generate_traces_creates_files_and_correct_hash(tmp_path):
    f = tmp_path / "EQUIPO01.zip"
    data = b"contenido de evidencia"
    f.write_bytes(data)

    entries = hashing.generate_traces(tmp_path, max_workers=2, operator="tester")

    assert (tmp_path / hashing.TRACES_TXT).is_file()
    assert (tmp_path / hashing.TRACES_CSV).is_file()
    assert len(entries) == 1
    assert entries[0].sha256 == hashlib.sha256(data).hexdigest()
    assert entries[0].rel_path == "EQUIPO01.zip"


def test_generate_traces_is_idempotent(tmp_path):
    (tmp_path / "a.zip").write_bytes(b"a")
    hashing.generate_traces(tmp_path)
    # Second call must not regenerate (traces.txt already exists)
    entries = hashing.generate_traces(tmp_path)
    assert entries == []


def test_traces_skip_output_dirs(tmp_path):
    (tmp_path / "a.zip").write_bytes(b"a")
    csvs = tmp_path / "CSVs"
    csvs.mkdir()
    (csvs / "out.csv").write_text("x")
    entries = hashing.generate_traces(tmp_path)
    rels = {e.rel_path for e in entries}
    assert "a.zip" in rels
    assert all("CSVs" not in r for r in rels)


def test_traces_include_drops_default_hashes_drop_contents(tmp_path):
    (tmp_path / "acq.zip").write_bytes(b"a")
    drop = tmp_path / "weblogs-www.client.com"
    drop.mkdir()
    (drop / "access.log.1").write_text("x")
    (drop / "access.log.2.gz").write_bytes(b"y")
    entries = hashing.generate_traces(tmp_path, operator="t")   # default: include
    rels = {e.rel_path.replace("\\", "/") for e in entries}
    assert "acq.zip" in rels
    assert any("weblogs-www.client.com/access.log" in r for r in rels)


def test_traces_exclude_drops_keeps_root_containers(tmp_path):
    (tmp_path / "acq.zip").write_bytes(b"a")                    # delivered container: always hashed
    drop = tmp_path / "fortigate-fw"
    drop.mkdir()
    (drop / "fw.log").write_text("x")
    (drop / "fw.log.1.gz").write_bytes(b"y")
    entries = hashing.generate_traces(tmp_path, operator="t", include_drops=False)
    rels = {e.rel_path.replace("\\", "/") for e in entries}
    assert "acq.zip" in rels                                    # root container still hashed
    assert not any(r.startswith("fortigate-fw/") for r in rels)  # drop contents skipped


# --------------------------------------------------------------------------- #
# What counts as an original on the SECOND run
# --------------------------------------------------------------------------- #
def _extracted(root, name: str, files: dict[str, bytes]):
    """An extraction destination as phase 1 leaves it: a tree plus its marker."""
    dest = root / name
    for rel, data in files.items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    (dest / extractor.MARKER).write_text("ok\n", encoding="utf-8")
    return dest


def test_an_extracted_tree_is_not_a_new_original(tmp_path):
    """Phase 0 runs before phase 1, so on the first run the case root holds the
    acquisitions and nothing else -- which is the premise the whole phase rests
    on. On the second run the extracted trees are sitting there too.

    MEASURED before this: 21 recorded acquisitions became 120,029 "new
    originals" on the next run, about 50 GB re-hashed, and a custody record
    whose 21 meaningful rows were buried under a hundred thousand derived ones.
    Every one of those files came out of an archive already recorded here.
    """
    (tmp_path / "acq.zip").write_bytes(b"PK\x03\x04original")
    _extracted(tmp_path, "acq", {"etc/passwd": b"x", "var/log/a.log": b"y",
                                 "deep/er/still/z.bin": b"z"})

    entries = hashing.generate_traces(tmp_path, operator="t")

    assert [e.rel_path for e in entries] == ["acq.zip"]


def test_a_failed_extractions_leftovers_are_not_new_originals(tmp_path):
    """A failed extraction never gets the marker (v0.7.128): it keeps its failure
    note instead, and what it left -- plus the outputs parsed over it -- came out
    of an archive already recorded here."""
    (tmp_path / "acq.zip").write_bytes(b"PKoriginal")
    dest = tmp_path / "acq"
    (dest / "C").mkdir(parents=True)
    (dest / "C" / "left.bin").write_bytes(b"x")
    (dest / "C" / "report.txt").write_text("r", encoding="utf-8")
    (dest / extractor.FAILED_NOTE).write_text("rc=2", encoding="utf-8")

    entries = hashing.generate_traces(tmp_path, operator="t")

    assert [e.rel_path for e in entries] == ["acq.zip"]


def test_a_tree_with_no_marker_is_still_hashed(tmp_path):
    """The marker is the only signal that a directory was PRODUCED here. A
    folder of loose evidence the analyst copied in has none, and its custody is
    exactly what this phase exists to record."""
    (tmp_path / "loose").mkdir()
    (tmp_path / "loose" / "image.dd").write_bytes(b"D")

    entries = hashing.generate_traces(tmp_path, operator="t")

    assert [e.rel_path for e in entries] == [str(Path("loose") / "image.dd")]


def test_the_first_run_is_unchanged(tmp_path):
    """Nothing is pruned before phase 1 has run, because no marker exists yet."""
    (tmp_path / "a.zip").write_bytes(b"A")
    (tmp_path / "b.tar.gz").write_bytes(b"B")

    entries = hashing.generate_traces(tmp_path, operator="t")

    assert sorted(e.rel_path for e in entries) == ["a.zip", "b.tar.gz"]


def test_a_second_delivery_beside_an_extracted_one_is_still_recorded(tmp_path):
    """The append-only behaviour this phase was given in v0.7.x has to survive
    the pruning: a new acquisition arriving after the first was extracted is the
    case this is for."""
    (tmp_path / "first.zip").write_bytes(b"1")
    hashing.generate_traces(tmp_path, operator="t")
    _extracted(tmp_path, "first", {"etc/hosts": b"h"})
    (tmp_path / "second.zip").write_bytes(b"2")

    entries = hashing.generate_traces(tmp_path, operator="t")

    assert [e.rel_path for e in entries] == ["second.zip"]


def test_a_file_still_arriving_is_recorded_only_once_it_has_arrived(tmp_path):
    """Append-only is what a custody record must be, and it is also why a file
    hashed mid-copy would stay here under the hash of a truncated file."""
    acq = tmp_path / "HOST-01.zip"
    acq.write_bytes(b"first half")
    assert hashing.generate_traces(tmp_path, hold={acq}) == []

    acq.write_bytes(b"first half, then the rest")
    [entry] = hashing.generate_traces(tmp_path)

    assert entry.sha256 == hashlib.sha256(b"first half, then the rest").hexdigest()


def test_a_hash_computed_to_check_a_seal_is_not_computed_again(tmp_path, monkeypatch):
    """A sealed archive is read whole to check its seal; phase 0 reads the same
    bytes for the custody record. On a delivery of tens of gigabytes that is the
    difference between one pass and two."""
    import pytest

    acq = tmp_path / "HOST-02.zip"
    acq.write_bytes(b"sealed")
    monkeypatch.setattr(hashing, "sha256_file", lambda p: pytest.fail("read a second time"))

    [entry] = hashing.generate_traces(tmp_path, hashed={acq: "ab" * 32})

    assert entry.sha256 == "ab" * 32



def test_the_engines_own_root_outputs_are_not_originals_but_evidence_of_that_name_is(tmp_path):
    """run-summary, stale-outputs and the lateral graph are written at the case
    root AFTER phase 0, so the next run recorded them as new originals (v0.7.124).
    Only at the root: a collected file of the same name inside an acquisition is
    evidence and is hashed."""
    from artifact_engine.core import consolidate

    (tmp_path / "HOST-01.zip").write_bytes(b"a")
    deep = tmp_path / "HOST-01" / "home" / "jdoe"
    deep.mkdir(parents=True)
    from artifact_engine.core import casedb
    names = ["run-summary.json", "run-summary.txt", consolidate.STALE_LIST,
             "lateral_movement.csv", "lateral_movement.html",
             casedb.CASE_DB, casedb.CASE_DB + ".tmp", "case.html", "case.html.tmp"]
    for n in names:
        (tmp_path / n).write_text("x", encoding="utf-8")
        (deep / n).write_text("x", encoding="utf-8")
    rels = {e.rel_path.replace("\\", "/") for e in hashing.generate_traces(tmp_path)}
    assert "HOST-01.zip" in rels
    for n in names:
        assert n not in rels, n
        assert f"HOST-01/home/jdoe/{n}" in rels, n


# --- AE-100: a custody record whose index cannot be used is never started again ---

def _recorded(root: Path) -> tuple[bytes, bytes]:
    return ((root / hashing.TRACES_TXT).read_bytes(), (root / hashing.TRACES_CSV).read_bytes())


def _raises_custody(root: Path) -> str:
    try:
        hashing.generate_traces(root, operator="jdoe")
    except hashing.CustodyError as e:
        return str(e)
    raise AssertionError("an unusable custody index was not an error")


def test_an_index_resaved_with_another_separator_stops_and_writes_nothing(tmp_path):
    """A spreadsheet re-saving traces.csv with ';' left a header with no rel_path
    and no exception: the index read as empty, every original was hashed again and
    both files were opened with "w" -- the record of every earlier delivery gone."""
    (tmp_path / "first.zip").write_bytes(b"one")
    hashing.generate_traces(tmp_path, operator="jdoe")
    csv_path = tmp_path / hashing.TRACES_CSV
    csv_path.write_bytes(csv_path.read_bytes().replace(b",", b";"))
    (tmp_path / "second.zip").write_bytes(b"two")
    before = _recorded(tmp_path)

    assert "rel_path" in _raises_custody(tmp_path)
    assert _recorded(tmp_path) == before, "the custody record was rewritten"


def test_an_empty_or_headerless_index_stops(tmp_path):
    (tmp_path / "first.zip").write_bytes(b"one")
    hashing.generate_traces(tmp_path, operator="jdoe")
    csv_path = tmp_path / hashing.TRACES_CSV
    for body in (b"", b"\r\n"):
        csv_path.write_bytes(body)
        before = _recorded(tmp_path)
        _raises_custody(tmp_path)
        assert _recorded(tmp_path) == before


def test_an_index_saved_with_a_bom_is_still_the_index(tmp_path):
    (tmp_path / "first.zip").write_bytes(b"one")
    hashing.generate_traces(tmp_path, operator="jdoe")
    csv_path = tmp_path / hashing.TRACES_CSV
    csv_path.write_bytes(b"\xef\xbb\xbf" + csv_path.read_bytes())

    assert hashing.generate_traces(tmp_path, operator="jdoe") == [], "re-hashed a recorded original"


def test_a_record_whose_index_is_gone_stops(tmp_path):
    (tmp_path / "first.zip").write_bytes(b"one")
    hashing.generate_traces(tmp_path, operator="jdoe")
    (tmp_path / hashing.TRACES_CSV).unlink()
    txt = (tmp_path / hashing.TRACES_TXT).read_bytes()

    assert hashing.TRACES_CSV in _raises_custody(tmp_path)
    assert (tmp_path / hashing.TRACES_TXT).read_bytes() == txt
    assert not (tmp_path / hashing.TRACES_CSV).exists()


def test_an_index_with_no_rows_yet_is_appended_to_not_restarted(tmp_path):
    """A first run that found nothing to hash left a header-only index; the next
    delivery's lines go after the existing record, not over it."""
    hashing.generate_traces(tmp_path, operator="jdoe")
    txt_path, csv_path = tmp_path / hashing.TRACES_TXT, tmp_path / hashing.TRACES_CSV
    csv_path.write_text("rel_path,size_bytes,sha256\n", encoding="utf-8")
    txt_path.write_text("Opened by jdoe\n", encoding="utf-8")

    (tmp_path / "first.zip").write_bytes(b"one")
    assert len(hashing.generate_traces(tmp_path, operator="jdoe")) == 1

    assert txt_path.read_text(encoding="utf-8").startswith("Opened by jdoe\n")
    csv_txt = csv_path.read_text(encoding="utf-8")
    assert csv_txt.startswith("rel_path,size_bytes,sha256\n") and "first.zip" in csv_txt
    assert csv_txt.count("rel_path,") == 1, "header written again mid-file"


def test_the_run_does_not_start_over_an_unusable_index(tmp_path, monkeypatch):
    import argparse

    from artifact_engine import cli

    (tmp_path / "first.zip").write_bytes(b"one")
    hashing.generate_traces(tmp_path, operator="jdoe")
    (tmp_path / hashing.TRACES_CSV).write_bytes(b"")

    def extract_all(*a, **k):
        raise AssertionError("extraction ran over an unusable custody record")

    monkeypatch.setattr(extractor, "extract_all", extract_all)
    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)
    assert cli.cmd_run(args) == 1


def test_an_index_that_ends_mid_line_gets_its_row_on_a_line_of_its_own(tmp_path):
    """A traces.csv cut short or hand-edited ends without a line break: the first
    appended row was glued onto its last line, and the original that line named
    was hashed again, and given another section, on every later run."""
    (tmp_path / "first.zip").write_bytes(b"one")
    hashing.generate_traces(tmp_path, operator="jdoe")
    csv_path = tmp_path / hashing.TRACES_CSV
    csv_path.write_bytes(csv_path.read_bytes().rstrip(b"\r\n"))

    (tmp_path / "second.zip").write_bytes(b"two")
    assert len(hashing.generate_traces(tmp_path, operator="jdoe")) == 1
    assert hashing.generate_traces(tmp_path, operator="jdoe") == [], \
        "a recorded original was not recognised"


def test_an_index_that_cannot_be_written_leaves_the_record_as_it_was(tmp_path, monkeypatch):
    """A traces.csv open in a spreadsheet that denies writes failed AFTER the txt
    section was in: a section nothing indexed, so the next run wrote it again."""
    import builtins

    (tmp_path / "first.zip").write_bytes(b"one")
    hashing.generate_traces(tmp_path, operator="jdoe")
    (tmp_path / "second.zip").write_bytes(b"two")
    before = _recorded(tmp_path)
    csv_path = tmp_path / hashing.TRACES_CSV
    real_open = builtins.open

    def locked(file, mode="r", *a, **k):
        if Path(file) == csv_path and mode[0] in "aw":
            raise PermissionError(13, "locked by another process")
        return real_open(file, mode, *a, **k)

    monkeypatch.setattr(builtins, "open", locked)
    assert "written" in _raises_custody(tmp_path)
    monkeypatch.undo()
    assert _recorded(tmp_path) == before, "the record moved without its index"


# --- AE-104: an original that cannot be hashed is said, recorded, and tried again ---

def test_a_file_that_cannot_be_read_is_recorded_as_not_hashed_and_the_rest_are(
        tmp_path, monkeypatch):
    """One locked file raised out of the pool: the phase ended with nothing written
    for the files that DID hash."""
    (tmp_path / "first.zip").write_bytes(b"one")
    (tmp_path / "locked.zip").write_bytes(b"two")
    real = hashing.sha256_file

    def locked(p):
        if Path(p).name == "locked.zip":
            raise PermissionError(13, "in use by another process")
        return real(p)

    monkeypatch.setattr(hashing, "sha256_file", locked)
    got = {e.rel_path: e for e in hashing.generate_traces(tmp_path, operator="jdoe")}

    assert not got["first.zip"].error and got["locked.zip"].error
    txt = (tmp_path / hashing.TRACES_TXT).read_text(encoding="utf-8")
    assert "first.zip" in txt and "NOT HASHED" in txt
    csv_txt = (tmp_path / hashing.TRACES_CSV).read_text(encoding="utf-8")
    assert "first.zip" in csv_txt and "locked.zip" not in csv_txt

    monkeypatch.undo()
    [again] = hashing.generate_traces(tmp_path, operator="jdoe")
    assert again.rel_path == "locked.zip" and not again.error, "not tried again"


def test_a_folder_that_cannot_be_listed_is_said_not_skipped(tmp_path, monkeypatch):
    (tmp_path / "first.zip").write_bytes(b"one")
    (tmp_path / "evtx").mkdir()
    (tmp_path / "evtx" / "a.evtx").write_bytes(b"x")
    real = hashing.os.walk

    def walk(top, onerror=None, **kw):
        for dirpath, dirnames, filenames in real(top, onerror=onerror, **kw):
            if Path(dirpath).name == "evtx":
                if onerror:
                    onerror(PermissionError(13, "Access is denied", dirpath))
                continue
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(hashing.os, "walk", walk)
    got = {e.rel_path: e for e in hashing.generate_traces(tmp_path, operator="jdoe")}
    assert "evtx" in got and "not listed" in got["evtx"].error
    assert "NOT HASHED" in (tmp_path / hashing.TRACES_TXT).read_text(encoding="utf-8")



def test_the_run_names_the_originals_it_could_not_hash(tmp_path, monkeypatch):
    import argparse
    import json

    from artifact_engine import cli
    from artifact_engine.core import pipeline

    (tmp_path / "locked.zip").write_bytes(b"two")

    def locked(p):
        raise PermissionError(13, "in use by another process")

    monkeypatch.setattr(hashing, "sha256_file", locked)
    monkeypatch.setattr(extractor, "extract_all", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "detect", lambda *a, **k: [])
    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)
    assert cli.cmd_run(args) == cli.EXIT_INCOMPLETE
    summary = json.loads((tmp_path / "run-summary.json").read_text(encoding="utf-8"))
    assert [a["path"] for a in summary["not_hashed"]] == ["locked.zip"]


def test_a_drop_folder_kept_out_of_custody_is_not_a_gap_when_unlisted(tmp_path, monkeypatch):
    """Found by review: with `traces_include_drops` off, an unlistable folder in a
    drop was reported NOT HASHED on every run, for files the record never takes."""
    (tmp_path / "first.zip").write_bytes(b"one")
    (tmp_path / "evtx1" / "sub").mkdir(parents=True)
    real = hashing.os.walk

    def walk(top, onerror=None, **kw):
        for dirpath, dirnames, filenames in real(top, onerror=onerror, **kw):
            if Path(dirpath).name == "sub":
                onerror(PermissionError(13, "Access is denied", dirpath))
                continue
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(hashing.os, "walk", walk)
    got = hashing.generate_traces(tmp_path, operator="jdoe", include_drops=False)
    assert [e.rel_path for e in got] == ["first.zip"]


def test_a_probe_into_an_unlistable_folder_is_said_not_raised(tmp_path, monkeypatch):
    """Found by review: `is_file()` on a name that IS there in a folder that cannot
    be listed raises instead of answering, and phase 0 aborted."""
    (tmp_path / "first.zip").write_bytes(b"one")
    (tmp_path / "HOST-01").mkdir()
    real = Path.is_file

    def is_file(self):
        if self.parent.name == "HOST-01" and self.name == extractor.MARKER:
            raise PermissionError(13, "Access is denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "is_file", is_file)
    got = {e.rel_path: e for e in hashing.generate_traces(tmp_path, operator="jdoe")}
    assert "HOST-01" in got and "not listed" in got["HOST-01"].error
