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
