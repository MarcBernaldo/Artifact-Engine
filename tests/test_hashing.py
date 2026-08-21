import hashlib

from artifact_engine.core import hashing


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
