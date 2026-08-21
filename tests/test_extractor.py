import io
import os
import tarfile
import zipfile

from artifact_engine.core import extractor


def _make_zip(path, files: dict[str, bytes]):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)


def test_extract_zip(tmp_path):
    z = tmp_path / "evidence.zip"
    _make_zip(z, {"a.txt": b"hello", "sub/b.txt": b"world"})

    results = extractor.extract_all(tmp_path)

    out = tmp_path / "evidence"
    assert out.is_dir()
    assert (out / "a.txt").read_bytes() == b"hello"
    assert (out / "sub" / "b.txt").read_bytes() == b"world"
    assert any(r.dest == out and r.ok for r in results)


def test_extract_targz_single_pass(tmp_path):
    t = tmp_path / "linux.tar.gz"
    with tarfile.open(t, "w:gz") as tf:
        info = tarfile.TarInfo("uac.log")
        payload = b"log"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    extractor.extract_all(tmp_path)

    out = tmp_path / "linux"  # .tar.gz -> no double extension
    assert (out / "uac.log").read_bytes() == b"log"


def test_double_zip_wrapper_extracted(tmp_path):
    """Zip inside zip (direct wrapper, e.g. double-compressed KAPE): IS recursed."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("deep.txt", b"deep")
    outer = tmp_path / "outer.zip"
    _make_zip(outer, {"inner.zip": inner.getvalue()})

    extractor.extract_all(tmp_path)

    assert (tmp_path / "outer" / "inner" / "deep.txt").read_bytes() == b"deep"


def test_container_in_subfolder_not_recursed(tmp_path):
    """A container in a subfolder (e.g. Velociraptor/LiveResponse.zip) is NOT extracted."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("x.txt", b"x")
    outer = tmp_path / "outer.zip"
    _make_zip(outer, {"sub/inner.zip": inner.getvalue()})

    extractor.extract_all(tmp_path)

    assert (tmp_path / "outer" / "sub" / "inner.zip").is_file()    # present
    assert not (tmp_path / "outer" / "sub" / "inner").exists()     # NOT extracted


def test_loose_gz_not_extracted(tmp_path):
    """Standalone .gz (rotated logs, dumps) are left compressed."""
    import gzip
    t = tmp_path / "uac.tar.gz"
    with tarfile.open(t, "w:gz") as tf:
        payload = gzip.compress(b"rotated log")
        info = tarfile.TarInfo("var/log/syslog.2.gz")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    extractor.extract_all(tmp_path)
    out = tmp_path / "uac"

    assert (out / "var" / "log" / "syslog.2.gz").is_file()   # still compressed
    assert not (out / "var" / "log" / "syslog.2").exists()   # not extracted


def test_zip_path_traversal_blocked(tmp_path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../escape.txt", b"pwned")

    extractor.extract_all(tmp_path)

    # Must not have written outside the destination
    assert not (tmp_path / "escape.txt").exists()


def test_tar_sanitizes_illegal_names(tmp_path):
    """Linux names with ':' (illegal on NTFS) must be extracted sanitized, not skipped."""
    t = tmp_path / "linux.tar.gz"
    with tarfile.open(t, "w:gz") as tf:
        for name in ["etc/0:role.xml", "etc/normal.txt"]:
            payload = b"x"
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))

    extractor.extract_all(tmp_path)
    out = tmp_path / "linux"

    assert (out / "etc" / "normal.txt").read_bytes() == b"x"
    if os.name == "nt":
        assert (out / "etc" / "0_role.xml").read_bytes() == b"x"
    else:
        assert (out / "etc" / "0:role.xml").read_bytes() == b"x"


def test_idempotent_skip(tmp_path):
    z = tmp_path / "e.zip"
    _make_zip(z, {"a.txt": b"x"})
    extractor.extract_all(tmp_path)
    # Second pass: the destination exists and is not re-extracted (no error)
    extractor.extract_all(tmp_path)
    assert (tmp_path / "e" / "a.txt").read_bytes() == b"x"


def test_extract_drops_weblogs_and_fortigate(tmp_path):
    """Archives INSIDE a loose-drop folder (weblogs/fortigate, exports named any
    which way) are extracted in place, one nested level deep; standalone .gz
    stays compressed."""
    import gzip
    drop = tmp_path / "weblogs-cliente"
    drop.mkdir()
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("access.log", b"clf line\n")
    _make_zip(drop / "logs_marzo.zip",                       # arbitrary export name
              {"www/x.log": b"log\n", "wrapped.zip": inner.getvalue()})
    (drop / "access.log.2.gz").write_bytes(gzip.compress(b"rotated\n"))
    fg = tmp_path / "fortigate-fw01"
    fg.mkdir()
    _make_zip(fg / "EXPORT_fw.zip", {"fw.log": b"date=2019-01-01 logid=1\n"})
    (tmp_path / "otradir").mkdir()
    _make_zip(tmp_path / "otradir" / "n.zip", {"y.txt": b"y"})   # outside a drop: untouched

    results = extractor.extract_drops(tmp_path)
    assert all(r.ok for r in results) and len(results) == 3      # export + wrapped + fw

    assert (drop / "logs_marzo" / "www" / "x.log").read_bytes() == b"log\n"
    assert (drop / "logs_marzo" / "wrapped" / "access.log").read_bytes() == b"clf line\n"
    assert (drop / "access.log.2.gz").is_file()                  # .gz rotation untouched
    assert (fg / "EXPORT_fw" / "fw.log").is_file()               # fortigate drop too
    assert not (tmp_path / "otradir" / "n").exists()             # non-drop dir untouched

    # idempotent: second pass extracts nothing new
    assert all(r.ok for r in extractor.extract_drops(tmp_path))


def test_extract_drops_zipped_evtx_drop(tmp_path):
    """An `evtx[-label]` drop gets the same treatment as the other kinds: colleagues
    hand event logs over zipped, and without this the folder would detect as a
    machine with no `*.evtx` to stage -- so the whole toolchain would parse nothing."""
    drop = tmp_path / "evtx-dc01"
    drop.mkdir()
    _make_zip(drop / "eventlogs.zip",
              {"Security.evtx": b"ElfFile\x00", "sub/System.evtx": b"ElfFile\x00"})

    results = extractor.extract_drops(tmp_path)
    assert len(results) == 1 and results[0].ok
    staged = {p.name for p in (drop / "eventlogs").rglob("*.evtx")}
    assert staged == {"Security.evtx", "System.evtx"}   # ready for prepare_evtx_drops


def test_extract_drops_root_is_the_drop(tmp_path):
    """`-p` pointing AT the drop folder itself: detection matches the root as a
    machine, so extraction must treat the root as a drop too. Numeric suffixes
    without separator (weblogs1) count as sub-drops as well."""
    root = tmp_path / "weblogs"
    (root / "weblogs1").mkdir(parents=True)
    (root / "weblogs2").mkdir()
    _make_zip(root / "weblogs1" / "srv1.zip", {"access.log": b"a\n"})
    _make_zip(root / "weblogs2" / "srv2.zip", {"access.log": b"b\n"})

    results = extractor.extract_drops(root)
    assert len(results) == 2 and all(r.ok for r in results)
    assert (root / "weblogs1" / "srv1" / "access.log").read_bytes() == b"a\n"
    assert (root / "weblogs2" / "srv2" / "access.log").read_bytes() == b"b\n"


def _parsed_tree(dest, volume=None):
    """A destination as it looks after a full run: evidence + the analyst's output."""
    base = dest / volume if volume else dest
    (base / "CSVs" / "EventLogs").mkdir(parents=True)
    (base / "CSVs" / "EventLogs" / "auth.csv").write_text("timestamp,event\n", encoding="utf-8")
    (base / "report.txt").write_text("Artifact Engine - Machine report\n", encoding="utf-8")
    (dest / "evidence.txt").write_text("original", encoding="utf-8")


def test_a_parsed_destination_is_adopted_not_re_extracted(tmp_path):
    """The results live INSIDE the extracted tree. A destination that already holds
    them is finished work: re-extracting is at best wasted, and the 7-Zip retry
    path used to clear the destination first -- taking the case with it. Marker-less
    destinations exist in the wild (extracted before the marker, or it was lost)."""
    z = tmp_path / "MACHINE01_kape.zip"
    _make_zip(z, {"C/Windows/System32/config/SYSTEM": b"hive"})
    dest = tmp_path / "MACHINE01_kape"
    dest.mkdir()
    _parsed_tree(dest, volume="C")            # KAPE shape: outputs one level down
    assert not (dest / extractor.MARKER).exists()

    results = extractor.extract_all(tmp_path)

    assert all(r.ok for r in results)
    assert (dest / "C" / "CSVs" / "EventLogs" / "auth.csv").is_file()   # kept
    assert (dest / "C" / "report.txt").is_file()
    assert not (dest / "C" / "Windows").exists()      # NOT re-extracted over
    assert (dest / extractor.MARKER).is_file()        # and marked, so no next time


def test_a_failed_extraction_never_clears_a_destination_holding_results(tmp_path, monkeypatch):
    """`_clear_dir` exists so 7-Zip starts clean after a PARTIAL extraction. Run
    against a destination that already holds a parsed case it deletes the evidence
    tree and every result under it."""
    z = tmp_path / "uac-host-linux-20260101.tar.gz"
    with tarfile.open(z, "w:gz") as tf:
        info = tarfile.TarInfo("[root]/etc/hostname")
        data = b"host\n"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    dest = tmp_path / "uac-host-linux-20260101"
    dest.mkdir()
    _parsed_tree(dest)                        # UAC shape: outputs at the root
    (dest / "host.db").write_bytes(b"SQLite format 3\x00")

    # force the native path to fail so the 7-Zip retry (and its clear) is taken
    def boom(*a, **kw):
        raise RuntimeError("simulated tar failure")

    monkeypatch.setattr(extractor, "_extract_tar", boom)
    monkeypatch.setattr(extractor, "find_7z", lambda *a, **kw: tmp_path / "7z.exe")
    monkeypatch.setattr(extractor, "_extract_with_7z",
                        lambda seven, path, d: (False, ""))
    cleared: list = []
    monkeypatch.setattr(extractor, "_clear_dir", lambda d: cleared.append(d))

    extractor.extract_all(tmp_path)

    assert cleared == []                                        # refused
    assert (dest / "CSVs" / "EventLogs" / "auth.csv").is_file()  # survived
    assert (dest / "host.db").is_file()
    assert (dest / "evidence.txt").read_text(encoding="utf-8") == "original"


def test_a_failed_extraction_still_clears_a_scratch_destination(tmp_path, monkeypatch):
    """The other side of the trade: a half-extracted destination with no results in
    it is scratch space, and 7-Zip must still get a clean slate."""
    z = tmp_path / "wrapper.zip"
    _make_zip(z, {"a.txt": b"x"})
    dest = tmp_path / "wrapper"
    dest.mkdir()
    (dest / "half-extracted.bin").write_bytes(b"\x00" * 8)

    monkeypatch.setattr(extractor, "_extract_zip",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(extractor, "find_7z", lambda *a, **kw: tmp_path / "7z.exe")
    monkeypatch.setattr(extractor, "_extract_with_7z", lambda seven, path, d: (False, ""))
    cleared: list = []
    monkeypatch.setattr(extractor, "_clear_dir", lambda d: cleared.append(d))

    extractor.extract_all(tmp_path)
    assert cleared == [dest]
