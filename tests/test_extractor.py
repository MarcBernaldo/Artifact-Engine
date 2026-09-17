import io
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

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


# --------------------------------------------------------------------------- #
# Names that differ only in case
# --------------------------------------------------------------------------- #
r"""An acquisition from a case-sensitive host can hold `etc/Config` and
`etc/config`. On NTFS those are one path, and extracting both used to leave a
single file carrying the FIRST member's name and the SECOND member's content --
a file whose hash matches neither of the two that were on the host, reported as
a clean extraction.

These tests pin the behaviour on BOTH kinds of filesystem, because the right
answer genuinely differs: where both names can coexist nothing is lost and
nothing should be reported.
"""


def _tar_with(path, members: dict[str, bytes]):
    with tarfile.open(path, "w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _files_under(root):
    # os.walk, not rglob: before 3.12, Windows pathlib de-duplicates paths by
    # `.lower()`, which merges the Kelvin sign with `k` and hides one of the files.
    out = {}
    for here, _dirs, files in os.walk(root):
        for f in files:
            p = Path(here, f)
            out[p.relative_to(root).as_posix()] = p.read_bytes()
    return out


def test_no_file_ever_carries_one_members_name_and_anothers_content(tmp_path):
    """The invariant that holds on every filesystem, and the one that was broken.

    Whatever the destination does about case, a file on disk must be exactly one
    archive member. Anything else is a hash that matches nothing.
    """
    t = tmp_path / "acq.tar"
    _tar_with(t, {"etc/Config": b"FIRST", "etc/config": b"SECOND", "etc/x": b"X"})
    dest = tmp_path / "out"
    dest.mkdir()

    _san, _sk, collisions = extractor._extract_tar(t, dest)

    files = _files_under(dest)
    for name, body in files.items():
        assert body in (b"FIRST", b"SECOND", b"X"), f"{name} holds spliced content"
    # Every member is either on disk or named in the collisions. Nothing vanishes
    # without being counted -- which is the whole point.
    assert len(files) + len(collisions) == 3


def test_a_case_insensitive_destination_keeps_the_first_and_says_so(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    if not extractor._case_insensitive(dest):
        pytest.skip("this destination can hold both names; see the sibling test")

    t = tmp_path / "acq.tar"
    _tar_with(t, {"etc/Config": b"FIRST", "etc/config": b"SECOND"})
    _san, _sk, collisions = extractor._extract_tar(t, dest)

    assert _files_under(dest) == {"etc/Config": b"FIRST"}
    assert len(collisions) == 1
    assert "etc/config" in collisions[0] and "etc/Config" in collisions[0]


def test_a_case_sensitive_destination_extracts_both_and_reports_nothing(tmp_path):
    """Where nothing is lost, nothing is reported. A signal that fires on the
    ordinary case stops being read."""
    dest = tmp_path / "out"
    dest.mkdir()
    if extractor._case_insensitive(dest):
        pytest.skip("this destination folds case; see the sibling test")

    t = tmp_path / "acq.tar"
    _tar_with(t, {"etc/Config": b"FIRST", "etc/config": b"SECOND"})
    _san, _sk, collisions = extractor._extract_tar(t, dest)

    assert _files_under(dest) == {"etc/Config": b"FIRST", "etc/config": b"SECOND"}
    assert collisions == []


def test_an_exact_duplicate_member_is_caught_on_any_filesystem(tmp_path):
    """Two members with the identical name clobber on every filesystem there is,
    so this half of the check is not case-dependent at all."""
    t = tmp_path / "acq.tar"
    with tarfile.open(t, "w") as tf:
        for body in (b"FIRST", b"SECOND"):
            info = tarfile.TarInfo("etc/same")
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    dest = tmp_path / "out"
    dest.mkdir()

    _san, _sk, collisions = extractor._extract_tar(t, dest)

    assert _files_under(dest) == {"etc/same": b"FIRST"}
    assert len(collisions) == 1


# Pairs NTFS was measured on (v0.7.73). `str.casefold()` merges every one of
# them; NTFS keeps all but the last apart. The names are built from code points
# so the file says exactly which characters are meant.
_UNICODE_PAIRS = [
    ("stra\u00dfe", "STRASSE"),          # sharp s / SS
    ("\u212aey", "key"),                 # Kelvin sign / k
    ("mi\u017fc", "misc"),               # long s / s
    ("caf\u00e9", "CAF\u00c9"),          # e acute / E acute: one name on NTFS
    ("x\u1f80", "x\u1f88"),              # Greek with ypogegrammeni / its titlecase:
]                                        # one name on NTFS, two-char upper() in Python


def _holds_both(d, a, b):
    """Ask the filesystem itself whether `a` and `b` are two names there."""
    d.mkdir()
    (d / a).write_bytes(b"")
    (d / b).write_bytes(b"")
    return len(list(d.iterdir())) == 2


def test_names_are_one_only_when_the_filesystem_says_so(tmp_path):
    """Whether two members collide is the destination's answer, not Python's.

    Until v0.7.73 names were compared with `casefold()`, so on NTFS `straße` and
    `STRASSE` -- two files there -- lost one of them and the acquisition was
    called partial. The expectation is read off the filesystem per pair, so this
    holds on any destination, folding or not.
    """
    members, expected = {}, {}
    for i, (a, b) in enumerate(_UNICODE_PAIRS):
        both = _holds_both(tmp_path / f"probe{i}", a, b)
        members[f"p{i}/{a}"] = f"{i}A".encode()
        members[f"p{i}/{b}"] = f"{i}B".encode()
        expected[f"p{i}/{a}"] = f"{i}A".encode()
        if both:
            expected[f"p{i}/{b}"] = f"{i}B".encode()
    t = tmp_path / "acq.tar"
    _tar_with(t, members)
    dest = tmp_path / "out"
    dest.mkdir()

    _san, _sk, collisions = extractor._extract_tar(t, dest)

    assert _files_under(dest) == expected
    assert len(collisions) == len(members) - len(expected)


def test_the_py7zr_path_asks_the_filesystem_too(tmp_path):
    """py7zr extracts every accepted member in one call, after all the claims, so
    nothing is on disk yet when the second name of a pair comes up: the answer
    has to come from the probes, not from the tree."""
    py7zr = pytest.importorskip("py7zr")
    dest = tmp_path / "out"
    dest.mkdir()
    if not extractor._case_insensitive(dest):
        pytest.skip("this destination can hold both names")
    merged = not _holds_both(tmp_path / "probe", "caf\u00e9", "CAF\u00c9")

    a = tmp_path / "acq.7z"
    with py7zr.SevenZipFile(a, "w") as zf:
        zf.writestr(b"FIRST", "etc/Config")
        zf.writestr(b"SECOND", "etc/config")
        zf.writestr(b"E1", "caf\u00e9")
        zf.writestr(b"E2", "CAF\u00c9")
        zf.writestr(b"S1", "stra\u00dfe")
        zf.writestr(b"S2", "STRASSE")
    _san, _skipped, collisions = extractor._extract_7z_native(a, dest)

    files = _files_under(dest)
    assert files["etc/Config"] == b"FIRST" and files["caf\u00e9"] == b"E1"
    assert len(collisions) == 1 + merged
    assert len(files) + len(collisions) == 6


def test_the_probe_agrees_with_what_the_filesystem_actually_does(tmp_path):
    """`_case_insensitive` decides whether a member is about to be lost, so it is
    worth pinning against the filesystem itself rather than against `os.name`."""
    (tmp_path / "Probe").write_bytes(b"")
    really_folds = (tmp_path / "probe").exists()
    assert extractor._case_insensitive(tmp_path) is really_folds


def test_the_probe_leaves_nothing_behind(tmp_path):
    before = set(tmp_path.iterdir())
    extractor._case_insensitive(tmp_path)
    assert set(tmp_path.iterdir()) == before


def test_the_fold_probes_leave_nothing_behind(tmp_path):
    """A probe left in the destination would be extracted evidence to the phases
    after this one."""
    dest = tmp_path / "out"
    dest.mkdir()
    claims = extractor._Claims(dest)
    for name in ("caf\u00e9", "CAF\u00c9", "stra\u00dfe", "\u212aey"):
        claims.claim(Path(name), name)
    assert list(dest.iterdir()) == []


def test_a_dropped_member_makes_the_acquisition_partial_and_outlives_the_run(tmp_path):
    """A hole in the tree that announces itself once, in phase 1 of the first run,
    is a hole that announces itself never: extraction is the phase a later run
    does not repeat.

    Built from an exact duplicate name rather than a case pair, on purpose: only
    DETECTION depends on the filesystem, and the reporting this pins does not. A
    duplicate collides everywhere, so this runs on both platforms instead of
    skipping on the one where the marker path matters least.
    """
    t = tmp_path / "acq.tar"
    with tarfile.open(t, "w") as tf:
        for body in (b"FIRST", b"SECOND"):
            info = tarfile.TarInfo("etc/dup")
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    dest = tmp_path / "acq"

    first = extractor._extract_one(t, dest, seven=None)
    assert first.partial and first.collisions
    assert extractor.incomplete_acquisitions([first])[0]["status"] == "partial"

    # Second run: the marker short-circuits extraction, and the news survives.
    again = extractor._extract_one(t, dest, seven=None)
    assert again.partial
    assert extractor.incomplete_acquisitions([again])[0]["status"] == "partial"


def test_a_clean_archive_is_not_reported_as_partial(tmp_path):
    t = tmp_path / "clean.tar"
    _tar_with(t, {"etc/a": b"A", "etc/b": b"B"})
    r = extractor._extract_one(t, tmp_path / "clean", seven=None)
    assert r.ok and not r.partial and r.collisions == []
    assert extractor.incomplete_acquisitions([r]) == []
