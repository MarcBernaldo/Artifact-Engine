import gzip
import io
import os
import random
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

    _san, _sk, collisions, _damage = extractor._extract_tar(t, dest)

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
    _san, _sk, collisions, _damage = extractor._extract_tar(t, dest)

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
    _san, _sk, collisions, _damage = extractor._extract_tar(t, dest)

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

    _san, _sk, collisions, _damage = extractor._extract_tar(t, dest)

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

    _san, _sk, collisions, _damage = extractor._extract_tar(t, dest)

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




# --------------------------------------------------------------------------- #
# A tarball that breaks part-way keeps what came before the break
# --------------------------------------------------------------------------- #
_MEMBERS = 400
_SIZE = 4096


def _payload(rng, compressible):
    if not compressible:
        return rng.randbytes(_SIZE)
    words = ("sshd", "session", "opened", "closed", "for", "user", "jdoe", "from", "port")
    text = "".join(f"{rng.randint(0, 99999):05d} {rng.choice(words)} {rng.choice(words)} "
                   f"value={rng.randint(0, 999)}\n" for _ in range(200))
    return text.encode("ascii")[:_SIZE].ljust(_SIZE, b"#")


def _uac_tarball(path, members=_MEMBERS, compressible=False, seed=7, mode="w:gz"):
    """UAC-shaped and seeded, so every run of the suite damages the same bytes.

    Incompressible content is STORED by gzip, not compressed, so a cut lands in the
    middle of the stream but corruption only changes bytes; compressible content is
    what real logs are, and corrupting it breaks the deflate stream itself.
    """
    rng = random.Random(seed)
    with tarfile.open(path, mode) as tf:
        for i in range(members):
            payload = _payload(rng, compressible)
            info = tarfile.TarInfo(f"[root]/var/log/app/file{i:04d}.log")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return path


def _cut(path, fraction):
    with open(path, "r+b") as fh:
        fh.truncate(int(path.stat().st_size * fraction))


def _kept(dest):
    return [p for p in dest.rglob("*") if p.is_file() and not p.name.startswith(".aeng")]


def test_a_truncated_tarball_keeps_everything_before_the_cut(tmp_path):
    """MEASURED on a real case: two damaged UAC tarballs extracted to nothing,
    although 3,273 and 22,919 files were readable before the damage. `getmembers()`
    walked to the damage at the end before writing anything at the start."""
    arc = _uac_tarball(tmp_path / "uac-HOST-01-linux-20260101000000.tar.gz")
    _cut(arc, 0.6)
    dest = tmp_path / "out"

    res = extractor._extract_one(arc, dest, seven=None)

    kept = _kept(dest)
    assert res.ok and res.partial
    assert 0 < len(kept) < _MEMBERS
    assert "damaged" in res.warning_detail and f"{len(kept)} member(s)" in res.warning_detail
    status, detail = extractor.read_marker(dest)
    assert status == extractor.EXTRACT_PARTIAL and "damaged" in detail


def test_no_member_cut_in_half_is_left_on_disk(tmp_path):
    """A file cut short carries a real name over content that matches nothing on
    the host -- worse than a missing file, because it looks whole."""
    arc = _uac_tarball(tmp_path / "a.tar.gz")
    _cut(arc, 0.55)
    dest = tmp_path / "out"

    extractor._extract_one(arc, dest, seven=None)

    sizes = {p.stat().st_size for p in _kept(dest)}
    assert sizes == {_SIZE}


def test_corruption_in_the_middle_is_damage_too(tmp_path):
    """The second real archive was not short, it was corrupt: "invalid block type"."""
    arc = _uac_tarball(tmp_path / "b.tar.gz", compressible=True)
    raw = bytearray(arc.read_bytes())
    mid = len(raw) // 2
    raw[mid:mid + 256] = bytes(256)
    arc.write_bytes(bytes(raw))
    dest = tmp_path / "out"

    res = extractor._extract_one(arc, dest, seven=None)

    assert res.ok and res.partial and 0 < len(_kept(dest)) < _MEMBERS


def test_a_failed_crc_keeps_the_members_and_says_one_of_them_is_bad(tmp_path):
    """Found writing the test above: gzip checks its CRC only at the END, and tar
    stops at its end-of-archive marker without reading that far, so unless the
    stream is read to its last byte nothing complains at all. "Nothing after it"
    would be false; the truth is that some member already on disk is damaged and
    tar cannot say which."""
    arc = _uac_tarball(tmp_path / "crc.tar.gz", members=50)
    raw = bytearray(arc.read_bytes())
    raw[-8:-4] = bytes(b ^ 0xFF for b in raw[-8:-4])      # the gzip trailer's CRC32
    arc.write_bytes(bytes(raw))
    dest = tmp_path / "out"

    res = extractor._extract_one(arc, dest, seven=None)

    assert res.ok and res.partial
    assert len(_kept(dest)) == 50
    assert "CRC" in res.warning_detail and "cannot say which" in res.warning_detail


_ENTRY = 512 + _SIZE  # one member of an uncompressed tar: its header, then its data


@pytest.mark.parametrize("into_header", [0, 300], ids=["between-members", "inside-a-header"])
def test_a_plain_tar_cut_short_is_not_mistaken_for_its_end(tmp_path, into_header):
    """MEASURED: tar ends the member loop cleanly, no exception, when the file stops
    between two members or inside a header -- the same end a whole archive gets."""
    arc = _uac_tarball(tmp_path / "g.tar", mode="w")
    with open(arc, "r+b") as fh:
        fh.truncate(_ENTRY * 100 + into_header)
    dest = tmp_path / "out"

    res = extractor._extract_one(arc, dest, seven=None)

    assert res.ok and res.partial
    assert len(_kept(dest)) == 100
    assert "end-of-archive marker" in res.warning_detail


def test_an_unreadable_header_is_not_the_end_of_the_archive(tmp_path):
    """MEASURED: a corrupt header checksum ends the loop as quietly as a cut."""
    arc = _uac_tarball(tmp_path / "h.tar", mode="w")
    raw = bytearray(arc.read_bytes())
    at = _ENTRY * 150 + 148                                # member 150's checksum field
    raw[at:at + 8] = b"99999999"
    arc.write_bytes(bytes(raw))
    dest = tmp_path / "out"

    res = extractor._extract_one(arc, dest, seven=None)

    assert res.ok and res.partial
    assert len(_kept(dest)) == 150
    assert "header that cannot be read" in res.warning_detail


def test_a_stream_cut_after_its_last_member_is_not_called_whole(tmp_path):
    """Every member came out, but the CRC that would vouch for them is gone."""
    arc = _uac_tarball(tmp_path / "j.tar.gz", members=50)
    with open(arc, "r+b") as fh:
        fh.truncate(arc.stat().st_size - 3)
    dest = tmp_path / "out"

    res = extractor._extract_one(arc, dest, seven=None)

    assert res.ok and res.partial
    assert len(_kept(dest)) == 50
    assert "none of them could be verified" in res.warning_detail


def test_bytes_after_a_whole_gzip_stream_do_not_make_it_partial(tmp_path):
    """gzip reaches them only after the stream's CRC has passed: every member was
    verified, and calling the acquisition partial would be a false alarm."""
    arc = _uac_tarball(tmp_path / "i.tar.gz", members=50)
    arc.write_bytes(arc.read_bytes() + b"JUNK" * 64)
    dest = tmp_path / "out"

    res = extractor._extract_one(arc, dest, seven=None)

    assert res.ok and not res.partial and not res.warnings
    assert len(_kept(dest)) == 50


def test_damage_before_the_first_member_is_still_a_failure(tmp_path):
    """Nothing to keep is not a partial acquisition, and must not read as one."""
    arc = _uac_tarball(tmp_path / "c.tar.gz")
    _cut(arc, 0.001)
    dest = tmp_path / "out"

    res = extractor._extract_one(arc, dest, seven=None)

    assert not res.ok and not res.partial
    assert not (dest / extractor.MARKER).is_file()


def test_an_intact_tarball_is_not_touched_by_any_of_this(tmp_path):
    arc = _uac_tarball(tmp_path / "d.tar.gz", members=50)
    dest = tmp_path / "out"

    res = extractor._extract_one(arc, dest, seven=None)

    assert res.ok and not res.partial and not res.warnings
    assert len(_kept(dest)) == 50


def test_with_a_7zip_the_damaged_tarball_still_goes_to_it(tmp_path, monkeypatch):
    """Never worse than before on a host that has one: the archive is handed to
    7-Zip exactly as it was before streaming existed."""
    arc = _uac_tarball(tmp_path / "e.tar.gz")
    _cut(arc, 0.6)
    dest = tmp_path / "out"
    calls = []

    def _seven(seven, path, out):
        calls.append(path)
        return extractor.EXTRACT_PARTIAL, "7-Zip: unexpected end of archive"

    monkeypatch.setattr(extractor, "_extract_with_7z", _seven)

    res = extractor._extract_one(arc, dest, seven=tmp_path / "7z")

    assert calls == [arc]
    assert res.ok and res.used_7z and res.partial


def test_a_read_error_on_the_source_media_is_not_damage(tmp_path, monkeypatch):
    """The other half of the same distinction, and the one that costs most.

    A share that drops or a sector that will not read raises `OSError` from the
    READ side too. Classified as damage it becomes `partial` IN THE MARKER, and a
    later run short-circuits on that marker: a host fault turns into a permanent
    verdict about the evidence, and the members past it are never extracted by any
    run. Failing loudly leaves no marker, so the next run retries the archive.
    """
    arc = _uac_tarball(tmp_path / "m.tar.gz", members=20)
    dest = tmp_path / "out"
    real_read = gzip.GzipFile.read
    reads = {"n": 0}

    def _flaky(self, size=-1):
        reads["n"] += 1
        if reads["n"] > 40:                      # several members are out by then
            raise OSError(5, "Input/output error")
        return real_read(self, size)

    monkeypatch.setattr(gzip.GzipFile, "read", _flaky)

    res = extractor._extract_one(arc, dest, seven=None)

    assert not res.ok and not res.partial
    assert "Input/output error" in res.error
    # no marker: the next run tries again instead of inheriting this verdict
    assert not (dest / extractor.MARKER).is_file()


def test_a_destination_that_cannot_be_written_is_not_mistaken_for_damage(tmp_path, monkeypatch):
    """A full disk is the HOST failing. Calling it a damaged archive would blame
    the evidence and quietly keep a fraction of it.

    The disk fills PART WAY THROUGH on purpose: with nothing written yet the code
    raises whichever way the error is classified, so a version that read a write
    error as damage passed this test anyway. With ten members already out, that
    version comes back `ok=True, partial=True` over "the archive is damaged".
    """
    arc = _uac_tarball(tmp_path / "f.tar.gz", members=20)
    dest = tmp_path / "out"
    real_open = open
    opened = {"n": 0}

    class _Fills:
        """Writes ten members, then a short write and ENOSPC -- the normal shape."""

        def __init__(self, fh):
            self.fh = fh

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.fh.close()
            return False

        def write(self, data):
            if opened["n"] > 10:
                self.fh.write(data[:100])
                raise OSError(28, "No space left on device")
            self.fh.write(data)

    def _open(file, mode="r", *args, **kwargs):
        fh = real_open(file, mode, *args, **kwargs)
        if mode == "wb" and str(dest) in str(file):
            opened["n"] += 1
            return _Fills(fh)
        return fh

    monkeypatch.setattr(extractor, "open", _open, raising=False)

    res = extractor._extract_one(arc, dest, seven=None)

    assert not res.ok and not res.partial
    assert "No space left" in res.error
    # and the member the disk died on is not left behind under its real name,
    # where phase 0 of the next run would record it as an original
    assert {p.stat().st_size for p in _kept(dest)} == {_SIZE}


# --------------------------------------------------------------------------- #
# What this host cannot do, said before the run rather than during phase 1
# --------------------------------------------------------------------------- #
def test_a_host_with_no_archiver_is_told_what_to_install(monkeypatch, tmp_path):
    """MEASURED: on a host without one, four of eleven acquisitions extracted to
    NOTHING -- an unsupported compression method twice, a corrupt deflate stream,
    a truncated archive. All four were reported as failures rather than parsed as
    clean trees, which is right, and all four were reported halfway through
    extraction, which is too late to act on.

    `aeng setup` cannot fetch this one either: it is an installer, not a release
    asset a parser manifest can declare."""
    monkeypatch.setattr(extractor, "find_7z", lambda *a, **k: None)

    warning = extractor.archiver_warning(tmp_path)

    assert "will not extract AT ALL" in warning
    assert "install 7-Zip" in warning and "tools directory" in warning


def test_an_archiver_in_the_tools_directory_is_enough(tmp_path):
    """Exercises the search itself: a binary the engine was given, with no
    installed 7-Zip and nothing on PATH involved."""
    exe = tmp_path / "7zip" / "7z.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"MZ")

    assert extractor.archiver_warning(tmp_path) == ""


def test_a_host_that_can_hold_a_long_path_says_nothing(tmp_path):
    assert extractor.long_path_warning(tmp_path) == ""


def test_the_long_path_probe_leaves_nothing_behind(tmp_path):
    """It writes into the analyst's case root, so it has to clean up after itself
    whichever way it answers."""
    extractor.long_path_warning(tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_a_host_that_cannot_hold_a_long_path_is_told_what_to_enable(tmp_path, monkeypatch):
    """The failure is not silent today -- extraction reports a failed or partial
    acquisition -- but it lands halfway through phase 1, after the analyst has
    committed to the run, and the fix is a reboot-scale setting."""
    real = Path.mkdir

    def shallow(self, *a, **kw):
        if len(str(self)) > 200:
            raise OSError(206, "path too long")
        return real(self, *a, **kw)

    monkeypatch.setattr(Path, "mkdir", shallow)

    warning = extractor.long_path_warning(tmp_path)

    assert "LongPathsEnabled" in warning
    assert "reboot" in warning


def test_the_long_path_answer_comes_from_writing_not_from_the_registry():
    """`LongPathsEnabled` is one of TWO conditions -- the running executable also
    has to declare `longPathAware` in its manifest -- so a host where the key is
    1 can still fail, and the registry would have said yes."""
    import inspect

    src = inspect.getsource(extractor.long_path_warning)
    body = src.split('"""')[2]
    assert "winreg" not in body and "LongPathsEnabled" not in body.split("return")[0]
    assert ".mkdir(" in body and "write_bytes" in body


def test_both_warnings_come_before_the_work_they_are_about():
    """The whole point of this version: the same two failures were already
    reported loudly, and already too late -- one halfway through extraction, the
    other after phase 0 had hashed the case. Read before the run, an installer
    and a reboot are still cheap."""
    import inspect

    from artifact_engine import cli

    src = inspect.getsource(cli.cmd_run)
    assert src.index("archiver_warning") < src.index("Computing integrity")
    assert src.index("long_path_warning") < src.index("extract_all(")
    # and the archiver line is not then repeated inside phase 1
    assert "warn_archiver=False" in src


# --------------------------------------------------------------------------- #
# The archive the tree came out of, and what has not arrived yet
# --------------------------------------------------------------------------- #
def test_an_archive_that_changed_after_it_was_extracted_is_said_every_run(tmp_path):
    """An upload still running when a run opened it, or a new copy under the same
    name: the tree on disk came out of a different archive. Nothing is extracted
    over it, and the run says so instead of reading it as the same acquisition."""
    z = tmp_path / "HOST-07.zip"
    _make_zip(z, {"a.txt": b"first copy"})
    extractor.extract_all(tmp_path)

    _make_zip(z, {"a.txt": b"first copy", "b.txt": b"the rest of the upload"})
    [r] = extractor.extract_all(tmp_path)

    assert r.partial and "describe the earlier copy" in r.warning_detail
    assert [a["archive"] for a in extractor.incomplete_acquisitions([r])] == ["HOST-07.zip"]
    assert not (tmp_path / "HOST-07" / "b.txt").exists(), "extracted over the earlier tree"


def test_a_marker_from_before_sizes_were_recorded_is_read_as_before(tmp_path):
    z = tmp_path / "HOST-08.zip"
    _make_zip(z, {"a.txt": b"x"})
    dest = tmp_path / "HOST-08"
    dest.mkdir()
    (dest / extractor.MARKER).write_text("ok\n\n", encoding="utf-8")

    [r] = extractor.extract_all(tmp_path)

    assert r.ok and not r.partial and not r.warning_detail


def test_a_detail_with_a_newline_does_not_push_the_size_off_the_marker(tmp_path):
    """The size is the marker's THIRD line, and a detail is built from a member
    name or a filesystem error, either of which can carry a newline. Unflattened
    it would move the size to a line nothing reads, and the archive would stop
    being compared against the one its tree came out of."""
    z = tmp_path / "HOST-10.zip"
    _make_zip(z, {"a.txt": b"x"})
    dest = tmp_path / "HOST-10"
    dest.mkdir()

    extractor._mark_done(dest / extractor.MARKER, extractor.EXTRACT_PARTIAL,
                         "one line\nand another", archive=z)

    assert extractor.recorded_size(dest) == z.stat().st_size
    assert extractor.read_marker(dest) == (extractor.EXTRACT_PARTIAL,
                                           "one line and another")


def test_what_has_not_arrived_is_not_extracted(tmp_path):
    root_zip = tmp_path / "HOST-09.zip"
    _make_zip(root_zip, {"a.txt": b"x"})
    drop = tmp_path / "weblogs-site"
    drop.mkdir()
    drop_zip = drop / "logs.zip"
    _make_zip(drop_zip, {"access.log": b"x"})

    assert extractor.extract_all(tmp_path, hold={root_zip}) == []
    assert extractor.extract_drops(tmp_path, hold={drop_zip}) == []
    assert not (tmp_path / "HOST-09").exists() and not (drop / "logs").exists()


def test_two_archives_that_fold_to_one_destination_are_told_to_rename(tmp_path):
    """`HOST-12.zip` and `HOST-12.7z` both extract to `HOST-12`. The second one
    used to find the first one's marker and be reported as extracted -- a clean
    verdict over an archive nobody opened. It is not a changed upload either, so
    what is said is rename, and NOT delete: the tree belongs to the other one."""
    first = tmp_path / "HOST-12.zip"
    _make_zip(first, {"a.txt": b"x"})
    extractor.extract_all(tmp_path)
    second = tmp_path / "HOST-12.7z"
    _make_zip(second, {"b.txt": b"y"})          # a zip under a .7z name is enough

    results = {r.archive.name: r for r in extractor.extract_all(tmp_path)}

    clash = results["HOST-12.7z"]
    assert clash.partial and "rename" in clash.warning_detail
    assert "delete" not in clash.warning_detail
    assert "HOST-12.zip" in clash.warning_detail
    assert not (tmp_path / "HOST-12" / "b.txt").exists()
    assert results["HOST-12.zip"].ok and not results["HOST-12.zip"].partial


def test_the_marker_records_which_archive_the_tree_came_out_of(tmp_path):
    z = tmp_path / "HOST-13.zip"
    _make_zip(z, {"a.txt": b"x"})

    extractor.extract_all(tmp_path)

    dest = tmp_path / "HOST-13"
    assert extractor.recorded_name(dest) == "HOST-13.zip"
    assert extractor.recorded_size(dest) == z.stat().st_size
    assert extractor.read_marker(dest)[0] == extractor.EXTRACT_OK

