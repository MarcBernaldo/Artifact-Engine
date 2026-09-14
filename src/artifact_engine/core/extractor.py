"""Phase 1 - Recursive extraction.

Supports .zip, .tar, .tar.gz/.tgz, .tar.bz2, .tar.xz, .gz (standalone) and .7z.
- tar.gz is extracted in ONE pass (tarfile), avoiding 7zip's two-step process.
- Recursive: extracts nested archives (zip inside zip, etc.).
- Robust on Windows:
    * 7-Zip fallback for methods Python does not support (Deflate64, etc.).
    * sanitizes NTFS-illegal names (: * ? " < > | and control chars), common in
      Linux acquisitions (UAC).
- Safe: blocks path traversal (lexical check) and aborts on zip-bombs.
- Idempotent: marks each completed destination with a sentinel file, so a failed
  or interrupted extraction is retried on the next pass.
- Never destructive to a finished case: the analyst's results live INSIDE the
  extracted tree, so a destination already holding them is adopted (and marked)
  rather than extracted again, and the clear-and-retry-with-7-Zip path refuses to
  run against it. Markerless destinations are real -- they predate the sentinel, or
  lost it -- and without that guard a failed re-extraction takes the evidence tree
  and every CSV/.db/report under it.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from artifact_engine.core import procs
from artifact_engine.logging_setup import get_logger

log = get_logger()

MAX_RATIO = 200                   # suspicious uncompressed/compressed ratio
MAX_TOTAL = 80 * 1024**3          # 80 GiB uncompressed per archive
MARKER = ".aeng_extracted_ok"     # "destination completed" sentinel
# Every member whose name the engine had to change, written beside the tree it
# describes. In the extraction rather than the case root because that is where it
# stays true: a destination adopted by a later run brings its own list with it.
RENAMES = ".aeng_renamed.txt"
# How many of them the CASE LOG carries. The file above holds all of them; a
# filesystem copy full of colons would otherwise push everything else out of the
# log, and the count plus the file is the same information.
_RENAMES_LOGGED = 20

# How an extraction went, as recorded IN the marker. The status has to outlive
# the run that extracted, because the marker short-circuits the work on every
# later run: a partial acquisition that announced itself once, in phase 1 of the
# first run, is a partial acquisition that announces itself never.
#
#   ok        the archive was read whole
#   warnings  the native extractor failed, 7-Zip finished the job with warnings
#   partial   the tree on disk is not the whole archive. Two causes, and the
#             status deliberately does not distinguish them, because what the
#             parsers below are reading is the same either way:
#               - the native extractor failed AND 7-Zip could not finish either;
#                 what is on disk is as much as could be salvaged
#               - members were dropped because the DESTINATION could not hold
#                 their names apart from one already written (`_Claims`) -- two
#                 spellings of one name on a filesystem that folds case, or the
#                 same name twice, which clobbers anywhere
EXTRACT_OK = "ok"
EXTRACT_WARNED = "warnings"
EXTRACT_PARTIAL = "partial"

# Containers that bundle a tree (extracted and recursed into).
# Standalone .gz (rotated logs, .mem.swab.gz dumps) are NOT auto-extracted.
CONTAINER_KINDS = {"zip", "tar", "7z"}

# Velociraptor sub-collections (KAPE side-collects them under <collection>/Velociraptor/).
# They are NOT pulled in by the generic nested-container pass (that one stays narrow
# on purpose). Only LiveResponse is extracted: it holds the volatile/live state nothing
# else captures. QuickTriage.zip is intentionally excluded -- its artifacts (Prefetch,
# Amcache, AppCompat, SRUM, lnk, RecycleBin...) duplicate the dedicated KAPE parsers.
# Add a name here if the collection profile changes.
VELOCIRAPTOR_ZIPS = ("LiveResponse.zip",)


@dataclass
class ExtractResult:
    archive: Path
    dest: Path
    ok: bool
    error: str = ""
    sanitized: int = 0
    skipped: int = 0
    used_7z: bool = False
    warnings: bool = False
    warning_detail: str = ""
    # The tree on disk is not the whole archive. Kept apart from `warnings`
    # because they are different claims: a warning is "something was odd", this
    # is "the parsers below are reading an acquisition with a hole in it".
    partial: bool = False
    # Members dropped because the destination filesystem cannot tell their names
    # apart from one already written (see `_Claims`). A hole in the tree like any
    # other, so it sets `partial` -- but named separately because the cause is the
    # DESTINATION, not the archive, and the same archive on a case-sensitive
    # filesystem extracts whole.
    collisions: list[str] = field(default_factory=list)
    # Members written under a name that is not the one in the archive, as
    # "<in the archive> -> <on disk>". `sanitized` is this list's length; the list
    # itself is what lets an analyst map a path in a table back to the acquisition.
    renamed: list[str] = field(default_factory=list)


_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")

_WIN_ILLEGAL = re.compile(r'[<>:"|?*]')
_CTRL = re.compile(r"[\x00-\x1f]")
_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


# --------------------------------------------------------------------------- #
# Archive type
# --------------------------------------------------------------------------- #
def _kind(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".zip"):
        return "zip"
    if name.endswith(_TAR_SUFFIXES):
        return "tar"
    if name.endswith(".7z"):
        return "7z"
    if name.endswith(".gz"):  # standalone .gz (not tar)
        return "gz"
    return None


def is_archive(path: Path) -> bool:
    return path.is_file() and _kind(path) is not None


def is_container(path: Path) -> bool:
    return path.is_file() and _kind(path) in CONTAINER_KINDS


def _dest_dir(path: Path) -> Path:
    name = path.name
    lower = name.lower()
    for suf in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lower.endswith(suf):
            return path.with_name(name[: -len(suf)])
    return path.with_name(path.stem)


def destination(path: Path) -> Path:
    """Where `path` is (or would be) extracted to."""
    return _dest_dir(path)


# --------------------------------------------------------------------------- #
# Path safety and name sanitization
# --------------------------------------------------------------------------- #
def _sanitize_component(part: str) -> str:
    r"""Clean a path component to the STRICTEST rule, on every host.

    It used to apply the Windows rules only on Windows, which reads like the
    careful thing to do -- why rewrite a name that is legal here? -- and quietly
    cost the one property this engine needs from two platforms: that they extract
    the same tree.

    A Linux acquisition can hold `var/log/app-2026-01-02T03:04:05.log`. Extracted
    on Linux that name survives; extracted on Windows the colon is illegal, so the
    file lands as `...T03_04_05.log`. Every table that carries a path then differs
    between the two hosts for the same archive -- not in a way anyone would notice
    reading one of them, only in a way that makes the two impossible to compare.
    And the same tree on a Windows SMB share is a copy that silently loses files.

    So the answer is the same everywhere, and it is the narrow one: nothing is
    lost, because the rewrite is recorded per member (`_Claims.note_rename`),
    written beside the extraction, and counted in the run summary. The archive
    itself is untouched and was hashed in phase 0.
    """
    s = _CTRL.sub("_", _WIN_ILLEGAL.sub("_", part))
    s = s.rstrip(" .")  # NTFS does not allow trailing space or dot
    if not s:
        return "_"
    if s.split(".")[0].upper() in _RESERVED:
        s = "_" + s
    return s


def _safe_relpath(member: str) -> tuple[Path | None, bool]:
    """Turn a member name into a safe relative path.

    LEXICAL check (does not touch the filesystem): rejects '..' and absolute paths.
    Returns (path|None, sanitized). None => unsafe member, ignore it.
    """
    member = member.replace("\\", "/")
    parts: list[str] = []
    changed = False
    for part in member.split("/"):
        if part in ("", ".", "/"):
            continue
        if part == "..":
            return None, False
        clean = _sanitize_component(part)
        if clean != part:
            changed = True
        parts.append(clean)
    if not parts:
        return None, False
    return Path(*parts), changed


def _case_insensitive(d: Path) -> bool:
    """Whether this destination treats two spellings of a name as one file.

    PROBED, not inferred from the platform. `os.name` is the wrong question: an
    exFAT stick and a macOS volume are case-insensitive under a POSIX host, and a
    Windows directory can carry the per-directory case-sensitivity flag. The
    answer decides whether two archive members are about to become one file, so it
    is worth a single write to measure instead of assume.
    """
    probe = d / ".aeng_case_probe"
    try:
        probe.write_bytes(b"")
        return (d / ".AENG_CASE_PROBE").exists()
    except OSError:
        return os.name == "nt"          # unmeasurable: fall back to the host's usual answer
    finally:
        try:
            probe.unlink()
        except OSError:
            pass


# A KAPE tree routinely reaches this far: `Users/<user>/AppData/Local/Packages/
# <publisher>/LocalState/...` inside a case folder inside an acquisition folder.
# The probe aims past the old limit and stops, rather than looking for the real
# ceiling, which is not a number worth knowing.
_LONG_PATH_TARGET = 300
_LONG_PATH_PROBE = ".aeng_longpath_probe"


def long_path_warning(dest: Path | None = None) -> str:
    """Empty when this host can create a path past the old 260-character limit.

    PROBED, and not read out of `LongPathsEnabled` in the registry, which is the
    obvious way and answers a different question. That key is one of TWO
    conditions: the running executable also has to declare `longPathAware` in its
    manifest, so a host where the key is 1 can still fail on a Python that does
    not declare it, and the registry would have said yes. Making a directory and
    writing a file into it asks the only question that matters.

    It is asked of the DESTINATION, because the answer belongs to the volume and
    the API path that reaches it, not to the machine: a case on a mapped network
    drive or a UNC share can answer differently from `C:`.

    What it costs when the answer is no: extraction fails on the members that are
    too deep -- loudly, as a failed or partial acquisition, so nothing is silent
    about it. But it fails halfway through phase 1, after the analyst has
    committed to the run, and the fix is a reboot-scale setting rather than
    anything the engine can do. That is worth saying first, which is the whole
    point of this function -- the same reasoning as `archiver_warning`.
    """
    root = Path(dest) if dest is not None else Path(tempfile.gettempdir())
    probe = root / _LONG_PATH_PROBE
    deep = probe
    try:
        probe.mkdir(parents=True, exist_ok=True)
        while len(str(deep)) < _LONG_PATH_TARGET:
            deep = deep / ("x" * 40)
            deep.mkdir()
        (deep / "probe.txt").write_bytes(b"")
        return ""
    except OSError:
        return ("[!] this host cannot create paths longer than "
                f"{_LONG_PATH_TARGET} characters: a deep acquisition will not extract "
                "whole. On Windows, enable LongPathsEnabled (Computer Configuration > "
                "Administrative Templates > System > Filesystem > Enable Win32 long "
                "paths) and reboot, or extract the case closer to the drive root")
    finally:
        shutil.rmtree(probe, ignore_errors=True)


class _Claims:
    r"""Which relative paths this extraction has already written.

    An acquisition from a case-sensitive host can legitimately hold `etc/Config`
    and `etc/config`, and on NTFS those are ONE path. Extracting both used to
    leave a single file carrying the FIRST member's name and the SECOND member's
    content -- which is worse than losing one of them, because its hash matches
    neither of the two files that were on the host, and nothing anywhere said so:
    the extraction reported `skipped: 0` and the run reported a clean tree.

    So the second member is dropped rather than written, the first is kept whole,
    and the pair is reported. The archive still holds both and is hashed in phase
    0, so nothing is unrecoverable -- it just stops being silent.

    Keyed by the DESTINATION's own idea of sameness (`_case_insensitive`), which
    is why the same code is right on both platforms: where both names can coexist
    nothing is flagged, because nothing is lost. An exact duplicate member name is
    flagged everywhere, because that one clobbers on any filesystem.
    """

    __slots__ = ("_fold", "_taken", "collisions", "damage", "renames")

    def __init__(self, dest: Path) -> None:
        self._fold = _case_insensitive(dest)
        self._taken: dict[str, str] = {}
        self.collisions: list[str] = []
        self.renames: list[str] = []
        # Set by `_extract_tar` when the archive broke part-way: the one-line
        # detail, empty while the stream was whole.
        self.damage = ""

    def note_rename(self, member: str, rel: Path) -> None:
        """Record that `member` could not be written under its own name.

        Kept in full rather than sampled: a name the engine changed is the kind of
        thing an analyst comes back to months later, asking why a path in a table
        does not match the one in a ticket. The case log gets a sample and the
        whole list is written beside the extraction.
        """
        self.renames.append(f"{member} -> {rel.as_posix()}")

    def claim(self, rel: Path, member: str) -> bool:
        """True if `member` may be written to `rel`; False if something has it."""
        key = rel.as_posix()
        if self._fold:
            key = key.casefold()
        holder = self._taken.get(key)
        if holder is not None:
            self.collisions.append(f"{member} (collides with {holder}, which was kept)")
            return False
        self._taken[key] = member
        return True


def rename_detail(renames: list[str]) -> str:
    """The one-line summary that goes in the marker and the run summary."""
    return (f"{len(renames)} member(s) written under a changed name: the archive "
            f"holds characters no Windows path may carry -- see {RENAMES}")


def _write_renames(dest: Path, renames: list[str]) -> None:
    """The full mapping, beside the tree it describes.

    Best-effort: a destination that cannot take this file is not a reason to fail
    an extraction that otherwise succeeded, and the count still reaches the run
    summary either way.
    """
    header = ("# Members whose names this engine changed, as "
              "<in the archive> -> <on disk>.\n"
              "# The archive is unmodified and was hashed in phase 0.\n")
    try:
        (dest / RENAMES).write_text(header + "\n".join(renames) + "\n", encoding="utf-8")
    except OSError as e:
        log.debug(f"could not write {dest / RENAMES}: {e}")


def collision_detail(collisions: list[str]) -> str:
    """The one-line summary that goes in the marker and the run summary."""
    return (f"{len(collisions)} member(s) dropped: the destination filesystem cannot "
            f"hold names that differ only in case -- see the case log for which")


# --------------------------------------------------------------------------- #
# 7-Zip (fallback)
# --------------------------------------------------------------------------- #
def find_7z(tools_dir: Path | None = None) -> Path | None:
    """A 7-Zip binary, wherever this host keeps one.

    Unlike a parser binary this one MAY come off `PATH`, deliberately: it is a
    decompressor, not something whose version shows up in a result, so the
    audit-trail argument that removed the `PATH` fallback in `core/toolchain` does
    not apply here. Its output is the archive's own bytes, or it is an error.
    """
    cands: list[Path] = []
    if tools_dir:
        cands += [tools_dir / "7zip" / "7z.exe", tools_dir / "7z.exe", tools_dir / "7za.exe"]
    for name in ("7z", "7za", "7zz"):
        w = shutil.which(name)
        if w:
            cands.append(Path(w))
    if os.name == "nt":
        # LAST RESORT, and only where these paths can exist at all. A default
        # install puts 7-Zip here and leaves it off `PATH`, which is common enough
        # to be worth two lines -- but building them on a host with no C: drive is
        # two guaranteed misses dressed up as a search.
        cands += [
            Path(r"C:\Program Files\7-Zip\7z.exe"),
            Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
        ]
    for c in cands:
        if c and c.is_file():
            return c
    return None


def _install_hint() -> str:
    """The package to ask for, named rather than implied.

    "Install 7-Zip" on a Linux box is a sentence the analyst has to translate
    first, and `aeng setup` cannot fetch this one either way: it is a system
    package, not a release asset. A function rather than a constant so both
    answers are reachable from a test on either host.
    """
    if os.name == "nt":
        return "install 7-Zip, or drop 7z.exe into the tools directory"
    return "install the p7zip-full package"


def archiver_warning(tools_dir: Path | None = None) -> str:
    """Empty when a 7-Zip binary is available here; otherwise the line to print.

    MEASURED on a Linux host that had none: four of eleven acquisitions extracted
    to NOTHING -- two using a compression method the built-in readers do not
    implement, one with a corrupt deflate stream, one truncated. All four were
    reported as failed acquisitions rather than parsed as clean trees, which is
    the right failure; all four were reported halfway through extraction, which is
    the wrong moment, after the analyst has committed to the run.

    This is the only tool whose absence costs a WHOLE acquisition, and the only
    one no parser manifest declares -- so `preflight.check`, built from those
    manifests, cannot see it. Hence a function of its own.
    """
    if find_7z(tools_dir):
        return ""
    return ("[!] no 7-Zip binary: an archive using Deflate64 or another method the "
            f"built-in readers do not implement will not extract AT ALL -- {_install_hint()}")


# Generic 7-Zip counters with no useful info (dropped from the warning).
_7Z_NOISE = ("sub items errors", "archives with errors", "files:", "errors:")
_7Z_PREFIX = re.compile(r"^(ERROR|WARNING)\s*:\s*")


def _seven_errors(*streams: str) -> str:
    """Extract the useful error/warning lines from 7-Zip output.

    Keeps the real cause (e.g. 'data after the end of the payload data : <file>')
    and drops the generic counters. Strips the 'ERROR:'/'WARNING:' prefix.
    """
    msgs: list[str] = []
    seen: set[str] = set()
    for s in streams:
        for line in (s or "").splitlines():
            t = line.strip()
            if not t:
                continue
            low = t.lower()
            if not any(k in low for k in ("error", "warning", "cannot", "after the end")):
                continue
            if any(noise in low for noise in _7Z_NOISE):
                continue
            t = _7Z_PREFIX.sub("", t).strip()
            if t and t not in seen:
                seen.add(t)
                msgs.append(t)
    return " | ".join(msgs[:4])[:240]


def _extract_with_7z(seven: Path, path: Path, dest: Path) -> tuple[str, str]:
    """Extract with 7-Zip. Returns (status, detail). Raises on total failure.

    7-Zip rc: 0=ok, 1=warning (non-fatal), 2=fatal. With rc>=2 it often extracts
    almost everything (e.g. minor corruption of one file), so if content was
    produced we keep it rather than discarding the whole acquisition -- but as
    EXTRACT_PARTIAL, not as a warning. The difference decides what the run is
    allowed to say afterwards: a truncated acquisition is the case a parser
    reporting nothing is least able to distinguish from a quiet host.
    """
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [str(seven), "x", "-y", "-bb0", "-bsp0", f"-o{dest}", str(path)]
    rc, out, err = procs.run(cmd)
    detail = _seven_errors(out, err)
    if rc == 0:
        return EXTRACT_OK, ""
    if rc == 1:
        return EXTRACT_WARNED, detail
    if any(dest.iterdir()):
        log.debug(f"7z rc={rc} on {path.name} (partial): {detail}")
        return EXTRACT_PARTIAL, detail
    raise RuntimeError(f"rc={rc}: {detail or '7-Zip failure'}")


# --------------------------------------------------------------------------- #
# Native extractors
# --------------------------------------------------------------------------- #
def _extract_zip(path: Path, dest: Path) -> tuple[int, _Claims]:
    skipped = 0
    claims = _Claims(dest)
    with zipfile.ZipFile(path) as zf:
        comp = sum(i.compress_size for i in zf.infolist()) or 1
        total = sum(i.file_size for i in zf.infolist())
        if total > MAX_TOTAL or (total / comp) > MAX_RATIO:
            raise RuntimeError(f"possible zip-bomb (ratio {int(total / comp)}x, {total} bytes)")
        for info in zf.infolist():
            rel, changed = _safe_relpath(info.filename)
            if rel is None:
                skipped += 1
                continue
            if changed:
                claims.note_rename(info.filename, rel)
            target = dest / rel
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not claims.claim(rel, info.filename):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    return skipped, claims


# What a damaged archive raises while being READ, as distinct from a failure to
# WRITE the destination. Only the read side is damage: a full disk or a refused
# path is the host's problem and has to stay loud.
_STREAM_DAMAGE = (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError, OSError)
_COPY_BUF = 1024 * 1024


class _Damaged(RuntimeError):
    """A tarball that broke part-way, raised only to hand it to 7-Zip."""


def _damage_detail(written: int, error: BaseException) -> str:
    # A gzip CRC failure is found at the END, after every member was read -- so
    # "nothing after it" would be false, and the real news is worse: some member
    # already written holds damaged bytes, and tar keeps no per-member checksum
    # that could say which. Seen with incompressible content, which gzip stores
    # rather than compresses, so corruption changes bytes without breaking the
    # stream.
    if isinstance(error, gzip.BadGzipFile) and "crc" in str(error).lower():
        return (f"the archive failed its CRC check: {written} member(s) extracted, but "
                f"at least one of them holds damaged content and the archive cannot say "
                f"which ({type(error).__name__}: {error})")
    return (f"the archive is damaged: {written} member(s) extracted before the damage "
            f"and nothing after it ({type(error).__name__}: {error})")


def _copy_member(src, target: Path) -> BaseException | None:
    """Copy one member. On a READ failure the partial file is removed and the
    exception returned; a WRITE failure is raised like any other."""
    broken = None
    with src, open(target, "wb") as out:
        while True:
            try:
                chunk = src.read(_COPY_BUF)
            except _STREAM_DAMAGE as e:
                broken = e
                break
            if not chunk:
                return None
            out.write(chunk)
    target.unlink(missing_ok=True)
    return broken


class _WhyTarStopped(tarfile.TarInfo):
    """Remembers the header that ended the member loop, on the archive itself.

    `TarFile.next()` swallows the header error that ends iteration, so a whole
    archive and a broken one end the loop the same way. MEASURED: a plain tar cut
    between two members, one cut inside a header and one with a corrupt header
    checksum all iterate to a clean end with fewer members and no exception."""

    @classmethod
    def fromtarfile(cls, tarfile_):
        try:
            return super().fromtarfile(tarfile_)
        except tarfile.HeaderError as e:
            tarfile_.aeng_stopped_by = e
            raise


def _why_tar_stopped(tf: tarfile.TarFile, written: int) -> str:
    """The damage a clean end of the member loop hides, or "" when there is none."""
    stop = getattr(tf, "aeng_stopped_by", None)
    if isinstance(stop, tarfile.InvalidHeaderError):
        return (f"the archive is damaged: {written} member(s) extracted before a tar "
                f"header that cannot be read, and nothing after it "
                f"({type(stop).__name__}: {stop})")
    if isinstance(stop, (tarfile.EmptyHeaderError, tarfile.TruncatedHeaderError)):
        return (f"the archive is cut short: {written} member(s) extracted, and it ends "
                f"without tar's end-of-archive marker, so whatever followed them is missing")
    if not isinstance(tf.fileobj, (gzip.GzipFile, bz2.BZ2File, lzma.LZMAFile)):
        return ""
    # A normal end. The compressed stream is still read to its last byte, because
    # that is where gzip keeps the CRC, and tar stops at its end-of-archive marker
    # without reading that far. On a whole archive what is left is a few blocks of
    # padding, so this costs nothing.
    try:
        while tf.fileobj.read(_COPY_BUF):
            pass
    except _STREAM_DAMAGE as e:
        text = str(e).lower()
        if isinstance(e, gzip.BadGzipFile) and "not a gzipped file" in text:
            return ""  # bytes after a stream whose CRC had already passed
        if isinstance(e, gzip.BadGzipFile) and "crc" in text:
            return _damage_detail(written, e)
        return (f"the archive is damaged past its last member: {written} member(s) "
                f"extracted, but the stream breaks before its checksum, so none of them "
                f"could be verified ({type(e).__name__}: {e})")
    return ""


def _extract_tar(path: Path, dest: Path) -> tuple[int, _Claims]:
    """Stream the members out, and keep them when the archive breaks part-way.

    MEASURED on a real case: two UAC tarballs -- one with a corrupt deflate block
    ("invalid block type"), one cut short ("Compressed file ended before the
    end-of-stream marker was reached") -- extracted to NOTHING. Streamed, the same
    two now come out partial with 3,273 files (1.30 GB) and 22,919 files (7.33 GB),
    in 6 s and 40 s. The cause was
    `getmembers()`: it walks the whole archive before a single member is written,
    so damage at the END was discovered before anything at the START was kept.

    So members are written as they are read, and a stream that breaks after at
    least one of them is recorded on `claims.damage` instead of raised; the caller
    marks the acquisition `partial`. The member being read when it broke is
    removed, because a file cut short carries a name whose content -- and hash --
    matches nothing that was on the host. Damage before the first member is still
    an exception: there is nothing to keep, and it has to read as a failure.

    Nor is the end of the member loop taken for the end of the archive. tar ends
    it without a word on a header it cannot read, exactly as on a whole archive
    (see `_WhyTarStopped`), and a gzip stream corrupted mid-way can end it that way
    too; so can a failed CRC, which gzip checks only at the very end, past the point
    where tar stops reading. `_why_tar_stopped` asks both questions. This was true
    of `getmembers()` as well: those archives always extracted as whole.
    """
    skipped = 0
    written = 0
    claims = _Claims(dest)
    with tarfile.open(path, "r:*", tarinfo=_WhyTarStopped) as tf:
        members = iter(tf)
        while True:
            try:
                m = next(members)
            except StopIteration:
                break
            except _STREAM_DAMAGE as e:
                if not written:
                    raise
                claims.damage = _damage_detail(written, e)
                break
            rel, changed = _safe_relpath(m.name)
            if rel is None:
                skipped += 1
                continue
            if changed:
                claims.note_rename(m.name, rel)
            target = dest / rel
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not m.isreg():  # symlinks, devices, fifos: skipped (safety/portability)
                skipped += 1
                continue
            if not claims.claim(rel, m.name):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                src = tf.extractfile(m)
            except _STREAM_DAMAGE as e:
                if not written:
                    raise
                claims.damage = _damage_detail(written, e)
                break
            if src is None:
                skipped += 1
                continue
            broken = _copy_member(src, target)
            if broken is not None:
                if not written:
                    raise broken
                claims.damage = _damage_detail(written, broken)
                break
            written += 1
        if not claims.damage:
            claims.damage = _why_tar_stopped(tf, written)
            if claims.damage and not written:
                raise tarfile.ReadError(claims.damage)
    return skipped, claims


def _extract_gz(path: Path, dest: Path) -> tuple[int, _Claims]:
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / path.stem  # drop .gz
    with gzip.open(path, "rb") as src, open(out, "wb") as fh:
        shutil.copyfileobj(src, fh)
    return 0, _Claims(dest)


def _extract_7z_native(path: Path, dest: Path) -> tuple[int, _Claims]:
    """py7zr fallback (used when no 7-Zip binary is available).

    Held to the SAME safety bar as the zip/tar paths, which it used to skip: a bare
    `extractall()` trusts every member name, so one `../` would write outside `dest`,
    and nothing bounded the uncompressed size. Members are vetted lexically first
    (`_safe_relpath`), an unsafe one is dropped rather than extracted, and the
    declared uncompressed total is checked against the zip-bomb limits.
    """
    import py7zr  # type: ignore

    dest.mkdir(parents=True, exist_ok=True)
    claims = _Claims(dest)
    with py7zr.SevenZipFile(path, "r") as zf:
        entries = zf.list()
        total = sum(getattr(e, "uncompressed", 0) or 0 for e in entries)
        comp = max(1, path.stat().st_size)
        if total > MAX_TOTAL or (total / comp) > MAX_RATIO:
            raise RuntimeError(f"possible zip-bomb (ratio {int(total / comp)}x, {total} bytes)")
        safe, skipped = [], 0
        for name in zf.getnames():
            rel = _safe_relpath(name)[0]
            if rel is None:
                log.warning(f"[!] {path.name}: unsafe member skipped: {name}")
                skipped += 1
            elif claims.claim(rel, name):
                safe.append(name)
        # Always by explicit target list. `extractall` would write every member,
        # including the ones `claims` just refused, and this path has no per-member
        # hook to stop it with -- so the filtering has to happen in the argument.
        zf.reset()
        zf.extract(path=dest, targets=safe)
    # py7zr writes the members under the names it was GIVEN, so this path cannot
    # apply `_sanitize_component` -- there is no per-member hook between the
    # decision and the write. Said here rather than left to be inferred from an
    # empty list: a `.7z` is the one archive kind whose tree can still differ
    # between the two platforms. It is also the rarest: KAPE and UAC produce zip
    # and tar, and this runs only when no 7-Zip binary is installed.
    return skipped, claims


def _clear_dir(d: Path) -> None:
    for child in d.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


# Names that only exist because a previous run PARSED this destination.
_OUTPUT_MARKS = ("CSVs", "JSONs", "TXTs")


def _already_parsed(dest: Path) -> bool:
    """True if a previous run's own output lives in this destination.

    The analyst's results sit INSIDE the extracted tree: `CSVs/`, `JSONs/`, and the
    `.db` / `.xlsx` / `report.txt` beside them -- at the destination root for a UAC
    tarball, one level down per volume for a KAPE zip (`<dest>/C/CSVs`). A
    destination carrying those is finished work, not scratch space, and nothing here
    may re-extract into it or (see the failure path in `_extract_one`) clear it.
    """
    try:
        candidates = [dest, *(p for p in dest.iterdir() if p.is_dir())]
    except OSError:
        return False
    for d in candidates:
        try:
            if any((d / n).is_dir() for n in _OUTPUT_MARKS):
                return True
            if (d / "report.txt").is_file():
                return True
            if next(d.glob("*.db"), None) or next(d.glob("*.xlsx"), None):
                return True
        except OSError:
            continue
    return False


def _size_of(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _mark_done(marker: Path, status: str = EXTRACT_OK, detail: str = "",
               archive: Path | None = None) -> None:
    # The third line is the size of the archive the tree came out of, so a later
    # run can tell that the archive is no longer that one (see `_extract_one`).
    size = _size_of(archive) if archive is not None else None
    detail = detail.replace("\r", " ").replace("\n", " ")
    try:
        marker.write_text(f"{status}\n{detail}\n{'' if size is None else size}\n",
                          encoding="utf-8")
    except OSError as e:
        log.debug(f"could not write {marker}: {e}")


def recorded_size(dest: Path) -> int | None:
    """The size of the archive `dest` was extracted from, as its marker recorded
    it; None for a marker written before v0.7.70, which did not record one."""
    try:
        lines = (dest / MARKER).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    try:
        return int(lines[2]) if len(lines) > 2 and lines[2].strip() else None
    except ValueError:
        return None


def read_marker(dest: Path) -> tuple[str, str]:
    """(status, detail) recorded when `dest` was extracted; ('', '') if unmarked.

    Markers written before v0.7.20 hold the single word "ok", which is exactly
    what they meant and what this reads them back as.
    """
    try:
        text = (dest / MARKER).read_text(encoding="utf-8")
    except OSError:
        return "", ""
    lines = text.splitlines()
    status = (lines[0].strip() if lines else "") or EXTRACT_OK
    return status, (lines[1].strip() if len(lines) > 1 else "")


def incomplete_acquisitions(results: list[ExtractResult]) -> list[dict]:
    """The acquisitions whose extracted tree is not the whole archive.

    Reported apart from parser errors, and for a different reason. A parser that
    errors says so; an acquisition with a hole in it says nothing at all -- every
    parser below it simply finds no input, self-gates, and is counted as
    "skipped", which is the same count a machine gets for artifacts its distro
    does not have. A run over a tarball that was cut short mid-write therefore
    ends "OK 2 | skipped 37 | errors 0", which reads as a clean triage of a quiet
    host. It is not a finding about the host. It is a finding about the archive.

    Mere warnings are left out: 7-Zip finishing the job with complaints is not
    the same claim, and a signal that fires on the ordinary case stops being read.
    """
    out: list[dict] = []
    for r in results:
        if not r.ok:
            out.append({"archive": r.archive.name, "status": "failed",
                        "detail": r.error})
        elif r.partial:
            out.append({"archive": r.archive.name, "status": "partial",
                        "detail": r.warning_detail})
    return out


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _extract_one(path: Path, dest: Path, seven: Path | None) -> ExtractResult:
    marker = dest / MARKER
    if marker.is_file():
        # Re-runs report what the FIRST run found. Extraction is the one phase a
        # later run does not repeat, so without this the news that an acquisition
        # is truncated survives exactly one run and then disappears for good.
        status, detail = read_marker(dest)
        was, now = recorded_size(dest), _size_of(path)
        if was is not None and now is not None and now != was:
            # Not the archive this tree came out of: an upload still running when
            # an earlier run opened it, or a new copy under the same name. Nothing
            # is extracted over a tree that may hold results; it is SAID, on every
            # run, until somebody decides what to do with it.
            changed = (f"the archive is {now} bytes and was {was} when it was "
                       f"extracted, so this tree and every result under it describe "
                       f"the earlier copy -- delete {dest.name} to extract it again")
            return ExtractResult(path, dest, ok=True, warnings=True, partial=True,
                                 warning_detail=f"{detail}; {changed}" if detail else changed)
        return ExtractResult(path, dest, ok=True, warnings=status != EXTRACT_OK,
                             warning_detail=detail, partial=status == EXTRACT_PARTIAL)
    if _already_parsed(dest):
        # Extracted and parsed by an earlier run whose marker this destination does
        # not carry -- it predates the marker, or lost it. Adopt it instead of
        # extracting again: a re-extraction over a finished case is at best wasted
        # work, and if it fails the retry path below clears the destination, which
        # takes the evidence tree AND every result under it with it.
        _mark_done(marker, archive=path)
        log.info(f"[=] {dest.name}: already extracted and parsed, left untouched")
        return ExtractResult(path, dest, ok=True)
    dest.mkdir(parents=True, exist_ok=True)
    kind = _kind(path)
    used_7z = False
    status = EXTRACT_OK
    try:
        if kind == "zip":
            sk, claims = _extract_zip(path, dest)
        elif kind == "tar":
            sk, claims = _extract_tar(path, dest)
            if claims.damage and seven is not None:
                # With a 7-Zip on the host a damaged tarball goes to it exactly as
                # it did before streaming existed: the retry below clears what was
                # kept and lets 7-Zip read the archive its own way.
                raise _Damaged(claims.damage)
        elif kind == "gz":
            sk, claims = _extract_gz(path, dest)
        elif kind == "7z":
            try:
                sk, claims = _extract_7z_native(path, dest)
            except ImportError as e:
                raise RuntimeError("py7zr missing") from e
        else:
            return ExtractResult(path, dest, ok=False, error="unsupported format")
    except Exception as e:  # noqa: BLE001 - retried or reported
        if seven is None:
            return ExtractResult(path, dest, ok=False, error=f"{e} (no 7-Zip)")
        log.debug(f"{path.name}: {e} -> retrying with 7-Zip")
        detail = ""
        try:
            # The clear exists so 7-Zip starts from a clean slate after a partial
            # extraction. Re-checked here rather than trusted from above, because
            # the cost of getting it wrong is asymmetric: a partial tree costs a
            # retry, a wrongly cleared one costs the case.
            if _already_parsed(dest):
                log.warning(f"[!] {dest.name}: extraction failed and the destination "
                            "already holds results -- NOT clearing it; "
                            "delete it by hand if you really want a fresh extraction")
            else:
                _clear_dir(dest)
            status, detail = _extract_with_7z(seven, path, dest)
            # The 7-Zip binary writes the members itself, so `_Claims` has no hook
            # here and a case collision on this path is NOT caught. Said plainly
            # rather than papered over: it is a fallback for archives the native
            # readers could not open at all, and pre-listing the archive to find
            # collisions would cost a second full pass over it.
            sk, used_7z, claims = 0, True, _Claims(dest)
        except Exception as e2:  # noqa: BLE001
            return ExtractResult(path, dest, ok=False, error=f"7-Zip: {e2}")
        _mark_done(marker, status, detail, archive=path)
        return ExtractResult(
            path, dest, ok=True, skipped=sk, used_7z=used_7z,
            warnings=status != EXTRACT_OK, warning_detail=detail,
            partial=status == EXTRACT_PARTIAL,
        )
    coll, ren = claims.collisions, claims.renames
    if ren:
        _write_renames(dest, ren)
    if claims.damage:
        # Reached only with no 7-Zip on the host (see the tar branch above). What
        # came out before the damage is whole and is KEPT; the acquisition is
        # PARTIAL, through the marker, so a later run that adopts this destination
        # still says so.
        detail = claims.damage
        if coll:
            detail += f"; {collision_detail(coll)}"
        log.warning(f"[!] {path.name}: {detail}")
        for c in coll:
            log.warning(f"        {c}")
        _mark_done(marker, EXTRACT_PARTIAL, detail, archive=path)
        return ExtractResult(path, dest, ok=True, sanitized=len(ren), skipped=sk,
                             used_7z=used_7z, warnings=True, warning_detail=detail,
                             partial=True, collisions=coll, renamed=ren)
    if coll:
        # Named in the CASE log, one line each: which member lost and to what. The
        # summary carries only the count -- the names are evidence paths and belong
        # beside the evidence, not in a console rollup.
        detail = collision_detail(coll)
        log.warning(f"[!] {path.name}: {detail}")
        for c in coll:
            log.warning(f"        {c}")
        # PARTIAL, and written into the marker, because extraction is the one phase
        # a later run does not repeat: without this the news survives exactly one
        # run and then disappears while the hole stays.
        _mark_done(marker, EXTRACT_PARTIAL, detail, archive=path)
        return ExtractResult(path, dest, ok=True, sanitized=len(ren), skipped=sk,
                             used_7z=used_7z, warnings=True, warning_detail=detail,
                             partial=True, collisions=coll, renamed=ren)
    if ren:
        # A warning, not `partial`: the tree is whole, the names in it are not the
        # names in the archive. Through the marker for the same reason as above --
        # a later run adopts this destination without re-extracting it, and the
        # fact has to outlive the run that discovered it.
        detail = rename_detail(ren)
        log.warning(f"[!] {path.name}: {detail}")
        for r in ren[:_RENAMES_LOGGED]:
            log.warning(f"        {r}")
        if len(ren) > _RENAMES_LOGGED:
            log.warning(f"        ... and {len(ren) - _RENAMES_LOGGED} more, all of "
                        f"them in {RENAMES}")
        _mark_done(marker, EXTRACT_WARNED, detail, archive=path)
        return ExtractResult(path, dest, ok=True, sanitized=len(ren), skipped=sk,
                             used_7z=used_7z, warnings=True, warning_detail=detail,
                             renamed=ren)
    _mark_done(marker, archive=path)
    return ExtractResult(path, dest, ok=True, skipped=sk, used_7z=used_7z)


def _nested_containers(dest: Path, processed: set[Path]) -> list[Path]:
    """Containers DIRECTLY inside an extracted destination (double-compressed
    acquisition: zip inside zip). Does not search subfolders, so it doesn't pull
    in inner zips like Velociraptor or the .gz files under /var/log."""
    out = []
    try:
        children = list(dest.iterdir())
    except OSError:
        return out
    for p in children:
        if is_container(p) and p.resolve() not in processed:
            out.append(p)
    return out


def extract_all(
    root: Path,
    tools_dir: Path | None = None,
    max_depth: int = 3,
    max_workers: int = 4,
    hold: set[Path] | frozenset[Path] = frozenset(),
) -> list[ExtractResult]:
    """Extract the parent acquisitions (and nested wrappers) IN PARALLEL.

    Only handles CONTAINERS (zip/tar/tar.gz/7z); standalone .gz (rotated logs,
    memory dumps) are left compressed. Recurses only into containers that hang
    directly off an already-extracted destination (the 'zip inside zip' case).
    """
    seven = find_7z(tools_dir)
    if not seven:
        log.warning(archiver_warning(tools_dir))

    processed: set[Path] = set()
    results: list[ExtractResult] = []
    # What has not finished arriving is left for a later run (core/arrival.py).
    held = {Path(p).resolve() for p in hold}
    level = sorted((p for p in root.iterdir() if is_container(p) and p.resolve() not in held),
                   key=lambda p: p.name.lower())

    depth = 0
    while level and depth < max_depth:
        for p in level:
            processed.add(p.resolve())
        workers = max(1, min(max_workers, len(level)))
        ex = ThreadPoolExecutor(max_workers=workers)
        futs = [ex.submit(_extract_one, a, _dest_dir(a), seven) for a in level]
        try:
            level_results = [f.result() for f in as_completed(futs)]
        except KeyboardInterrupt:
            procs.cancel_all()                            # kill in-flight 7-Zip
            ex.shutdown(wait=False, cancel_futures=True)  # drop the pending ones
            raise
        ex.shutdown(wait=True)
        results.extend(level_results)

        nxt: list[Path] = []
        for r in level_results:
            if r.ok:
                nxt.extend(_nested_containers(r.dest, processed))
        level = nxt
        depth += 1

    results.sort(key=lambda r: r.archive.name.lower())
    return results


# Loose-drop folder conventions (see the matching detection profiles).
# Accepts a bare numeric suffix too (weblogs1, weblogs2) -- how analysts
# actually name multiple drops. Public: Phase-0 integrity also keys off it.
DROP_DIR = re.compile(r"(weblogs|fortigate|evtx)(\d+|[-_].+)?$", re.IGNORECASE)


def drop_dirs(root: Path) -> list[Path]:
    """The loose-drop folders of a case: at the root and one level down, plus the
    root itself when `-p` points AT one (detection matches the root as a machine,
    so extraction must look there too or its archives never open)."""
    drops = [d for pat in ("*", "*/*") for d in root.glob(pat)
             if d.is_dir() and DROP_DIR.fullmatch(d.name)]
    if DROP_DIR.fullmatch(root.name):
        drops.append(root)
    return sorted(set(drops))


def extract_drops(root: Path, tools_dir: Path | None = None,
                  hold: set[Path] | frozenset[Path] = frozenset()) -> list[ExtractResult]:
    """Extract archives dropped INSIDE a loose-drop folder (`weblogs[-label]`,
    `fortigate[-label]`, `evtx[-label]`), in place.

    Exports arrive zipped and named any which way (`logs_marzo.zip`,
    `export.tar.gz`, a colleague's `eventlogs.zip` of a host's channels); the
    analyst just copies them into the drop folder -- so every drop kind gets the
    same treatment, or `evtx-dc01/logs.zip` would detect as a machine with no
    `*.evtx` to stage and parse nothing at all. The
    generic pass never sees them (it only extracts containers at the case root),
    so this one walks each drop dir (case root + one level down) and extracts
    every container next to itself, one nested level deep (zip inside zip).
    Standalone .gz rotated logs stay compressed (the parsers stream them).
    Idempotent via the same .aeng_extracted_ok marker."""
    seven = find_7z(tools_dir)
    # What has not finished arriving is left for a later run (core/arrival.py).
    held = {Path(p).resolve() for p in hold}
    results: list[ExtractResult] = []
    processed: set[Path] = set()
    for drop in drop_dirs(root):
        level = [p for p in sorted(drop.rglob("*"))
                 if is_container(p) and p.resolve() not in held]
        for _ in range(2):                       # containers + one nested level
            level = [p for p in level if p.resolve() not in processed]
            if not level:
                break
            nxt: list[Path] = []
            for z in level:
                processed.add(z.resolve())
                r = _extract_one(z, _dest_dir(z), seven)
                results.append(r)
                if r.ok:
                    nxt.extend(_nested_containers(r.dest, processed))
            level = nxt
    return results


def extract_velociraptor(
    root: Path,
    tools_dir: Path | None = None,
    names: tuple[str, ...] = VELOCIRAPTOR_ZIPS,
) -> list[ExtractResult]:
    """Extract the wanted Velociraptor sub-collections (LiveResponse.zip) in place.

    These sit at <collection>/Velociraptor/<name> -- too deep for the generic
    nested-container pass, which deliberately stays at the top level. We look only
    where they actually are (collection root and one level down), so we don't
    rglob the whole multi-million-file KAPE tree. Each extracts next to itself
    (LiveResponse.zip -> Velociraptor/LiveResponse/results/*.json) and is
    idempotent via the same .aeng_extracted_ok marker.
    """
    seven = find_7z(tools_dir)
    found: list[Path] = []
    for name in names:
        for pat in (f"Velociraptor/{name}", f"*/Velociraptor/{name}"):
            found.extend(z for z in root.glob(pat) if z.is_file())
    results = [_extract_one(z, _dest_dir(z), seven) for z in sorted(set(found))]
    return results
