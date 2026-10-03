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

# How an extraction went, as recorded IN the marker. The status has to outlive
# the run that extracted, because the marker short-circuits the work on every
# later run: a partial acquisition that announced itself once, in phase 1 of the
# first run, is a partial acquisition that announces itself never.
#
#   ok        the archive was read whole
#   warnings  the native extractor failed, 7-Zip finished the job with warnings
#   damaged   every member is on disk and at least one of them is not a faithful
#             copy: 7-Zip read past the size the archive declared for it (a file
#             that was still being written when it was collected) or its checksum
#             failed. Nothing is MISSING, so this is not `partial` -- but the
#             bytes under that one name are not the bytes that were on the host,
#             and a parser reading them reports something rather than nothing,
#             which is the one failure a hole does not have (v0.7.86)
#   partial   the tree on disk is not the whole archive. Three causes, and the
#             status deliberately does not distinguish them, because what the
#             parsers below are reading is the same either way:
#               - the native extractor failed AND 7-Zip could not finish either;
#                 what is on disk is as much as could be salvaged
#               - members were dropped because the DESTINATION could not hold
#                 their names apart from one already written (`_Claims`) -- two
#                 spellings of one name on a filesystem that folds case, or the
#                 same name twice, which clobbers anywhere
#               - a member that IS a nested container came out damaged, so the
#                 subtree this engine would have recursed into never landed
EXTRACT_OK = "ok"
EXTRACT_WARNED = "warnings"
EXTRACT_DAMAGED = "damaged"
EXTRACT_PARTIAL = "partial"

# Worst-wins, for a detail that carries several complaints.
_SEVERITY = {EXTRACT_OK: 0, EXTRACT_WARNED: 1, EXTRACT_DAMAGED: 2, EXTRACT_PARTIAL: 3}

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
    # At least one member is on disk holding bytes that are not a faithful copy
    # of the file that was collected. A different claim from `partial` and
    # reported apart from it: nothing here is missing, so the run's verdict does
    # NOT turn on it, and a verdict that fired on this fired on every healthy
    # acquisition (v0.7.86).
    damaged: bool = False
    # Members dropped because the destination filesystem cannot tell their names
    # apart from one already written (see `_Claims`). A hole in the tree like any
    # other, so it sets `partial` -- but named separately because the cause is the
    # DESTINATION, not the archive, and the same archive on a case-sensitive
    # filesystem extracts whole.
    collisions: list[str] = field(default_factory=list)


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
    """Clean a path component so it is valid on the host OS."""
    if os.name != "nt":
        return _CTRL.sub("_", part)
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
    is why the same code is right on every filesystem: where both names can
    coexist nothing is flagged, because nothing is lost. An exact duplicate member
    name is flagged everywhere, because that one clobbers on any filesystem.

    On a folding destination the key upper-cases each character -- but a
    non-ASCII character only once the destination has confirmed, with a probe
    file, that it treats the two as one (`_folds`). Until v0.7.73 the key was
    `str.casefold()`, which is not what NTFS does: of 17 pairs measured, NTFS kept
    13 apart that casefold merges (`ß`/`SS`, the Kelvin sign/`k`, `ſ`/`s`, `µ`/`μ`
    ...), so a member that fitted beside its neighbour was dropped and the
    acquisition called partial for nothing. Plain `str.upper()` is no better (8 of
    17 wrong): NTFS's upcase table is fixed when the volume is formatted and is
    older than Python's Unicode data, hence the per-character question. Nothing
    is written in the tree itself, so a failed extraction leaves no empty file
    posing as a member.
    """

    __slots__ = ("_dest", "_fold", "_folds", "_taken", "collisions")

    def __init__(self, dest: Path) -> None:
        self._dest = dest
        self._fold = _case_insensitive(dest)
        self._folds: dict[str, str] = {}      # non-ASCII char -> its key on this destination
        self._taken: dict[str, str] = {}
        self.collisions: list[str] = []

    def claim(self, rel: Path, member: str) -> bool:
        """True if `member` may be written to `rel`; False if something has it."""
        key = rel.as_posix()
        if self._fold:
            key = "".join(map(self._char_key, key))
        holder = self._taken.get(key)
        if holder is not None:
            self.collisions.append(f"{member} (collides with {holder}, which was kept)")
            return False
        self._taken[key] = member
        return True

    def _char_key(self, c: str) -> str:
        if c.isascii():
            return c.upper()
        key = self._folds.get(c)
        if key is None:
            # `title()` for the letters whose uppercase is two characters: NTFS
            # still folds Greek `ᾀ` with its titlecase `ᾈ`, and without this the
            # pair keeps two keys and becomes one spliced file.
            up = c.upper() if len(c.upper()) == 1 else c.title()
            key = up if len(up) == 1 and up != c and _same_name(self._dest, c, up) else c
            self._folds[c] = key
        return key


def _same_name(d: Path, a: str, b: str) -> bool:
    """Whether `d`'s filesystem opens the same file for `a` and for `b`.

    Written and removed at once, beside the case probe; a name that cannot be
    created counts as different, and the write of the member itself then fails
    and says why.
    """
    stem = f".aeng_fold_probe_{os.getpid()}_"
    probe = d / (stem + a)
    try:
        probe.write_bytes(b"")
        return (d / (stem + b)).exists()
    except OSError:
        return False
    finally:
        try:
            probe.unlink()
        except OSError:
            pass


def collision_detail(collisions: list[str]) -> str:
    """The one-line summary that goes in the marker and the run summary."""
    return (f"{len(collisions)} member(s) dropped: the destination filesystem takes their "
            f"names for one already extracted (the same name, or it in another case) "
            f"-- see the case log for which")


# --------------------------------------------------------------------------- #
# 7-Zip (fallback)
# --------------------------------------------------------------------------- #
def find_7z(tools_dir: Path | None = None) -> Path | None:
    """A 7-Zip binary, wherever this host keeps one.

    Unlike a parser binary this one MAY come off `PATH`, deliberately: it is a
    decompressor, not something whose version shows up in a result, so the
    audit-trail argument that keeps parser tools pinned does not apply here. Its
    output is the archive's own bytes, or it is an error.
    """
    cands: list[Path] = []
    if tools_dir:
        cands += [tools_dir / "7zip" / "7z.exe", tools_dir / "7z.exe", tools_dir / "7za.exe"]
    for name in ("7z", "7za", "7zz"):
        w = shutil.which(name)
        if w:
            cands.append(Path(w))
    cands += [
        Path(r"C:\Program Files\7-Zip\7z.exe"),
        Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
    ]
    for c in cands:
        if c and c.is_file():
            return c
    return None


def archiver_warning(tools_dir: Path | None = None) -> str:
    """Empty when a 7-Zip binary is available here; otherwise the line to print.

    MEASURED on a host that had none: four of eleven acquisitions extracted to
    NOTHING -- two using a compression method the built-in readers do not
    implement, one with a corrupt deflate stream, one truncated. All four were
    reported as failed acquisitions rather than parsed as clean trees, which is
    the right failure; all four were reported halfway through extraction, which
    is the wrong moment, after the analyst has committed to the run.

    This is the only tool whose absence costs a WHOLE acquisition rather than one
    parser's table, and `aeng setup` cannot fetch it either: it is an installer,
    not a release asset a parser manifest can declare. Hence a function of its
    own, called before phase 0 rather than when extraction reaches the archive.
    """
    if find_7z(tools_dir):
        return ""
    return ("[!] no 7-Zip binary: an archive using Deflate64 or another method the "
            "built-in readers do not implement will not extract AT ALL -- install "
            "7-Zip, or drop 7z.exe into the tools directory")


# Generic 7-Zip counters with no useful info (dropped from the warning).
_7Z_NOISE = ("sub items errors", "archives with errors", "files:", "errors:")
_7Z_PREFIX = re.compile(r"^(ERROR|WARNING)\s*:\s*")

# How much of the output is kept. Read back by `_claim`, which has to know the
# text may have been cut, so the cap lives here rather than in both places.
_DETAIL_CAP = 240

# --------------------------------------------------------------------------- #
# What a complaint claims about the tree
# --------------------------------------------------------------------------- #
# 7-Zip's exit code is not the claim, and this is the whole of v0.7.86. It exits
# 2 -- fatal -- when a member grew between being listed and being read, which is
# the ORDINARY state of a live acquisition: the endpoint-security agent holds a
# .lck open, the registry holds DEFAULT.LOG1, OneDrive holds a .db-wal. It exits
# 2 for an archive cut in half as well, and the old code read the exit code.
#
# MEASURED on three real cases, 34 units: eighteen acquisitions were reported as
# not having extracted whole, and eight of those eighteen were one open file. One
# whole case was `incomplete` on nothing else at all. That is the failure this
# guards against, and `incomplete_acquisitions` says so itself -- "a signal that
# fires on the ordinary case stops being read" -- so the rule was right and only
# applied to the mild exit code.
#
# The question a message answers is only ever whether content is MISSING.

# Appended to a detail that does not account for the whole output, because the
# cap on it is verdict-bearing now and the marker keeps only this text.
_CUT_MARK = " [...]"

# Content is gone: the stream ended before the archive did, or a member could
# not be read at all. "unexpected end" without the rest: 7-Zip says "of data" in
# a tar and "of archive" in a zip, and the zip wording was what a cut archive
# reported while this list only knew the other one.
_MISSING = ("unexpected end", "cannot open", "cannot read", "cannot find",
            "headers error", "is not supported", "unavailable", "wrong password")

# The one complaint that is positive evidence of a whole tree: the member was
# LONGER than the archive declared, which is what a file still being written
# looks like. It cannot be truncation -- truncation is the archive stopping
# early, not a member overrunning its own size.
_GREW = "there are some data after the end of the payload data"

# A member's bytes failed their checksum. Whether anything is MISSING depends on
# whether 7-Zip reached the end of the archive: a cut .zip reports exactly this,
# about the member it was reading when the data ran out, and it is the same
# sentence a whole-but-corrupt archive produces. So it is only read as a damaged
# member when the archiver finished the job (its mild exit code); under a fatal
# one it is a hole, which is what v0.7.85 called it.
_CHECKSUM = ("data error", "crc failed")

# Left out on purpose. Not a claim about the tree.
_BY_DESIGN = ("dangerous link path was ignored",)

# What `_nested_containers` recurses into. A bare .gz or .xz is deliberately NOT
# here: a rotated log, a package-database backup or a journal segment is a member
# like any other and nothing extracts it (see CONTAINER_KINDS), so a corrupt one
# costs that file and not a subtree.
_NESTED = (*_TAR_SUFFIXES, ".zip", ".7z")


def _names_a_container(msg: str) -> bool:
    """Whether anything this message names is a container we recurse into.

    EVERY ` : `-separated part is asked, not just the first. The first ` : `
    separates 7-Zip's complaint from what it names, but a member name may legally
    contain " : " on Linux -- and then the suffix that decides between a damaged
    file and a lost subtree sits in a later part, so reading only the first one
    fails towards "just a bad file", which is the one direction this must not
    fail in. Safe here because the skipped-link message, the one whose second
    part is a target rather than a name, is answered before this is reached."""
    return any(part.strip().lower().endswith(_NESTED)
               for part in msg.partition(" : ")[2].split(" : "))


def _complaint(msg: str) -> str:
    """The part of a message that is 7-Zip speaking, with no member name in it.

    Matched against instead of the whole line, because everything past the first
    ` : ` is a path out of the acquisition: a file called `unavailable.log`, or a
    directory called `cannot open`, would otherwise turn the ordinary
    copied-while-open complaint ABOUT that file into a hole -- the noise this
    version exists to remove, reintroduced by a filename."""
    return msg.partition(" : ")[0].strip().lower()


def _one_claim(msg: str, finished: bool) -> str:
    """What one 7-Zip message claims about the tree.

    An unrecognised message claims the worst. These lists are what has been seen
    on real acquisitions, not everything 7-Zip can say, and a message nobody has
    classified is not evidence that the archive came out whole."""
    said = _complaint(msg)
    if any(k in said for k in _BY_DESIGN):
        return EXTRACT_WARNED
    if any(k in said for k in _MISSING):
        return EXTRACT_PARTIAL
    if said.startswith(_GREW) or (finished and
                                  any(said.startswith(k) for k in _CHECKSUM)):
        return EXTRACT_PARTIAL if _names_a_container(msg) else EXTRACT_DAMAGED
    return EXTRACT_PARTIAL


def _claim(detail: str, finished: bool = False) -> str:
    """The worst claim the messages in one detail make about the tree.

    `finished` is whether the archiver read the archive to its end -- its mild
    exit code. It is what decides a checksum failure, and it defaults to the
    unsafe-to-assume answer, which is what reading a marker has to assume.

    A detail carrying `_CUT_MARK` does not account for the whole output: a
    message was dropped or cut, and the cut is exactly where the line saying
    content is missing would have been. So it claims the worst -- an empty detail
    likewise, since something went wrong and nothing said what."""
    if not detail.strip() or _CUT_MARK.strip() in detail:
        return EXTRACT_PARTIAL
    worst = EXTRACT_OK
    for msg in detail.split(" | "):
        claim = _one_claim(msg, finished)
        if _SEVERITY[claim] > _SEVERITY[worst]:
            worst = claim
    return worst


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
            # "unexpected end" carries no other keyword, and it is the line that
            # says the archive stopped early -- dropping it left a cut archive
            # describing itself with a member's checksum failure, which is what a
            # whole-but-corrupt archive says too (found by review, v0.7.86).
            if not any(k in low for k in ("error", "warning", "cannot",
                                          "after the end", "unexpected end")):
                continue
            if any(noise in low for noise in _7Z_NOISE):
                continue
            t = _7Z_PREFIX.sub("", t).strip()
            if t and t not in seen:
                seen.add(t)
                msgs.append(t)
    # Four messages and a length were a DISPLAY cap. They decide a verdict now,
    # so when either one bites the detail says it does, in the text, which is the
    # only part of this that survives into the marker: a classifier reading a
    # detail that does not account for the whole output must not conclude the
    # archive is whole, and a LENGTH cannot tell it that -- `read_marker` strips
    # the line, so a cut landing on a space came back one character short of the
    # cap and read as intact (found by review, v0.7.86).
    dropped = len(msgs) > 4
    joined = " | ".join(msgs[:4])
    if dropped or len(joined) > _DETAIL_CAP:
        return joined[:_DETAIL_CAP - len(_CUT_MARK)].rstrip() + _CUT_MARK
    return joined


def _extract_with_7z(seven: Path, path: Path, dest: Path) -> tuple[str, str]:
    """Extract with 7-Zip. Returns (status, detail). Raises on total failure.

    7-Zip rc: 0=ok, 1=warning (non-fatal), 2=fatal. With rc>=2 it often extracts
    almost everything (e.g. minor corruption of one file), so if content was
    produced we keep it rather than discarding the whole acquisition. What the
    run is then allowed to say comes from the MESSAGE and not from the exit code
    (`_claim`, v0.7.86): rc=2 is what 7-Zip returns for an archive cut in half
    AND for a member that was being written while it was collected, and reading
    the code made every acquisition holding an open .lck say it had a hole in it.
    A truncated acquisition is the case a parser reporting nothing is least able
    to distinguish from a quiet host, which is exactly why that claim cannot also
    be made about the ordinary one."""
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [str(seven), "x", "-y", "-bb0", "-bsp0", f"-o{dest}", str(path)]
    rc, out, err = procs.run(cmd)
    detail = _seven_errors(out, err)
    if rc == 0:
        return EXTRACT_OK, ""
    if rc == 1:
        # 7-Zip read the archive to its end, so there is no hole to find here --
        # but it still names what it was unhappy about, and a member whose bytes
        # are not a faithful copy is worth recording under the mild code too.
        return ((EXTRACT_DAMAGED if _claim(detail, finished=True) == EXTRACT_DAMAGED
                 else EXTRACT_WARNED), detail)
    if not any(dest.iterdir()):
        raise RuntimeError(f"rc={rc}: {detail or '7-Zip failure'}")
    claim = _claim(detail)
    if _SEVERITY[claim] < _SEVERITY[EXTRACT_DAMAGED]:
        # A fatal exit that nothing in the output accounts for. `warnings` would
        # put it in neither list and print it nowhere, which is the quiet verdict
        # this whole file exists to prevent (found by review, v0.7.86).
        claim = EXTRACT_PARTIAL
    log.debug(f"7z rc={rc} on {path.name} ({claim}): {detail}")
    return claim, detail


# --------------------------------------------------------------------------- #
# Native extractors
# --------------------------------------------------------------------------- #
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
                "whole. Enable LongPathsEnabled (Computer Configuration > "
                "Administrative Templates > System > Filesystem > Enable Win32 long "
                "paths) and reboot, or extract the case closer to the drive root")
    finally:
        shutil.rmtree(probe, ignore_errors=True)


def _extract_zip(path: Path, dest: Path) -> tuple[int, int, list[str]]:
    sanitized = skipped = 0
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
            sanitized += changed
            target = dest / rel
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not claims.claim(rel, info.filename):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    return sanitized, skipped, claims.collisions


# What a DAMAGED ARCHIVE raises while being read. Named exactly, and bare
# `OSError` deliberately left out: a read that fails on the source media -- a
# network share that drops, a USB disk with a bad sector -- raises one too, and
# treating it as damage would write `partial` into the marker, which a later run
# short-circuits on. A host fault would then be recorded as a verdict about the
# evidence, and the members past it would never be extracted by any run. Failing
# loudly instead leaves no marker, so the next run retries the archive.
#
# `gzip.BadGzipFile` IS an `OSError` and has to be named for that reason. The
# cost of the choice: bz2 signals a corrupt stream with a plain `OSError`, so a
# damaged .tar.bz2 reads as a failure rather than coming out partial. UAC ships
# .tar.gz; a tarball that fails loudly and is retried is the safe end of the
# trade.
_STREAM_DAMAGE = (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError,
                  gzip.BadGzipFile)
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
    exception returned; a WRITE failure is raised like any other -- but the
    half-written file goes either way.

    It has to: a member cut short carries a real name over content whose hash
    matches nothing that was on the host, and on the write path there is no
    marker either, so phase 0 of the next run would walk that truncated file and
    record it in `traces.txt` as an original.
    """
    broken = None
    try:
        with src, open(target, "wb") as out:
            while True:
                try:
                    chunk = src.read(_COPY_BUF)
                except _STREAM_DAMAGE as e:
                    broken = e
                    break
                if not chunk:
                    return None         # whole member, kept
                out.write(chunk)
    except BaseException:
        target.unlink(missing_ok=True)
        raise
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


def _extract_tar(path: Path, dest: Path) -> tuple[int, int, list[str], str]:
    """Stream the members out, and keep them when the archive breaks part-way.

    MEASURED on a real case: two UAC tarballs -- one with a corrupt deflate block
    ("invalid block type"), one cut short ("Compressed file ended before the
    end-of-stream marker was reached") -- extracted to NOTHING. Streamed, the same
    two came out partial with 3,273 files (1.30 GB) and 22,919 files (7.33 GB), in
    6 s and 40 s. The cause was `getmembers()`: it walks the whole archive before a
    single member is written, so damage at the END was discovered before anything
    at the START was kept.

    So members are written as they are read, and a stream that breaks after at
    least one of them is RETURNED as the fourth value instead of raised; the caller
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
    sanitized = skipped = written = 0
    damage = ""
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
                damage = _damage_detail(written, e)
                break
            rel, changed = _safe_relpath(m.name)
            if rel is None:
                skipped += 1
                continue
            sanitized += changed
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
                damage = _damage_detail(written, e)
                break
            if src is None:
                skipped += 1
                continue
            broken = _copy_member(src, target)
            if broken is not None:
                if not written:
                    raise broken
                damage = _damage_detail(written, broken)
                break
            written += 1
        if not damage:
            damage = _why_tar_stopped(tf, written)
            if damage and not written:
                raise tarfile.ReadError(damage)
    return sanitized, skipped, claims.collisions, damage


def _extract_gz(path: Path, dest: Path) -> tuple[int, int, list[str]]:
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / path.stem  # drop .gz
    with gzip.open(path, "rb") as src, open(out, "wb") as fh:
        shutil.copyfileobj(src, fh)
    return 0, 0, []


def _extract_7z_native(path: Path, dest: Path) -> tuple[int, int]:
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
    return 0, skipped, claims.collisions


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


def _flat(text: str) -> str:
    """One line, because the marker is read BY LINE and a value that carries a
    newline would push every value after it onto a line nothing reads."""
    return text.replace("\r", " ").replace("\n", " ")


def _mark_done(marker: Path, status: str = EXTRACT_OK, detail: str = "",
               archive: Path | None = None) -> None:
    # Lines three and four are the SIZE and the NAME of the archive this tree came
    # out of. The size lets a later run tell that the archive is no longer the one
    # it was extracted from; the name lets it tell that apart from a DIFFERENT
    # archive folding to the same destination (see `_extract_one`).
    size = _size_of(archive) if archive is not None else None
    name = _flat(archive.name) if archive is not None else ""
    try:
        marker.write_text(f"{status}\n{_flat(detail)}\n"
                          f"{'' if size is None else size}\n{name}\n",
                          encoding="utf-8")
    except OSError as e:
        log.debug(f"could not write {marker}: {e}")


def recorded_size(dest: Path) -> int | None:
    """The size of the archive `dest` was extracted from, as its marker recorded
    it; None for a marker written before v0.7.82, which did not record one."""
    try:
        lines = (dest / MARKER).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    try:
        return int(lines[2]) if len(lines) > 2 and lines[2].strip() else None
    except ValueError:
        return None


def recorded_name(dest: Path) -> str:
    """The name of the archive `dest` was extracted from, as its marker recorded
    it; '' for a marker written before v0.7.82, which did not record one."""
    try:
        lines = (dest / MARKER).read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    return lines[3].strip() if len(lines) > 3 else ""


def read_marker(dest: Path) -> tuple[str, str]:
    """(status, detail) recorded when `dest` was extracted; ('', '') if unmarked.

    Markers written before v0.7.20 hold the single word "ok", which is exactly
    what they meant and what this reads them back as.

    A recorded `partial` is re-read through `_claim` (v0.7.86). Extraction is the
    one phase a later run does not repeat, so a verdict written by an older engine
    outlives the reading that produced it: without this, a case extracted before
    this version keeps reporting a hole over a file that was merely copied while
    it was open, on every run, for as long as the case exists -- and the only way
    to correct it would be to delete the tree and extract the archive again, which
    costs the whole acquisition to fix a sentence.

    Only a DOWNGRADE is taken. A recorded `warnings` was written by a 7-Zip that
    read the archive to its end, so there is no hole there to discover, and
    re-reading one upwards would be this engine inventing a claim that the
    extraction itself never made.
    """
    try:
        text = (dest / MARKER).read_text(encoding="utf-8")
    except OSError:
        return "", ""
    lines = text.splitlines()
    status = (lines[0].strip() if lines else "") or EXTRACT_OK
    detail = lines[1].strip() if len(lines) > 1 else ""
    if status != EXTRACT_PARTIAL:
        return status, detail
    # Downgrade only, and never past `damaged`: a recorded `partial` was written
    # because the extraction could not account for the archive, and reading it
    # down to a warning would drop it out of every list the run reports.
    again = _claim(detail)
    return (again if again == EXTRACT_DAMAGED else EXTRACT_PARTIAL), detail


def incomplete_acquisitions(results: list[ExtractResult]) -> list[dict]:
    """The acquisitions whose extracted tree is not the whole archive.

    Reported apart from parser errors, and for a different reason. A parser that
    errors says so; an acquisition with a hole in it says nothing at all -- a
    parser whose input was cut out of the archive does not crash, it finds no
    input, self-gates, and is counted as "skipped", which is the same count a
    machine gets for artifacts its distro does not have. The parsers whose
    artifacts came out before the damage run normally, which is the point of
    keeping them (see `_extract_tar`) and also what makes the hole so quiet: a
    run over a tarball cut short mid-write ends "OK 2 | skipped 37 | errors 0",
    which reads as a clean triage of a quiet host. It is not a finding about the
    host. It is a finding about the archive.

    Mere warnings are left out: 7-Zip finishing the job with complaints is not
    the same claim, and a signal that fires on the ordinary case stops being read.
    So is a DAMAGED member (v0.7.86): the tree is whole, one file in it is not a
    faithful copy, and that belongs in `damaged_acquisitions` where it does not
    dilute this list. Until that split, every acquisition carrying an open .lck
    landed here -- on three real cases, eight of eighteen entries, and one case
    whose only entries were those -- which is this docstring's own warning
    happening to it.
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


def damaged_acquisitions(results: list[ExtractResult]) -> list[dict]:
    """The acquisitions whose tree is whole and holds a member that is not.

    A smaller claim than `incomplete_acquisitions` and a different one, so it is
    reported apart and does NOT make a run incomplete. What is on disk is
    everything the archive held; one member's bytes are not the bytes that were
    on the host, because it was being written while it was collected or because
    its checksum failed.

    Worth saying anyway, and worth saying separately. A hole is quiet -- a parser
    finds no input and self-gates into `skipped`. A damaged member is the
    opposite: the parser finds input, reads it, and reports. A corrupt event log
    or hive produces a table, and nothing about that table says the bytes under
    it were already wrong. The usual cause is harmless (a lock file, a .LOG1, a
    write-ahead log -- files no parser reads), which is why this cannot be allowed
    to decide the verdict; the unusual one is not, which is why it is printed.
    """
    return [{"archive": r.archive.name, "status": "damaged",
             "detail": r.warning_detail}
            for r in results if r.ok and not r.partial and r.damaged]


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
        came_from = recorded_name(dest)
        if came_from and came_from != _flat(path.name):
            # A DIFFERENT archive folding to the same destination -- `HOST-01.zip`
            # beside `HOST-01.7z`, `logs.zip` beside `logs.tar.gz`. Before the name
            # was recorded this archive adopted the other one's tree and was
            # reported as extracted: a clean verdict over an archive nobody opened.
            # It is not a changed upload, and the tree is not this archive's to
            # delete, so what is said is rename, not delete.
            clash = (f"was NOT extracted: {dest.name} came out of {came_from}, and two "
                     f"archives whose names fold to the same destination cannot share "
                     f"it -- rename one of them")
            log.warning(f"[!] {path.name}: {clash}")
            return ExtractResult(path, dest, ok=True, warnings=True, partial=True,
                                 warning_detail=clash)
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
                             warning_detail=detail, partial=status == EXTRACT_PARTIAL,
                             damaged=status == EXTRACT_DAMAGED)
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
    damage = ""
    try:
        if kind == "zip":
            san, sk, coll = _extract_zip(path, dest)
        elif kind == "tar":
            san, sk, coll, damage = _extract_tar(path, dest)
            if damage and seven is not None:
                # With a 7-Zip on the host a damaged tarball goes to it exactly as
                # it did before streaming existed: the retry below clears what was
                # kept and lets 7-Zip read the archive its own way.
                raise _Damaged(damage)
        elif kind == "gz":
            san, sk, coll = _extract_gz(path, dest)
        elif kind == "7z":
            try:
                san, sk, coll = _extract_7z_native(path, dest)
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
            san, sk, used_7z, coll = 0, 0, True, []
        except Exception as e2:  # noqa: BLE001
            return ExtractResult(path, dest, ok=False, error=f"7-Zip: {e2}")
        _mark_done(marker, status, detail, archive=path)
        return ExtractResult(
            path, dest, ok=True, sanitized=san, skipped=sk, used_7z=used_7z,
            warnings=status != EXTRACT_OK, warning_detail=detail,
            partial=status == EXTRACT_PARTIAL, damaged=status == EXTRACT_DAMAGED,
        )
    if damage:
        # Reached only with no 7-Zip on the host (see the tar branch above). What
        # came out before the damage is whole and is KEPT; the acquisition is
        # PARTIAL, through the marker, so a later run that adopts this destination
        # still says so.
        detail = damage
        if coll:
            detail += f"; {collision_detail(coll)}"
        log.warning(f"[!] {path.name}: {detail}")
        for c in coll:
            log.warning(f"        {c}")
        _mark_done(marker, EXTRACT_PARTIAL, detail, archive=path)
        return ExtractResult(path, dest, ok=True, sanitized=san, skipped=sk,
                             used_7z=used_7z, warnings=True, warning_detail=detail,
                             partial=True, collisions=coll)
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
        return ExtractResult(path, dest, ok=True, sanitized=san, skipped=sk,
                             used_7z=used_7z, warnings=True, warning_detail=detail,
                             partial=True, collisions=coll)
    _mark_done(marker, archive=path)
    return ExtractResult(path, dest, ok=True, sanitized=san, skipped=sk, used_7z=used_7z)


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
    warn_archiver: bool = True,
    hold: set[Path] | frozenset[Path] = frozenset(),
) -> list[ExtractResult]:
    """Extract the parent acquisitions (and nested wrappers) IN PARALLEL.

    Only handles CONTAINERS (zip/tar/tar.gz/7z); standalone .gz (rotated logs,
    memory dumps) are left compressed. Recurses only into containers that hang
    directly off an already-extracted destination (the 'zip inside zip' case).

    `warn_archiver=False` for a caller that has already said it -- `cmd_run` asks
    `archiver_warning` before phase 0, which is the point of asking at all, and
    the same line twice in one run is noise. A library caller still gets it.
    """
    seven = find_7z(tools_dir)
    if not seven and warn_archiver:
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
