r"""Ransomware traces in a filesystem listing, counted rather than matched.

The engine has had no ransomware detection at all. It has two filesystem
listings that already contain the whole answer -- the transcoded `$MFT` on
Windows and the bodyfile on Linux -- and `aeng update` now fetches the two
community lists that name what to look for. This module is the half both
platforms share.

WHY A MATCH IS NOT A VERDICT. The extension list is a list of REAL FILE TYPES:
`.frag` is a GLSL shader, `.razor` a Blazor component, `.enc`, `.lock`, `.crypt`,
`.AES` and `.money` are all extensions ordinary software writes. A handler that
flags a filename because it ends in one of them reports every developer
workstation in the estate. So an extension match is only ever a COUNT, and what
decides is the company the files keep -- the same reasoning the timestomp
detectors use, for the same reason.

WHAT ACTUALLY SEPARATES THEM:

- THE NOTE. `HOW_TO_DECRYPT.txt`, `README_C_I_0P.TXT`, `@READ_IT@.txt` -- those
  filenames occur for one reason. A single one is a finding on its own, and it
  corroborates every extension group on the same volume.
- THE DOUBLE EXTENSION. Ransomware that appends leaves `report.docx.locked`; a
  Blazor component is `Counter.razor`, never `Counter.cshtml.razor`. Where the
  matched extension sits AFTER a document extension, the shape is the rename.
- THE BURST. A run writes thousands of files across hundreds of directories in
  minutes. Without a note and without the double-extension shape a group is
  reported with its counts and its window and left unflagged, saying so -- a
  `git clone` of a Blazor repository writes five hundred `.razor` files across
  many directories in one second, and it is not ransomware.

AND THE FAMILY NOBODY HAS PUBLISHED YET. `mass_rename` applies the
double-extension test to extensions that are on NO list: a document extension
followed by something else, on enough files to be a run. That is the kind this
exists for, because a detector that can only find what the list already names is
a detector that finds last year's ransomware.

Unlike the service and task lists, neither of these carries `metadata_tool_type`,
so nothing here can be greyware and the selectivity has to come entirely from the
artifact.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.handlers import _awesome

NOTES_LIST = "ransomware_notes_list.csv"
EXTENSIONS_LIST = "ransomware_extensions_list.csv"

# What a ransom note is worth on its own, and what an extension needs.
_MIN_RENAMED = 5          # below this a group is counted, not listed
_MIN_BURST = 50           # flag-eligible without a note
_MIN_MASS = 25            # list-free double-extension groups
_DOUBLE_SHARE = 0.5       # share of a group that must carry the rename shape

# Bounds. A run the attacker controls must not become a memory problem.
_MAX_GROUPS = 20_000
_MAX_DIRS = 10_000
_MAX_ROWS = 500

# Extensions a rename leaves BEHIND: what the file was before it was encrypted.
# Deliberately the ordinary contents of a share -- an archive that ends
# `.tar.gz` is not this shape, because `tar` is not in here.
DOC_EXTS = frozenset({
    "doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "xlsb",
    "ppt", "pptx", "pptm", "pdf", "rtf", "txt", "csv", "odt", "ods", "odp",
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "psd", "ai", "eps", "dwg",
    "zip", "rar", "7z", "sql", "mdb", "accdb", "bak",
    "mp3", "mp4", "avi", "mov", "wav", "pst", "ost", "msg", "eml",
    "vhd", "vhdx", "vmdk", "vdi", "qcow2", "db", "sqlite", "dbf", "xml",
})

# Trailing extensions that follow a document extension for ordinary reasons:
# compression, backups, part-downloads, checksums, editor scratch files. Without
# these `mass_rename` reports every backup server (`dump.sql.gz`) and every
# document converter (`report.docx.pdf`, caught by the DOC_EXTS test above).
_BENIGN_TRAILING = frozenset({
    "gz", "bz2", "xz", "zst", "lz4", "lzma", "tar", "tgz", "z",
    "bak", "backup", "bkp", "tmp", "temp", "old", "orig", "save",
    "part", "partial", "crdownload", "download", "filepart",
    "lnk", "url", "sig", "asc", "gpg", "pgp",
    "md5", "sha1", "sha256", "sha512", "sums", "crc", "torrent",
    "swp", "swo", "swn", "lock", "meta", "thumb", "nfo",
    "log", "err", "out", "ini", "cfg", "conf",
    "journal", "wal", "shm", "idx", "index", "cache",
})

# A ransomware extension is a short alphanumeric token. A twenty-character
# trailing component is a filename that happens to contain dots.
_MAX_EXT_LEN = 12
_EXT_OK = re.compile(r"\A[a-z0-9_-]+\Z")

_TS = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)")

_COLUMNS = ["kind", "marker", "files", "directories", "double_extension",
            "first_modified_utc", "last_modified_utc", "span_hours", "example",
            "family", "reference", "note", "suspicious"]


def parse_time(value: str) -> datetime | None:
    m = _TS.match((value or "").strip())
    if not m:
        return None
    try:
        return datetime(*map(int, m.groups()), tzinfo=timezone.utc)
    except ValueError:
        return None


def extensions(name: str) -> tuple[str, str]:
    """(the extension before the last one, the last one), lower-cased, no dots.

    `report.docx.locked` -> `("docx", "locked")`; `Counter.razor` -> `("",
    "razor")`. The first half is the whole double-extension test.
    """
    parts = (name or "").rsplit(".", 2)
    if len(parts) < 2 or not parts[-1]:
        return "", ""
    return (parts[-2].lower() if len(parts) == 3 else ""), parts[-1].lower()


def load_lists(assets: Path) -> tuple[list[_awesome.Entry], list[_awesome.Entry]]:
    """(ransom notes, encrypted-file extensions), each [] when not downloaded."""
    return (
        _awesome.load(assets, NOTES_LIST, key="file_name",
                      extra_key="metadata_description"),
        _awesome.load(assets, EXTENSIONS_LIST, key="file_path",
                      extra_key="metadata_comment"),
    )


class _Group:
    """One marker's footprint: how many files, how spread out, and how fast."""

    __slots__ = ("capped", "count", "dirs", "doubles", "family", "first",
                 "last", "reference", "sample")

    def __init__(self) -> None:
        self.count = self.doubles = 0
        self.dirs: set[str] = set()
        self.capped = False
        self.first = self.last = ""
        self.sample = ""
        self.family = self.reference = ""

    def add(self, path: str, folder: str, mtime: str, double: bool) -> None:
        self.count += 1
        self.doubles += 1 if double else 0
        if len(self.dirs) < _MAX_DIRS:
            self.dirs.add(folder.lower())
        else:
            self.capped = True
        if mtime:
            self.first = mtime if not self.first else min(self.first, mtime)
            self.last = max(self.last, mtime)
        if not self.sample:
            self.sample = path

    @property
    def span_hours(self) -> int | None:
        a, b = parse_time(self.first), parse_time(self.last)
        return None if a is None or b is None else int((b - a).total_seconds() // 3600)


class Traces:
    """Every marker seen while streaming a filesystem listing."""

    def __init__(self) -> None:
        self.groups: dict[tuple[str, str], _Group] = {}
        self.dropped_groups = 0

    def add(self, kind: str, marker: str, path: str, folder: str, mtime: str,
            double: bool, family: str = "", reference: str = "") -> None:
        key = (kind, marker)
        grp = self.groups.get(key)
        if grp is None:
            if len(self.groups) >= _MAX_GROUPS:
                self.dropped_groups += 1
                return
            grp = self.groups[key] = _Group()
            grp.family, grp.reference = family, reference
        grp.add(path, folder, mtime, double)

    @property
    def note_found(self) -> bool:
        """Whether a ransom note was seen anywhere in this listing."""
        return any(kind == "note" for kind, _ in self.groups)


def _verdict(kind: str, grp: _Group, note_found: bool) -> tuple[bool, str]:
    """(flagged, why not) for one group."""
    if kind == "note":
        return True, ""
    shape = grp.doubles >= max(1, int(grp.count * _DOUBLE_SHARE))
    if kind == "mass_rename":
        return True, ""
    if note_found:
        return True, "a ransom note was found on this volume"
    if shape and grp.count >= _MIN_BURST:
        return True, ""
    if shape:
        return False, (f"renamed shape on {grp.doubles:,} file(s), fewer than the "
                       f"{_MIN_BURST} a run writes")
    return False, ("this extension is also a real file type, and nothing here "
                   "corroborates a run: no ransom note, no renamed shape")


def rows(traces: Traces) -> list[list]:
    """The table, most serious first, saying what it left out."""
    note_found = traces.note_found
    out: list[tuple[tuple, list]] = []
    quiet = 0
    for (kind, marker), grp in traces.groups.items():
        if kind == "renamed" and grp.count < _MIN_RENAMED and not grp.doubles:
            quiet += 1
            continue
        if kind == "mass_rename" and grp.count < _MIN_MASS:
            quiet += 1
            continue
        flagged, why = _verdict(kind, grp, note_found)
        span = grp.span_hours
        dirs = f"{len(grp.dirs):,}+" if grp.capped else f"{len(grp.dirs):,}"
        out.append(((0 if flagged else 1, -grp.count), [
            kind, marker, grp.count, dirs, grp.doubles or "",
            grp.first, grp.last, "" if span is None else span, grp.sample,
            grp.family, grp.reference, why, "yes" if flagged else "",
        ]))

    out.sort(key=lambda pair: pair[0])
    table = [row for _, row in out[:_MAX_ROWS]]
    hidden = len(out) - len(table)
    if quiet or hidden or traces.dropped_groups:
        table.append([
            "(not listed)", "", "", "", "", "", "", "", "", "", "",
            (f"{quiet:,} extension group(s) below the reporting threshold, "
             f"{hidden:,} beyond the {_MAX_ROWS}-row cap, "
             f"{traces.dropped_groups:,} file(s) past the group cap"), "",
        ])
    return table


def columns() -> list[str]:
    return list(_COLUMNS)


def unpublished_rename(prev: str, last: str) -> bool:
    """Whether `<stem>.<prev>.<last>` is the rename shape and nothing else.

    A document extension followed by something that is neither a document
    extension (a converter wrote `report.docx.pdf`) nor one of the ordinary
    trailing components (`dump.sql.gz`, `notes.txt.bak`), and short enough to be
    an extension at all.
    """
    return (prev in DOC_EXTS and last not in DOC_EXTS
            and last not in _BENIGN_TRAILING and not last.isdigit()
            and len(last) <= _MAX_EXT_LEN and bool(_EXT_OK.match(last)))


def classify(name: str, notes: list[_awesome.Entry],
             exts: list[_awesome.Entry]) -> tuple[str, str, str, str, bool] | None:
    """(kind, marker, family, reference, is a double extension) for one filename.

    None when the file says nothing. The note list is asked first: a ransom note
    is a note even when its extension is on the other list too.
    """
    if not name:
        return None
    hit = _awesome.match(notes, name)
    if hit is not None:
        return "note", name.lower(), hit.extra, hit.reference, False

    prev, last = extensions(name)
    if not last:
        return None
    double = prev in DOC_EXTS
    hit = _awesome.match(exts, name) or _awesome.match(exts, f".{last}")
    if hit is not None:
        return "renamed", f".{last}", hit.extra, hit.reference, double
    if unpublished_rename(prev, last):
        return "mass_rename", f".{last}", "", "", True
    return None
