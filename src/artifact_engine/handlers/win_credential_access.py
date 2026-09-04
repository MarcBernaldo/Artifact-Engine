r"""Handler: credential material staged for collection. Output: credential_access.csv

A harvest that copied SSH `known_hosts`, browser credential databases, DPAPI
master keys and registry hives into one directory, archived it and deleted the
tree was entirely visible in the `$MFT` and entirely unflagged. It was found by
listing a temp directory by hand. Nothing here needs an IOC, a hash or a
signature: every one of these files is ordinary IN ITS OWN PLACE and means
something else anywhere in particular.

THE RULE IS THE LOCATION, NOT THE NAME. `SAM` under `System32\config` is the
operating system; `SAM` under a temp directory is `reg save`. `Login Data` in a
Chrome profile is Chrome; the same file beside a copy of `NTUSER.DAT` is a
collection. So every family below is defined as a set of names PLUS the set of
paths where those names belong, and only the difference is reported.

THE STAGING HEURISTIC IS THE POINT. One stray `known_hosts` is noise -- people
copy their own key material around, and a detector that flags it will be turned
off. Two DIFFERENT families in one directory is not noise: nothing legitimate
puts a registry hive next to a browser credential database. So the families are
counted per directory, the count is what decides, and the row is the DIRECTORY
rather than the files, which turns a dozen scattered rows into one sentence an
incident lead can act on. A harvest that sorts its loot into subdirectories is
still one tree, so a directory is judged together with its immediate children.

DELETED FILES ARE THE EVIDENCE, NOT AN OBSTACLE. The tree is normally removed
after it is archived, so nothing here filters on `InUse`: a staged directory
whose files are all gone is a stronger finding than one still sitting there, and
`deleted_files` says which it is.

AND THE ARCHIVE. Once a directory qualifies, the volume is re-read for archives
written near it in time -- deleted ones included, since the package is deleted
too. That is the sentence worth writing down: these credential classes left this
host.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv

_MFT_CSV = Path("CSVs") / "Filesystem" / "MFT.csv"

# --------------------------------------------------------------------------- #
# The families, each a set of names and the places those names belong
# --------------------------------------------------------------------------- #

# Secret-bearing hives only. NTUSER.DAT and SOFTWARE are deliberately absent:
# they are copied around by roaming profiles and backup software constantly, and
# the two that matter are the two an attacker asks for by name.
_HIVE_STEMS = {"sam", "security", "system", "ntds"}
_HIVE_EXTS = {"", ".hiv", ".hive", ".save", ".bak", ".old", ".dit", ".dat"}
_HIVE_HOME = (
    "\\windows\\system32\\config\\",
    "\\windows\\repair\\",
    "\\windows\\ntds\\",
    "\\windows\\system32\\smi\\store\\machine\\",
    # WinSxS carries the pristine hive templates servicing installs from -- files
    # literally named SAM, SECURITY and SYSTEM, on every healthy machine.
    "\\windows\\winsxs\\",
    "\\windows\\panther\\",
    "\\windows\\servicing\\",
)

# DPAPI master keys, the credential history, and the Vault / Credential Manager
# stores. All of them live under a profile; none of them travels.
_SECRET_DIRS = ("\\microsoft\\protect\\", "\\microsoft\\credentials\\",
                "\\microsoft\\vault\\")
_SECRET_NAMES = {"credhist"}
_SECRET_HOME = (
    "\\appdata\\roaming\\microsoft\\", "\\appdata\\local\\microsoft\\",
    "\\windows\\system32\\microsoft\\protect\\",
    "\\windows\\serviceprofiles\\",
    "\\windows\\system32\\config\\systemprofile\\",
)

_BROWSER_NAMES = {"login data", "login data for account", "web data",
                  "key3.db", "key4.db", "cert9.db", "logins.json",
                  "signons.sqlite"}
_BROWSER_HOME = (
    "\\appdata\\local\\google\\", "\\appdata\\local\\microsoft\\edge\\",
    "\\appdata\\local\\chromium\\", "\\appdata\\local\\bravesoftware\\",
    "\\appdata\\local\\vivaldi\\", "\\appdata\\local\\yandex\\",
    "\\appdata\\local\\packages\\", "\\appdata\\local\\mozilla\\",
    "\\appdata\\roaming\\mozilla\\", "\\appdata\\roaming\\opera software\\",
    "\\appdata\\roaming\\thunderbird\\", "\\appdata\\local\\thunderbird\\",
)

_SSH_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity",
              "known_hosts", "authorized_keys"}
_SSH_EXTS = {".ppk"}
_SSH_HOME = ("\\.ssh\\", "\\programdata\\ssh\\",
             "\\windows\\system32\\openssh\\", "\\etc\\ssh\\")

# Process memory and Kerberos tickets: unambiguous wherever they are, so these
# have no home directory at all.
_DUMP_EXTS = {".kirbi", ".ccache"}

_FAMILY_ORDER = ("registry_hive", "credential_dump", "dpapi",
                 "browser_credentials", "ssh_material")

# Families that mean something on their own. A stray `known_hosts` or a copied
# browser profile does not; a registry hive outside System32 or an LSASS dump
# anywhere does.
_ALONE = {"registry_hive", "credential_dump"}

_ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".cab", ".tar", ".gz", ".tgz", ".iso",
                 ".wim", ".bz2", ".xz", ".zipx", ".arj", ".ace"}

# How far from the credential material an archive still counts as its package.
_ARCHIVE_WINDOW_MIN = 60

_MAX_DIRS = 50_000
_MAX_ROWS = 500
_EXAMPLES = 3

_COLUMNS = ["kind", "path", "families", "files", "deleted_files", "bytes",
            "first_created_utc", "last_created_utc", "examples", "note",
            "suspicious"]


def norm(path: str) -> str:
    r"""A `$MFT` path as `\lower\case\with\edges\`, so a location test is a
    substring test. MFTECmd writes ParentPath rooted at `.` -- that leading dot
    is not a directory and must not become one."""
    text = (path or "").strip().replace("/", "\\")
    if text.startswith(".\\"):
        text = text[1:]
    elif text == ".":
        text = "\\"
    text = text.strip("\\").lower()
    return f"\\{text}\\" if text else "\\"


def _at_home(folder: str, homes: tuple[str, ...]) -> bool:
    return any(h in folder for h in homes)


def family_of(folder: str, name: str, ext: str) -> str:
    """Which credential family this file belongs to, or "" when it is ordinary.

    `folder` is already normalised; `name` and `ext` are lower-cased.
    """
    stem = name[: -len(ext)] if ext and name.endswith(ext) else name

    if "lsass" in stem or ext in _DUMP_EXTS:
        return "credential_dump"
    if stem in _HIVE_STEMS and ext in _HIVE_EXTS and not _at_home(folder, _HIVE_HOME):
        return "registry_hive"
    if ((name in _SECRET_NAMES or _at_home(folder, _SECRET_DIRS))
            and not _at_home(folder, _SECRET_HOME)):
        return "dpapi"
    if name in _BROWSER_NAMES and not _at_home(folder, _BROWSER_HOME):
        return "browser_credentials"
    if ((name in _SSH_NAMES or ext in _SSH_EXTS)
            and not _at_home(folder, _SSH_HOME)):
        return "ssh_material"
    return ""


def parent_of(folder: str) -> str:
    """The directory above a normalised one; `\\` is its own parent."""
    trimmed = folder.strip("\\")
    if not trimmed or "\\" not in trimmed:
        return "\\"
    return "\\" + trimmed.rsplit("\\", 1)[0] + "\\"


def _dt(value: str) -> datetime | None:
    text = (value or "").strip().replace("T", " ")[:19]
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class _Dir:
    """The credential material found in one directory."""

    __slots__ = ("bytes", "deleted", "examples", "families", "files", "first", "last")

    def __init__(self) -> None:
        self.families: set[str] = set()
        self.files = self.deleted = self.bytes = 0
        self.first = self.last = ""
        self.examples: list[str] = []

    def add(self, name: str, family: str, created: str, size: str, gone: bool) -> None:
        self.families.add(family)
        self.files += 1
        self.deleted += 1 if gone else 0
        try:
            self.bytes += int(float(size or 0))
        except ValueError:
            pass
        if created:
            self.first = created if not self.first else min(self.first, created)
            self.last = max(self.last, created)
        if len(self.examples) < _EXAMPLES:
            self.examples.append(name)

    def merge(self, other: _Dir) -> None:
        self.families |= other.families
        self.files += other.files
        self.deleted += other.deleted
        self.bytes += other.bytes
        if other.first:
            self.first = other.first if not self.first else min(self.first, other.first)
            self.last = max(self.last, other.last)
        for name in other.examples:
            if len(self.examples) < _EXAMPLES:
                self.examples.append(name)


def _true(value: str) -> bool:
    return (value or "").strip().lower() in ("true", "1", "yes")


def _open(src: Path):
    try:
        return src.open("r", encoding="utf-8-sig", errors="replace", newline="")
    except OSError as e:
        raise HandlerSkip(f"MFT.csv unreadable: {e}") from e


def _reader(fh):
    """(row reader, column index) for an MFTECmd CSV, or a skip."""
    reader = csv.reader(line.replace("\x00", "") for line in fh)
    header = next(reader, None)
    if not header:
        raise HandlerSkip("MFT.csv is empty")
    idx = {name.strip(): i for i, name in enumerate(header)}
    if "FileName" not in idx or "ParentPath" not in idx:
        raise HandlerSkip("MFT.csv has no path columns")
    return reader, idx


def _scan(src: Path) -> dict[str, _Dir]:
    """Every directory holding credential material, deleted files included."""
    dirs: dict[str, _Dir] = {}
    with _open(src) as fh:
        reader, idx = _reader(fh)

        def cell(row: list, name: str) -> str:
            i = idx.get(name)
            return row[i] if i is not None and i < len(row) else ""

        for row in reader:
            if _true(cell(row, "IsDirectory")):
                continue
            name = cell(row, "FileName").strip().lower()
            if not name:
                continue
            folder = norm(cell(row, "ParentPath"))
            ext = cell(row, "Extension").strip().lower()
            if not ext and "." in name:
                ext = name[name.rindex("."):]
            family = family_of(folder, name, ext)
            if not family:
                continue
            if folder not in dirs and len(dirs) >= _MAX_DIRS:
                continue
            dirs.setdefault(folder, _Dir()).add(
                name, family, cell(row, "Created0x10"), cell(row, "FileSize"),
                # Nothing filters on InUse: the staged tree is normally deleted,
                # so a directory whose files are all gone is the stronger finding.
                not _true(cell(row, "InUse")))
    return dirs


def staging_roots(dirs: dict[str, _Dir]) -> dict[str, _Dir]:
    """Directories holding two different families, judged with their children.

    A harvest that sorts its loot into `hives\\` and `browsers\\` is one tree and
    deserves one row, so a directory is counted together with its immediate
    children. That rollup has to stop at the right level, though, or a tree in
    `\\Windows\\Temp\\stage\\` gets reported as `\\Windows\\Temp` -- naming the
    temp directory instead of the harvest. So a directory that qualifies ON ITS
    OWN is always the row, a parent only becomes one when the material is spread
    across its children, and a qualifying directory under one that already
    qualified is not reported twice.
    """
    merged: dict[str, _Dir] = {}
    for folder, rec in dirs.items():
        merged.setdefault(folder, _Dir()).merge(rec)
        parent = parent_of(folder)
        if parent != folder:
            merged.setdefault(parent, _Dir()).merge(rec)

    candidates = {f for f, r in merged.items() if len(r.families) >= 2}
    parents = {parent_of(f) for f in candidates} - {""}
    alone = {f for f, r in dirs.items() if len(r.families) >= 2}
    roots = alone | (candidates - parents)
    return {f: merged[f] for f in roots if not _has_root_ancestor(f, roots)}


def _has_root_ancestor(folder: str, roots: set[str]) -> bool:
    """Whether some directory above this one already covers the same tree."""
    seen = {folder}
    parent = parent_of(folder)
    while parent not in seen:
        if parent in roots:
            return True
        seen.add(parent)
        parent = parent_of(parent)
    return False


def _near(archive: str, first: str, last: str) -> int | None:
    """Minutes between an archive and the credential window, or None if outside."""
    when, a, b = _dt(archive), _dt(first), _dt(last)
    if when is None or a is None or b is None:
        return None
    if when < a:
        gap = int((a - when).total_seconds() // 60)
    elif when > b:
        gap = int((when - b).total_seconds() // 60)
    else:
        gap = 0
    return gap if gap <= _ARCHIVE_WINDOW_MIN else None


def _archives(src: Path, roots: dict[str, _Dir]) -> list[list]:
    """Archives written near a staging directory, the deleted ones included."""
    # A package is written beside the tree or one level above it. The root's own
    # entry is set last, so a root that happens to be another root's parent keeps
    # its own window rather than borrowing its child's.
    watched: dict[str, str] = {}
    for folder in roots:
        watched[parent_of(folder)] = folder
    for folder in roots:
        watched[folder] = folder

    rows: list[list] = []
    with _open(src) as fh:
        reader, idx = _reader(fh)

        def cell(row: list, name: str) -> str:
            i = idx.get(name)
            return row[i] if i is not None and i < len(row) else ""

        for row in reader:
            if _true(cell(row, "IsDirectory")):
                continue
            name = cell(row, "FileName").strip()
            ext = cell(row, "Extension").strip().lower()
            if not ext and "." in name:
                ext = name[name.rindex("."):].lower()
            if ext not in _ARCHIVE_EXTS:
                continue
            folder = norm(cell(row, "ParentPath"))
            root = watched.get(folder)
            if root is None:
                continue
            created = cell(row, "Created0x10")
            gap = _near(created, roots[root].first, roots[root].last)
            if gap is None:
                continue
            gone = not _true(cell(row, "InUse"))
            rows.append([
                "archive", f"{folder}{name}", "", 1, 1 if gone else "",
                cell(row, "FileSize"), created, created, name,
                (f"written {gap} minute(s) from the credential material in "
                 f"{root}" + ("; the archive itself is DELETED" if gone else "")),
                "yes",
            ])
    return rows


def _dir_row(kind: str, folder: str, rec: _Dir, note: str, flagged: bool) -> list:
    return [kind, folder, " ".join(f for f in _FAMILY_ORDER if f in rec.families),
            rec.files, rec.deleted or "", rec.bytes or "", rec.first, rec.last,
            " ".join(rec.examples), note, "yes" if flagged else ""]


def _note_for(rec: _Dir, staged: bool) -> str:
    if staged:
        gone = (f"; all {rec.deleted:,} of them are DELETED" if rec.deleted == rec.files
                else f"; {rec.deleted:,} of them deleted" if rec.deleted else "")
        return (f"{len(rec.families)} credential families in one tree{gone}")
    family = next(iter(rec.families), "")
    if family in _ALONE:
        return f"{family.replace('_', ' ')} outside the place it belongs"
    return ("one family only: people copy their own key material around, and this "
            "is a finding when something else joins it")


def run(ctx) -> None:
    src = Path(ctx.evidence) / _MFT_CSV
    if not src.is_file():
        raise HandlerSkip("no MFT.csv to read")

    dirs = _scan(src)
    if not dirs:
        return                                # nothing to say, and no empty table

    roots = staging_roots(dirs)
    rows: list[list] = []
    for folder, rec in roots.items():
        rows.append(_dir_row("staging", folder, rec, _note_for(rec, True), True))
    for folder, rec in dirs.items():
        # A staging row already counts the root and its immediate children; a row
        # of their own would be the same files twice.
        if folder in roots or parent_of(folder) in roots:
            continue
        flagged = bool(rec.families & _ALONE)
        rows.append(_dir_row("misplaced", folder, rec, _note_for(rec, False), flagged))

    # Only worth a second pass over a very large CSV once something qualified.
    if roots:
        rows.extend(_archives(src, roots))

    rows.sort(key=lambda r: (r[-1] != "yes", {"archive": 0, "staging": 1}.get(r[0], 2),
                             r[1]))
    hidden = max(0, len(rows) - _MAX_ROWS)
    rows = rows[:_MAX_ROWS]
    if hidden:
        rows.append(["(not listed)", "", "", "", "", "", "", "", "",
                     (f"{hidden:,} further directory row(s) beyond the "
                      f"{_MAX_ROWS}-row cap"), ""])
    write_csv(ctx.out, "credential_access.csv", _COLUMNS, rows)
