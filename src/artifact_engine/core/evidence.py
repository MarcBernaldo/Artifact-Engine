r"""Resolving a declared path against the tree that is actually on disk.

Every `requires:` in a parser manifest, every `exists:` in a profile and every
`{evidence}/...` in a command template names a path in ONE fixed spelling:
`Windows/System32/winevt/Logs`. Whether that spelling is the one on disk was
never a question on NTFS, which answers to any of them. On a case-sensitive
filesystem it is the whole question, and getting it wrong is silent in the worst
way this project has:

    an acquisition stored as `windows/` matches no `requires`, so the parser is
    never SELECTED. It does not error and it does not run -- it is counted as
    `skipped`, next to every artifact the host genuinely does not have. The run
    ends "OK 2 | skipped 37 | errors 0", which is what a clean triage of a quiet
    host looks like.

So a lookup that misses is retried against the directory's real contents, and
the answer is the real path. Used on BOTH platforms with no conditional: on
Windows the first attempt always succeeds and nothing below it ever runs, and
one code path is what stops the two systems drifting apart unnoticed.

WHY LAZY, AND NOT AN INDEX OF THE TREE. Indexing a KAPE acquisition up front
costs a full walk of hundreds of thousands of entries per machine -- to answer
questions that the plain `exists()` almost always answers on its own, and that
most parsers ask about paths which are simply not there. Here a miss walks only
the directories on that one path, and remembers each listing it had to read. A
hit costs a single stat.

NOTHING IS WRITTEN. The evidence tree is read-only as far as this module is
concerned: the destination probe that phase 1 uses (`extractor._case_insensitive`)
creates a file, which is fine in a directory being extracted into and is not fine
here. It is also unnecessary -- on a filesystem that folds case the first attempt
already answered, so the fallback below simply never finds anything the fast path
missed.
"""

from __future__ import annotations

import os
import string
from pathlib import Path

# {directory: {lowercased entry name: [real entry names]}}, filled only for the
# directories a failed lookup actually had to read. Plain dict reads and writes
# under the GIL: two workers racing on the same directory duplicate a `scandir`
# and agree on the result, which is cheaper than holding a lock across I/O.
#
# A LIST per key, not one name: a case-sensitive acquisition can hold `NTUSER.DAT`
# and `ntuser.dat` side by side, and keeping only the first would make the choice
# between them invisible. It also means the ambiguity check costs nothing -- the
# first version of this re-ran `scandir` to look for siblings every time a
# component resolved by case, which on a consistently lowercased tree is every
# component of every lookup.
_LISTINGS: dict[Path, dict[str, list[str]]] = {}

# Lookups whose case-insensitive answer was not unique -- `NTUSER.DAT` and
# `ntuser.dat` side by side, which a case-sensitive acquisition can hold and this
# module then has to CHOOSE between. Recorded rather than decided in silence.
_AMBIGUOUS: dict[str, list[str]] = {}


def parts_of(rel: str) -> list[str]:
    r"""The components of a declared relative path.

    Manifests are written with `/`, handlers reach for `\`, and both spellings
    mean the same artifact. `.` and empty components are dropped; `..` is left
    alone deliberately -- nothing in this engine declares one, and quietly
    resolving it here would turn a manifest typo into a read outside the volume.
    """
    text = str(rel or "").replace("\\", "/")
    return [p for p in text.split("/") if p not in ("", ".")]


def _listing(directory: Path) -> dict[str, list[str]]:
    """{lowercased name: [real names]} for one directory, read at most once."""
    cached = _LISTINGS.get(directory)
    if cached is not None:
        return cached
    entries: dict[str, list[str]] = {}
    try:
        with os.scandir(directory) as it:
            for entry in it:
                entries.setdefault(entry.name.lower(), []).append(entry.name)
    except OSError:
        pass                    # unreadable or gone: no candidates, not an error
    for names in entries.values():
        names.sort()            # a stable choice when there is more than one
    _LISTINGS[directory] = entries
    return entries


def resolve(root: Path | str, rel: str) -> Path | None:
    """The real path of `rel` under `root`, or None when nothing matches.

    Exact spelling first -- one stat, and the only cost on Windows or on a
    correctly-cased tree. Only a miss walks the components.
    """
    base = Path(root)
    parts = parts_of(rel)
    # Before the fast path, not after: `exists()` collapses `..` itself, so
    # `Windows/../../elsewhere` would come back as a real path OUTSIDE the volume
    # -- resolved by pathlib, never seen by the walk below. Nothing in this engine
    # declares a parent reference, so one is a manifest typo, and the answer to a
    # typo is `None` rather than a read somewhere else on the disk.
    if any(p == ".." for p in parts):
        return None
    if not parts:
        return base if base.exists() else None

    exact = base.joinpath(*parts)
    if exact.exists():
        return exact

    current = base
    if not current.is_dir():
        return None
    for i, part in enumerate(parts):
        found = _listing(current).get(part.lower())
        if not found:
            return None
        if len(found) > 1 and part not in found:
            # Two real files answer to this name and the declared spelling is
            # neither, so which one the parser reads is a coin toss. Recorded --
            # on a case-sensitive acquisition these are two different files.
            _AMBIGUOUS.setdefault("/".join(parts[:i + 1]), list(found))
        current = current / (part if part in found else found[0])
        if i < len(parts) - 1 and not current.is_dir():
            return None
    return current if current.exists() else None


def exists(root: Path | str, rel: str) -> bool:
    """Whether `rel` is present under `root`, whatever its spelling."""
    return resolve(root, rel) is not None


def in_tree(root: Path | str, rel: str) -> Path:
    """The real path of `rel` under `root`, or the plain join when it is absent.

    What a handler wants: the caller's own `is_dir()` / `is_file()` stays the
    gate, so `resolve` slots in without turning every artifact check into a
    None check -- and a handler whose skip message names the path it wanted
    still names a real one. Use `resolve` where the difference matters.
    """
    return resolve(root, rel) or Path(root).joinpath(*parts_of(rel))


def _ci_pattern(pattern: str) -> str:
    """A glob pattern that matches regardless of case.

    Each letter becomes its own character class, so `*.evtx` becomes
    `*.[eE][vV][tT][xX]`. Done this way rather than by lowercasing and comparing
    by hand because it keeps pathlib's own `**` semantics, which `fnmatch` does
    not share -- the profiles rely on `**/*` meaning what pathlib says it means.

    A class already in the pattern is left alone. Callers wrote `PSRead[Ll]ine`
    by hand for years before this module existed, and expanding the letters
    INSIDE it would produce `[[lL][lL]]`, which is not the same pattern and not
    obviously broken to look at.
    """
    out: list[str] = []
    in_class = False
    for c in pattern:
        if in_class:
            out.append(c)
            in_class = c != "]"
        elif c == "[":
            out.append(c)
            in_class = True
        elif c in string.ascii_letters:
            out.append(f"[{c.lower()}{c.upper()}]")
        else:
            out.append(c)
    return "".join(out)


def any_match(root: Path | str, pattern: str) -> bool:
    """Whether any entry under `root` matches `pattern`, ignoring case.

    Kept separate from `iglob` so it stays lazy: the profiles glob `**/*` to ask
    whether a drop folder has anything in it at all, and collecting an answer
    would walk the whole tree to decide a question the first hit settles.
    """
    base = Path(root)
    try:
        if any(base.glob(pattern)):
            return True
        return any(base.glob(_ci_pattern(pattern)))
    except (OSError, ValueError):
        return False


def iglob(root: Path | str, pattern: str) -> list[Path]:
    r"""Every entry under `root` matching `pattern`, whatever case it is in.

    `users_dir.glob("*/NTUSER.DAT")` is how three handlers find the per-user
    registry, and on a lowercased tree it finds NOTHING -- no error, no empty
    directory, just a parser that reports no users on a machine full of them.
    Sorted, so the order a handler reports in does not depend on the filesystem.
    """
    base = Path(root)
    try:
        hits = set(base.glob(pattern)) | set(base.glob(_ci_pattern(pattern)))
    except (OSError, ValueError):
        return []
    return sorted(hits)


def ambiguous() -> dict[str, list[str]]:
    """Declared paths that matched more than one real entry, and what they were.

    For the case log and the run summary: on a case-sensitive acquisition this is
    a real pair of files, and which one a parser read is not something to leave
    unrecorded.
    """
    return dict(_AMBIGUOUS)


def forget() -> None:
    """Drop the cached listings (a re-parse after the tree changed; and tests)."""
    _LISTINGS.clear()
    _AMBIGUOUS.clear()
