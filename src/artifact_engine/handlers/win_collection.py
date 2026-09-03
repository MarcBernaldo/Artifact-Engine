r"""Handler: the collection's own output, on the volume it collected.
Output: collection_artifacts.csv

A triage collector run against the live host has to write somewhere, and when the
operator points it at a folder on that same disk, every file it copies is recorded
in the $MFT twice: once where it lives, once under the output tree. A search for a
filename then returns the real hit and its copy, and a path under the operator's
download folder reads as activity at that path.

The shape is unmistakable and needs no tool list: a DIRECTORY WHOSE CHILDREN ARE
THE VOLUME'S OWN ROOT. Nothing on a healthy volume has `Windows`, `Users`,
`ProgramData` and `$Recycle.Bin` sitting inside it except a copy of the volume.
That is what is looked for here -- one pass to find such directories, a second to
size them and take the window their files were created in, which is the
acquisition.

TWO THINGS IT REFUSES TO CONFLATE. `Windows.old` (and `$WINDOWS.~BT`) have exactly
this shape and are not a collection: they are the previous install, left by an
in-place upgrade, and they hold real evidence of the host before it. They get a
row saying what they are and are NEVER excluded from a search. Everything else
with the shape is excluded by default, and `aeng sweep --include-collection` puts
it back -- the point is to keep the copies out of the answer, not to make them
unreachable.

A directory named after a known triage tool gets a row too, unexcluded: it says
where the operator worked, which is why paths under it look busy, without hiding
anything that might also be there.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv

_MFT_CSV = Path("CSVs") / "Filesystem" / "MFT.csv"

# Directory names that exist at the root of a Windows volume and nowhere else --
# except inside a copy of one.
_ROOT_MARKERS = {
    "windows", "users", "programdata", "program files", "program files (x86)",
    "$recycle.bin", "perflogs", "system volume information",
    "documents and settings", "recovery", "boot", "$extend",
}

# How many of them a directory must contain before it is a copy of the volume and
# not a folder that happens to be called Users.
_MIN_MARKERS = 3

# The same shape, produced by Windows itself. Real evidence of the previous
# install: named, and never excluded from a search.
_OS_UPGRADE = {"windows.old", "$windows.~bt", "$windows.~ws", "$sysreset"}

# Directory names of triage collectors. Reported for context only -- an attacker's
# tools can sit in the same folder, so nothing here is excluded from a search.
_TOOL_DIRS = {"kape", "gkape", "cylr", "velociraptor", "dfir-orc", "kapefiles",
              "modulesresults", "moduleresults", "triage", "cyliveresponse"}

# MFTECmd writes the volume root as "." (or "").
_ROOT = {"", ".", ".\\", "\\"}

_COLUMNS = ["kind", "path", "entries", "first_created_utc", "last_created_utc",
            "evidence", "exclude", "note", "suspicious"]

_TS = re.compile(r"^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d")


def _norm(path: str) -> str:
    return (path or "").strip().rstrip("\\")


def is_root(parent: str) -> bool:
    return _norm(parent).lower() in {r.rstrip("\\") for r in _ROOT}


def _join(parent: str, name: str) -> str:
    p = _norm(parent)
    return f"{p}\\{name}" if p and not is_root(p) else f".\\{name}"


def _cells(header: list[str]):
    idx = {name.strip(): i for i, name in enumerate(header)}

    def cell(row: list, name: str) -> str:
        i = idx.get(name)
        return row[i] if i is not None and i < len(row) else ""
    return idx, cell


def _reader(fh):
    return csv.reader(line.replace("\x00", "") for line in fh)


def classify(name: str) -> str:
    """What a directory of this name is, before its contents are looked at."""
    low = name.strip().lower()
    if low in _OS_UPGRADE:
        return "os_upgrade"
    if low in _TOOL_DIRS:
        return "tool_dir"
    return ""


def _under_tool(path: str, tools: dict[str, str]) -> str:
    """The collector directory this tree sits in or is, if any. A named tool turns
    an inference from shape into an identification."""
    low = path.lower()
    for t, kind in tools.items():
        if kind == "tool_dir" and (low == t.lower() or low.startswith(t.lower() + "\\")):
            return Path(t).name
    return ""


def run(ctx) -> None:
    src = Path(ctx.evidence) / _MFT_CSV
    if not src.is_file():
        raise HandlerSkip("no MFT.csv to read")

    # Pass 1: which directories hold the volume's own root inside them, and where
    # the collector tools are. Cheap per row -- three columns and a set lookup.
    markers: dict[str, set[str]] = {}
    tools: dict[str, str] = {}
    try:
        fh = src.open("r", encoding="utf-8-sig", errors="replace", newline="")
    except OSError as e:
        raise HandlerSkip(f"MFT.csv unreadable: {e}") from e
    with fh:
        reader = _reader(fh)
        header = next(reader, None)
        if not header:
            raise HandlerSkip("MFT.csv is empty")
        idx, cell = _cells(header)
        if "ParentPath" not in idx or "FileName" not in idx:
            raise HandlerSkip("MFT.csv has no path columns")
        for row in reader:
            if (cell(row, "IsDirectory") or "").strip().lower() not in ("true", "1", "yes"):
                continue
            name = cell(row, "FileName").strip()
            parent = cell(row, "ParentPath")
            low = name.lower()
            if low in _ROOT_MARKERS and not is_root(parent):
                markers.setdefault(_norm(parent), set()).add(low)
            kind = classify(name)
            if kind:
                tools[_join(parent, name)] = kind

    trees = {p: sorted(m) for p, m in markers.items() if len(m) >= _MIN_MARKERS}
    # A tool directory that also holds a copy of the volume is both, and the copy
    # is the more useful statement: it is the one worth keeping out of a search.
    watched: dict[str, str] = dict(tools)
    for p in trees:
        watched[p] = ("os_upgrade" if classify(Path(p).name) == "os_upgrade"
                      else "mirrored_tree")
    if not watched:
        return                                # nothing collected onto itself

    # Pass 2: how big each one is, and the window its files were created in --
    # which, for a collection tree, is the acquisition.
    counts = dict.fromkeys(watched, 0)
    first: dict[str, str] = {}
    last: dict[str, str] = {}
    prefixes = [(p, p.lower() + "\\") for p in watched]
    with src.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = _reader(fh)
        header = next(reader, None)
        _, cell = _cells(header or [])
        for row in reader:
            parent = _norm(cell(row, "ParentPath")).lower()
            if not parent:
                continue
            for p, prefix in prefixes:
                if parent == p.lower() or parent.startswith(prefix):
                    counts[p] += 1
                    created = cell(row, "Created0x10").strip()
                    if _TS.match(created):
                        if p not in first or created < first[p]:
                            first[p] = created
                        if p not in last or created > last[p]:
                            last[p] = created
                    break

    rows = []
    for path, kind in sorted(watched.items()):
        if kind == "mirrored_tree":
            named = _under_tool(path, tools)
            note = ("a copy of this volume, written onto it: every file under here "
                    "is a second record of a file that lives elsewhere")
            evidence = ", ".join(trees.get(path, []))
            if named:
                evidence += f"; under {named}"
            else:
                note += (". Identified by SHAPE alone -- a backup or a mounted "
                         "image looks the same; --include-collection puts it back")
            exclude = "yes"
        elif kind == "os_upgrade":
            note = ("the previous Windows install, left by an in-place upgrade. Real "
                    "evidence of the host before it, NOT a collection artifact")
            evidence = ", ".join(trees.get(path, [])) or Path(path).name
            exclude = ""
        else:
            note = ("a triage collector's own directory: explains why paths under it "
                    "look busy. Not excluded -- other things can sit here too")
            evidence = Path(path).name
            exclude = ""
        rows.append([kind, path, counts.get(path, 0), first.get(path, ""),
                     last.get(path, ""), evidence, exclude, note, ""])

    write_csv(ctx.out, "collection_artifacts.csv", _COLUMNS, rows)
