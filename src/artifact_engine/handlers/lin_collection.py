"""Handler: the collection's own output, on the filesystem it collected.
Output: collection_artifacts.csv

The Linux half of the same problem. UAC writes its output somewhere, and when
that somewhere is the host itself, the bodyfile records every collected path
twice -- once where it lives, once under the output tree. A search for a filename
then returns the real hit and its copy.

Same test as the Windows side, and for the same reason it needs no tool list: a
DIRECTORY WHOSE CHILDREN ARE THE FILESYSTEM'S OWN ROOT. Nothing under a healthy
`/` holds `etc`, `usr`, `var` and `home` inside it except a copy of `/` -- a UAC
`[root]/` tree, an extracted acquisition, a chroot, or a container image.

WHAT IT DOES NOT CLAIM. A chroot and a container rootfs have exactly this shape
and are not collection artifacts; so does a restored backup. The `evidence`
column says whether a collector's name was involved or the shape was the only
thing that identified it, and a search can always be told to look anyway
(`aeng sweep --include-collection`). The point is to keep the second copy out of
an answer by default, not to make it unreachable.
"""

from __future__ import annotations

import csv
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv

_BODYFILE = Path("CSVs") / "Filesystem" / "bodyfile.csv"

# Directory names that live at `/` and, together, nowhere else.
_ROOT_MARKERS = {"etc", "usr", "var", "home", "root", "opt", "bin", "sbin",
                 "lib", "lib64", "boot", "srv", "proc", "sys", "dev"}

# Four of them is a root; three is a coincidence a source tree can manage
# (`bin`, `lib`, `etc` under an application directory is not unusual).
_MIN_MARKERS = 4

# Directory names of collectors and of the trees they produce.
_TOOL_DIRS = {"uac", "uac-output", "cylr", "velociraptor", "live_response",
              "linux-triage", "fastir", "catscale", "catscale_output"}

_COLUMNS = ["kind", "path", "entries", "first_created_utc", "last_created_utc",
            "evidence", "exclude", "note", "suspicious"]


def _parts(path: str) -> tuple[str, str]:
    """(parent, name) for a bodyfile path, with `/` as its own parent."""
    clean = (path or "").rstrip("/")
    if not clean or clean == "":
        return "/", ""
    parent, _, name = clean.rpartition("/")
    return (parent or "/"), name


def is_directory(mode: str) -> bool:
    """The bodyfile mode field is `d/drwxr-xr-x` for a directory."""
    return (mode or "").strip().lower().startswith("d")


def looks_like_tool(name: str) -> bool:
    low = name.strip().lower()
    return low in _TOOL_DIRS or low.startswith("uac-")


def _rows(src: Path):
    with src.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        yield from csv.DictReader(fh)


def run(ctx) -> None:
    src = Path(ctx.evidence) / _BODYFILE
    if not src.is_file():
        raise HandlerSkip("no bodyfile.csv to read")

    # Pass 1: which directories hold a root inside them, and where the collectors
    # left their own trees.
    markers: dict[str, set[str]] = {}
    tools: set[str] = set()
    try:
        for row in _rows(src):
            if not is_directory(row.get("mode") or ""):
                continue
            parent, name = _parts(row.get("name") or "")
            if not name:
                continue
            if name.lower() in _ROOT_MARKERS and parent != "/":
                markers.setdefault(parent, set()).add(name.lower())
            if looks_like_tool(name):
                tools.add(f"{parent.rstrip('/')}/{name}")
    except OSError as e:
        raise HandlerSkip(f"bodyfile.csv unreadable: {e}") from e

    trees = {p: sorted(m) for p, m in markers.items() if len(m) >= _MIN_MARKERS}
    watched: dict[str, str] = {p: "tool_dir" for p in tools}
    for p in trees:
        watched[p] = "mirrored_tree"
    if not watched:
        return                                # nothing collected onto itself

    # Pass 2: size, and the window the copies were created in.
    counts = dict.fromkeys(watched, 0)
    first: dict[str, str] = {}
    last: dict[str, str] = {}
    prefixes = [(p, p.rstrip("/") + "/") for p in watched]
    for row in _rows(src):
        name = row.get("name") or ""
        for p, prefix in prefixes:
            if name.startswith(prefix):
                counts[p] += 1
                born = (row.get("crtime_utc") or row.get("ctime_utc") or "").strip()
                if born:
                    if p not in first or born < first[p]:
                        first[p] = born
                    if p not in last or born > last[p]:
                        last[p] = born
                break

    rows = []
    for path, kind in sorted(watched.items()):
        if kind == "mirrored_tree":
            named = next((Path(t).name for t in tools
                          if path == t or path.startswith(t.rstrip("/") + "/")), "")
            evidence = ", ".join(trees.get(path, []))
            note = ("a copy of this filesystem, sitting inside it: every path under "
                    "here is a second record of a file that lives elsewhere")
            if named:
                evidence += f"; under {named}"
            else:
                note += (". Identified by SHAPE alone -- a chroot, a container "
                         "rootfs or a restored backup looks the same; "
                         "--include-collection puts it back")
            exclude = "yes"
        else:
            evidence = Path(path).name
            note = ("a collector's own directory: explains why paths under it look "
                    "busy. Not excluded -- other things can sit here too")
            exclude = ""
        rows.append([kind, path, counts.get(path, 0), first.get(path, ""),
                     last.get(path, ""), evidence, exclude, note, ""])

    write_csv(ctx.out, "collection_artifacts.csv", _COLUMNS, rows)
