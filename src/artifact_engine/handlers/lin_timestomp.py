"""Handler: timestamps that disagree with each other (bodyfile). Output: timestomp.csv

`touch -r reference victim` copies atime and mtime. It cannot copy ctime: the
inode's change time is written by the kernel whenever the inode is written, and
setting the times IS writing the inode. So on a file whose times were forged,
ctime is the real drop time and mtime is whatever the attacker chose -- often
years earlier, which is what turns a confusing "magic date" into a rule.

Where ext4 records it, `crtime` gives a second, independent contradiction: a file
whose mtime is EARLIER than its own birth was modified before it existed.

WHY A PLAIN DELTA IS NOT THE RULE. Every packaged file on the system has ctime
years after mtime by design: dpkg and rpm restore the mtime the package was built
with, and the ctime is the install. On a normal host that is tens of thousands of
files, so `ctime - mtime > 30d` on its own selects the operating system. Untarring
does the same thing to crtime.

What separates them is not the delta, it is the COMPANY the file keeps. An
install writes thousands of inodes within one day; a drop writes a handful. So
inodes are counted per (ctime day, top-level directory), and a file sharing that
bucket with a crowd is reported as part of the crowd instead of being flagged.

The directory belongs in the key. Counting by day alone means a package update
run on the same afternoon as the drop buries the drop -- and an attacker does not
have to arrange that, an unattended-upgrades timer will do it for them. An
install fills /usr and /lib; a drop lands in /tmp or a home directory, and those
are separate crowds.

No package database is needed, which matters: the hosts where this question comes
up are exactly the ones whose package database is not to be trusted.

SMALLER CROWDS (v0.7.140). Not everything is installed by a package manager. A
security agent under /opt/<vendor> updates itself with a few dozen files a day; a
web application is deployed into /var/www with rsync or tar. Each of those keeps
the shipped mtimes, each stays under _BURST, and on six real hosts they were most
of what this table flagged. So a second crowd is counted per (ctime day, first
TWO path components): _UNPACK files sharing one is an unpack of somebody's
software, not a drop -- except in the staging dirs (/tmp, /var/tmp, /dev/shm),
where unpacking a kit is the thing to see.

`mtime_before_birth` alone flags only in those staging dirs too. Everywhere else it
is what `cp -p`, `rsync -a`, `tar x` and `scp -p` do to every file they write, and
a real `touch -r` leaves the ctime contradiction as well, which still flags.

The writable test is anchored at the start of the path: `/opt/` deep inside a
container layer (`/var/lib/.../overlay2/<id>/diff/opt/...`) is the image's
filesystem, not this host's /opt.

SPEED (v0.7.120). On a container node nearly every row matches -- an image layer
is unpacked with its files' original mtimes -- so both passes do the full work
on all of its 17 million rows. Rows are read as tuples of the named columns, a
timestamp string is parsed once and remembered, the writable test is one regex,
and the crowd key takes the first path component without splitting the rest.
Same rows, same order, same table.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers._topn import TopN

_BODYFILE = Path("CSVs") / "Filesystem" / "bodyfile.csv"

_MIN_DELTA_DAYS = 30
_STRONG_DELTA_DAYS = 365

# Inodes sharing one (ctime day, top-level directory), above which that bucket is
# an install or an unpack rather than somebody's afternoon.
_BURST = 200

# Where a forged timestamp buys something: an account can write here, or the
# path is one an intrusion actually uses.
_WRITABLE = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/home/", "/root/",
             "/var/www/", "/srv/", "/opt/", "/usr/local/", "/var/spool/")
_WRITABLE_RX = re.compile("|".join(re.escape(w) for w in _WRITABLE))

# Where an unpacked kit is the finding, not a reason to look away.
_STAGING = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")

# Inodes sharing one (ctime day, two-level directory) above which they are an
# unpack or a self-update of one piece of software.
_UNPACK = 20

_CAP = 2000

_COLUMNS = ["path", "mode", "uid", "size", "mtime_utc", "ctime_utc", "crtime_utc",
            "delta_days", "indicators", "location", "note", "suspicious"]


@lru_cache(maxsize=1 << 18)
def _when(text: str) -> datetime | None:
    """A timestamp, parsed once per distinct string (they repeat in bursts)."""
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _delta_days(later: str, earlier: str) -> int:
    a, b = _when(later), _when(earlier)
    if a is None or b is None:
        return 0
    return (a - b).days


def bucket(path: str, ctime: str) -> tuple[str, str]:
    """The crowd a file belongs to: the day its inode changed, and the top-level
    directory it lives in (its first non-empty path component)."""
    return (ctime[:10], (path or "").lstrip("/").split("/", 1)[0].lower())


def writable(path: str) -> bool:
    return _WRITABLE_RX.match((path or "").lower()) is not None


def tree(path: str, ctime: str) -> tuple[str, str]:
    """The smaller crowd: the ctime day and the first two path components."""
    return (ctime[:10], "/".join((path or "").lstrip("/").lower().split("/", 2)[:2]))


def staging(path: str) -> bool:
    return (path or "").lower().startswith(_STAGING)


def is_executable(mode: str) -> bool:
    """The bodyfile's mode field is `-/-rwxr-xr-x`; any x bit will do. A directory
    (`d/drwx...`) always has one and is never the thing being stomped."""
    tail = (mode or "").split("/")[-1]
    return bool(tail) and not tail.startswith("d") and "x" in tail


def indicators_for(row: dict) -> tuple[list[str], int]:
    """(indicator names, ctime-minus-mtime in days) for one bodyfile row."""
    return _indicators(row.get("mtime_utc") or "", row.get("ctime_utc") or "",
                       row.get("crtime_utc") or "")


def _indicators(mtime: str, ctime: str, crtime: str) -> tuple[list[str], int]:
    delta = _delta_days(ctime, mtime) if ctime and mtime else 0
    found = []
    if delta >= _MIN_DELTA_DAYS:
        found.append(f"ctime_{delta}d_after_mtime")
    if crtime and mtime and mtime < crtime:      # ISO text sorts chronologically
        found.append("mtime_before_birth")
    return found, delta


_COLS = ("name", "mode", "uid", "size", "mtime_utc", "ctime_utc", "crtime_utc")


def _rows(src: Path):
    """Each row's `_COLS`, as a tuple ('' for a column a row lacks)."""
    with src.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, [])
        at = [header.index(c) if c in header else -1 for c in _COLS]
        for r in reader:
            n = len(r)
            yield tuple(r[i] if 0 <= i < n else "" for i in at)


def run(ctx) -> None:
    src = Path(ctx.evidence) / _BODYFILE
    if not src.is_file():
        raise HandlerSkip("no bodyfile.csv to read")

    # Pass 1: how big each (day, top-level directory) crowd is. Counted over every
    # match, before any location filter -- the crowd that proves an install is
    # mostly in /usr, which is exactly what the filter drops.
    crowd: Counter[tuple[str, str]] = Counter()
    trees: Counter[tuple[str, str]] = Counter()
    try:
        for name, _mode, _uid, _size, mtime, ctime, crtime in _rows(src):
            if _indicators(mtime, ctime, crtime)[0]:
                crowd[bucket(name, ctime)] += 1
                trees[tree(name, ctime)] += 1
    except OSError as e:
        raise HandlerSkip(f"bodyfile.csv unreadable: {e}") from e

    # Pass 2: rank. The crowd is complete now, so each row's final key is known
    # as it is read and only the best _CAP need be held.
    top = TopN(_CAP)
    for name, mode, uid, size, mtime, ctime, crtime in _rows(src):
        found, delta = _indicators(mtime, ctime, crtime)
        if not found:
            continue
        where = writable(name)
        if not where and not is_executable(mode):
            continue
        key = bucket(name, ctime)
        day, where_root = key
        company = crowd.get(key, 0)
        installed = company >= _BURST
        kit = staging(name)
        sub = tree(name, ctime)[1]
        siblings = 0 if kit else trees.get(tree(name, ctime), 0)
        unpacked = not installed and siblings >= _UNPACK
        flagged = where and not installed and not unpacked and (
            delta >= _STRONG_DELTA_DAYS or len(found) >= 2
            or (kit and "mtime_before_birth" in found))
        note = (f"{company:,} inode(s) under /{where_root} changed on {day}: an "
                f"install or an unpack, not a drop") if installed else \
               (f"{siblings:,} inode(s) under /{sub} changed on {day}: an unpack "
                f"or a self-update of that software, not a drop") if unpacked else ""
        top.add((0 if flagged else 1, 1 if installed or unpacked else 0, -delta), [
            name, mode, uid, size, mtime, ctime, crtime,
            delta or "", " ".join(found),
            "writable" if where else "system", note, "yes" if flagged else "",
        ])

    rows = top.best()
    if not rows:
        return                                # nothing to say, and no empty table
    if top.dropped:
        rows.append(["(not listed)", "", "", "", "", "", "", "", "cap", "",
                     (f"{top.total:,} file(s) matched; the {len(rows):,} with "
                      f"the largest disagreement are listed"), ""])
    write_csv(ctx.out, "timestomp.csv", _COLUMNS, rows)
