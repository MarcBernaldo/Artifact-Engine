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
"""

from __future__ import annotations

import csv
from collections import Counter
from datetime import datetime
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

_CAP = 2000

_COLUMNS = ["path", "mode", "uid", "size", "mtime_utc", "ctime_utc", "crtime_utc",
            "delta_days", "indicators", "location", "note", "suspicious"]


def _delta_days(later: str, earlier: str) -> int:
    try:
        return (datetime.fromisoformat(later) - datetime.fromisoformat(earlier)).days
    except ValueError:
        return 0


def bucket(path: str, ctime: str) -> tuple[str, str]:
    """The crowd a file belongs to: the day its inode changed, and the top-level
    directory it lives in."""
    parts = [p for p in (path or "").split("/") if p]
    return (ctime[:10], parts[0].lower() if parts else "")


def writable(path: str) -> bool:
    low = (path or "").lower()
    return any(w in low for w in _WRITABLE)


def is_executable(mode: str) -> bool:
    """The bodyfile's mode field is `-/-rwxr-xr-x`; any x bit will do. A directory
    (`d/drwx...`) always has one and is never the thing being stomped."""
    tail = (mode or "").split("/")[-1]
    return bool(tail) and not tail.startswith("d") and "x" in tail


def indicators_for(row: dict) -> tuple[list[str], int]:
    """(indicator names, ctime-minus-mtime in days) for one bodyfile row."""
    mtime = row.get("mtime_utc") or ""
    ctime = row.get("ctime_utc") or ""
    crtime = row.get("crtime_utc") or ""
    delta = _delta_days(ctime, mtime) if ctime and mtime else 0
    found = []
    if delta >= _MIN_DELTA_DAYS:
        found.append(f"ctime_{delta}d_after_mtime")
    if crtime and mtime and mtime < crtime:      # ISO text sorts chronologically
        found.append("mtime_before_birth")
    return found, delta


def _rows(src: Path):
    with src.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        yield from csv.DictReader(fh)


def run(ctx) -> None:
    src = Path(ctx.evidence) / _BODYFILE
    if not src.is_file():
        raise HandlerSkip("no bodyfile.csv to read")

    # Pass 1: how big each (day, top-level directory) crowd is. Counted over every
    # match, before any location filter -- the crowd that proves an install is
    # mostly in /usr, which is exactly what the filter drops.
    crowd: Counter[tuple[str, str]] = Counter()
    try:
        for row in _rows(src):
            if indicators_for(row)[0]:
                crowd[bucket(row.get("name") or "", row.get("ctime_utc") or "")] += 1
    except OSError as e:
        raise HandlerSkip(f"bodyfile.csv unreadable: {e}") from e

    # Pass 2: rank. The crowd is complete now, so each row's final key is known
    # as it is read and only the best _CAP need be held.
    top = TopN(_CAP)
    for row in _rows(src):
        found, delta = indicators_for(row)
        if not found:
            continue
        where = writable(row.get("name") or "")
        if not where and not is_executable(row.get("mode") or ""):
            continue
        key = bucket(row.get("name") or "", row.get("ctime_utc") or "")
        day, where_root = key
        company = crowd.get(key, 0)
        installed = company >= _BURST
        flagged = where and not installed and (
            delta >= _STRONG_DELTA_DAYS or "mtime_before_birth" in found
            or len(found) >= 2)
        note = (f"{company:,} inode(s) under /{where_root} changed on {day}: an "
                f"install or an unpack, not a drop") if installed else ""
        top.add((0 if flagged else 1, 1 if installed else 0, -delta), [
            row.get("name") or "", row.get("mode") or "", row.get("uid") or "",
            row.get("size") or "", row.get("mtime_utc") or "",
            row.get("ctime_utc") or "", row.get("crtime_utc") or "",
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
