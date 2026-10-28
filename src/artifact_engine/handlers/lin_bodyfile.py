"""Handler: filesystem MAC timeline from the UAC bodyfile (Linux).
Output: art_bodyfile.csv  (one row per filesystem entry, epoch times -> ISO UTC).

The bodyfile is mactime pipe format:
  MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
It can be hundreds of MB / millions of rows, so it is streamed line by line and
never loaded whole. Like $MFT/$J it lands in the .db; the .xlsx skips it when it
exceeds Excel's row limit.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone

_HEADER = ["name", "inode", "mode", "uid", "gid", "size",
           "atime_utc", "mtime_utc", "ctime_utc", "crtime_utc"]


def _iso(epoch: str) -> str:
    try:
        t = int(epoch)
    except ValueError:
        return ""
    if t <= 0:
        return ""
    try:
        return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return ""


# Converting an epoch is most of a row's cost, and the values repeat: files are
# written in bursts (a package, an image layer), so 2 million rows of a
# container node held 38,790 distinct times. Remembered by the raw string, so
# the output is byte for byte what `_iso` gives (v0.7.119); emptied when full.
_CACHE_MAX = 1_000_000


def run(ctx) -> None:
    src = ctx.evidence / "bodyfile" / "bodyfile.txt"
    if not src.is_file():
        return                       # no bodyfile -> no CSV (nothing to parse)
    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "art_bodyfile.csv"

    seen: dict[str, str] = {}

    def iso(epoch: str) -> str:
        r = seen.get(epoch)
        if r is None:
            if len(seen) >= _CACHE_MAX:
                seen.clear()
            r = seen[epoch] = _iso(epoch)
        return r

    rows = 0
    with open(src, encoding="utf-8", errors="replace") as fin, \
            open(out, "w", newline="", encoding="utf-8") as fout:
        w = csv.writer(fout)
        w.writerow(_HEADER)
        for line in fin:
            line = line.rstrip("\n")
            if not line:
                continue
            # rsplit off the 9 trailing numeric fields so '|' in a filename is safe.
            parts = line.rsplit("|", 9)
            if len(parts) != 10:
                continue
            name = parts[0].split("|", 1)[1] if "|" in parts[0] else parts[0]
            inode, mode, uid, gid, size, atime, mtime, ctime, crtime = parts[1:]
            w.writerow([name, inode, mode, uid, gid, size,
                        iso(atime), iso(mtime), iso(ctime), iso(crtime)])
            rows += 1
    if rows == 0:
        out.unlink(missing_ok=True)  # header-only -> drop it
