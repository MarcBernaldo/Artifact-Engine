"""Handler: filesystem MAC timeline from the UAC bodyfile (Linux).
Output: bodyfile.csv  (one row per filesystem entry, epoch times -> ISO UTC).

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


def run(ctx) -> None:
    src = ctx.evidence / "bodyfile" / "bodyfile.txt"
    if not src.is_file():
        return                       # no bodyfile -> no CSV (nothing to parse)
    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "bodyfile.csv"

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
                        _iso(atime), _iso(mtime), _iso(ctime), _iso(crtime)])
            rows += 1
    if rows == 0:
        out.unlink(missing_ok=True)  # header-only -> drop it
