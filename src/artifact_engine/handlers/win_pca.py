"""Handler: Program Compatibility Assistant (PCA) app-launch log.

Windows 11 22H2+ records every GUI program launch (including binaries run from a
network share or USB) in:
    Windows/appcompat/pca/PcaAppLaunchDic.txt

The file is pipe-delimited "full path|last execution time" (local time). This is
an execution-evidence artifact comparable to Prefetch/Amcache.

Output: pca.csv
"""

from __future__ import annotations

import csv
from pathlib import Path

_PCA = "Windows/appcompat/pca/PcaAppLaunchDic.txt"


def _read_text(path: Path) -> str:
    """Decode by BOM (PCA files are UTF-16-LE w/ BOM); never guess UTF-16 endianness."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass
    if raw[:3] == b"\xef\xbb\xbf":
        return raw.decode("utf-8-sig", errors="replace")
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def run(ctx) -> None:
    src = ctx.evidence / _PCA
    rows: list[tuple[str, str]] = []
    if src.is_file():
        for line in _read_text(src).splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            path, _, ts = line.rpartition("|")
            rows.append((path.strip(), ts.strip()))

    if not rows:
        return                       # nothing parsed -> no CSV
    ctx.out.mkdir(parents=True, exist_ok=True)
    with open(ctx.out / "pca.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["executable_path", "last_executed"])
        w.writerows(rows)
