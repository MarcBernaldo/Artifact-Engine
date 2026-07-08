"""Phase 0 - Integrity: SHA256 of the original files before extraction.

Generates the chain of custody (human-readable traces.txt + machine traces.csv).
Runs BEFORE touching anything and is idempotent (not regenerated if it exists).
"""

from __future__ import annotations

import csv
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine import __version__
from artifact_engine.core.extractor import DROP_DIR
from artifact_engine.logging_setup import get_logger

log = get_logger()

TRACES_TXT = "traces.txt"
TRACES_CSV = "traces.csv"

# Files/folders produced by the tool itself: never "originals"
_OUTPUT_NAMES = {TRACES_TXT, TRACES_CSV, "aeng-run.log"}
_OUTPUT_DIRS = {"CSVs", "JSONs", "TXTs"}

_BUF = 1024 * 1024  # 1 MiB


@dataclass
class TraceEntry:
    rel_path: str
    size: int
    sha256: str
    mtime: str


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_BUF), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_original_files(root: Path, include_drops: bool = True):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.name in _OUTPUT_NAMES:
            continue
        parts = p.relative_to(root).parts
        if any(part in _OUTPUT_DIRS for part in parts):
            continue
        # Optionally skip the contents of a loose-drop folder (weblogs*/fortigate*)
        # at the case root: often thousands of rotated logs whose custody is not
        # always required. Only the FIRST path component is checked, so a real
        # acquisition that merely contains a var/log/... path is never affected.
        if not include_drops and parts and DROP_DIR.fullmatch(parts[0]):
            continue
        yield p


def _fmt_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f} {u}" if u != "B" else f"{int(f)} B"
        f /= 1024
    return f"{n} B"


def generate_traces(root: Path, max_workers: int = 4, operator: str = "",
                    include_drops: bool = True) -> list[TraceEntry]:
    """Hash the originals under `root` and write traces.txt/csv. Idempotent.

    `include_drops=False` skips the files inside loose-drop folders
    (weblogs*/fortigate*); the containers delivered at the case root are still
    hashed either way (Phase 0 runs before extraction, so a dropped `.zip` is
    hashed as the one delivered artifact regardless of this flag)."""
    txt_path = root / TRACES_TXT
    if txt_path.is_file():
        log.info(f"[=] {TRACES_TXT} already exists, skipping integrity phase")
        return []

    files = list(_iter_original_files(root, include_drops=include_drops))
    if not files:
        log.warning("[!] No files found to hash")
        return []

    def _hash(p: Path) -> TraceEntry:
        st = p.stat()
        return TraceEntry(
            rel_path=str(p.relative_to(root)),
            size=st.st_size,
            sha256=sha256_file(p),
            mtime=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        )

    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        entries = sorted(ex.map(_hash, files), key=lambda e: e.rel_path)

    _write_txt(txt_path, entries, operator)
    _write_csv(root / TRACES_CSV, entries)
    return entries


def _write_txt(path: Path, entries: list[TraceEntry], operator: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "Artifact Engine - Integrity record (chain of custody)",
        f"Generated: {now}   Operator: {operator or '-'}   Tool: v{__version__}",
        "=" * 100,
        f"{'PATH':<55} {'SIZE':>12}  SHA256",
        "-" * 100,
    ]
    for e in entries:
        lines.append(f"{e.rel_path:<55} {_fmt_size(e.size):>12}  {e.sha256}")
    lines.append("=" * 100)
    lines.append(f"Total: {len(entries)} file(s)")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_csv(path: Path, entries: list[TraceEntry]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rel_path", "size_bytes", "sha256", "mtime_utc"])
        for e in entries:
            w.writerow([e.rel_path, e.size, e.sha256, e.mtime])
