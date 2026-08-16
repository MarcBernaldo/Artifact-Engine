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
        # Optionally skip the contents of a loose-drop folder (weblogs*/fortigate*/evtx*)
        # at the case root: often thousands of rotated logs whose custody is not
        # always required. Only the FIRST path component is checked, so a real
        # acquisition that merely contains a var/log/... path is never affected.
        if not include_drops and parts and DROP_DIR.fullmatch(parts[0]):
            continue
        yield p


def fmt_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f} {u}" if u != "B" else f"{int(f)} B"
        f /= 1024
    return f"{n} B"


def _recorded_paths(csv_path: Path) -> set[str]:
    """rel_paths already in traces.csv -- the machine-readable custody index."""
    if not csv_path.is_file():
        return set()
    try:
        with open(csv_path, newline="", encoding="utf-8") as fh:
            return {row["rel_path"] for row in csv.DictReader(fh) if row.get("rel_path")}
    except (OSError, ValueError, KeyError) as e:
        log.warning(f"[!] {TRACES_CSV} unreadable ({type(e).__name__}), treating the "
                    f"custody index as empty: every original will be hashed again")
        return set()


def generate_traces(root: Path, max_workers: int = 4, operator: str = "",
                    include_drops: bool = True) -> list[TraceEntry]:
    """Hash originals under `root` that are not recorded yet; append them.

    Append-only, never regenerate. The earlier behaviour skipped the whole phase
    once traces.txt existed, which is right for evidence already recorded and
    wrong for everything that arrives later: a second delivery got extracted and
    parsed while the custody record kept claiming to describe the case. An
    incomplete record that does not say it is incomplete is worse than none.

    So each run hashes only what is new and appends it as its OWN dated section,
    because those files were received and hashed at a different moment and the
    record should show that. Lines already written are never touched -- rewriting
    a chain-of-custody document is exactly what the original guard was protecting
    against, and that protection is kept.

    `include_drops=False` skips the files inside loose-drop folders
    (weblogs*/fortigate*/evtx*); the containers delivered at the case root are still
    hashed either way (Phase 0 runs before extraction, so a dropped `.zip` is
    hashed as the one delivered artifact regardless of this flag)."""
    txt_path = root / TRACES_TXT
    csv_path = root / TRACES_CSV
    known = _recorded_paths(csv_path)

    files = list(_iter_original_files(root, include_drops=include_drops))
    if not files:
        log.warning("[!] No files found to hash")
        return []

    new = [p for p in files if str(p.relative_to(root)) not in known]
    if not new:
        log.info(f"[=] integrity: {len(known)} original(s) already recorded, none new")
        return []
    if known:
        log.info(f"[+] integrity: {len(new)} new original(s) "
                 f"({len(known)} already recorded)")

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
        entries = sorted(ex.map(_hash, new), key=lambda e: e.rel_path)

    _write_txt(txt_path, entries, operator, append=bool(known))
    _write_csv(csv_path, entries, append=bool(known))
    return entries


def _write_txt(path: Path, entries: list[TraceEntry], operator: str,
               append: bool = False) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = []
    if append:
        # A later delivery is its own event: own timestamp, own operator, own
        # total. Reading the file top to bottom gives the order things arrived.
        lines += ["", f"Added: {now}   Operator: {operator or '-'}   Tool: v{__version__}"]
    else:
        lines += ["Artifact Engine - Integrity record (chain of custody)",
                  f"Generated: {now}   Operator: {operator or '-'}   Tool: v{__version__}"]
    lines += ["=" * 100, f"{'PATH':<55} {'SIZE':>12}  SHA256", "-" * 100]
    for e in entries:
        lines.append(f"{e.rel_path:<55} {fmt_size(e.size):>12}  {e.sha256}")
    lines.append("=" * 100)
    lines.append(f"Total: {len(entries)} file(s)")
    body = "\n".join(lines) + "\n"
    with open(path, "a" if append else "w", encoding="utf-8") as fh:
        fh.write(body)


def _write_csv(path: Path, entries: list[TraceEntry], append: bool = False) -> None:
    exists = path.is_file()
    with open(path, "a" if append else "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if not (append and exists):
            w.writerow(["rel_path", "size_bytes", "sha256", "mtime_utc"])
        for e in entries:
            w.writerow([e.rel_path, e.size, e.sha256, e.mtime])
