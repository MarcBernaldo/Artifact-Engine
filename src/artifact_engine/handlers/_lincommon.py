"""Shared helpers for the Linux/UAC handlers (lin_*).

Not a handler itself (leading underscore): just the bits every lin_* module
needs. UAC stores the filesystem under "[root]"; some collectors use the root
directly.
"""

from __future__ import annotations

import bz2
import csv
import gzip
import lzma
from collections import deque
from pathlib import Path

_OPENERS = {".gz": gzip.open, ".xz": lzma.open, ".bz2": bz2.open}


def root(evidence: Path) -> Path:
    r = evidence / "[root]"
    return r if r.is_dir() else evidence


def live_response(evidence: Path) -> Path | None:
    """UAC live_response/ directory (collected command outputs), a sibling of
    [root]. Returns None if this acquisition has no live-response data."""
    d = evidence / "live_response"
    if d.is_dir():
        return d
    return next((h for h in evidence.rglob("live_response") if h.is_dir()), None)


def read_text(path: Path) -> str:
    """Best-effort text read; '' if the file is missing or unreadable."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_lines(path: Path) -> list[str]:
    """Lines of a text file with trailing newline stripped ('' -> [])."""
    return read_text(path).splitlines()


def tail_lines(path: Path, max_lines: int) -> list[str]:
    """Last `max_lines` lines of a log file (the most recent activity).

    Plain files are read backwards from EOF so a multi-GB current log isn't read
    whole; compressed files fall back to a bounded streaming tail.
    """
    if path.suffix.lower() in _OPENERS:
        return list(deque(iter_log_lines(path), maxlen=max_lines))
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            pos = fh.tell()
            data = b""
            block = 1 << 20
            while pos > 0 and data.count(b"\n") <= max_lines:
                step = min(block, pos)
                pos -= step
                fh.seek(pos)
                data = fh.read(step) + data
        return data.decode("utf-8", "replace").splitlines()[-max_lines:]
    except OSError:
        return []


def iter_log_lines(path: Path):
    """Yield lines from a log file, transparently decompressing .gz/.xz/.bz2.

    Streams (doesn't load the whole file) so rotated archives stay cheap.
    """
    opener = _OPENERS.get(path.suffix.lower())
    try:
        if opener:
            fh = opener(path, "rt", encoding="utf-8", errors="replace")
        else:
            fh = open(path, "rt", encoding="utf-8", errors="replace")
    except (OSError, lzma.LZMAError, EOFError):
        return
    with fh:
        try:
            for line in fh:
                yield line.rstrip("\n")
        except (OSError, EOFError, lzma.LZMAError):
            return


def write_csv(out: Path, name: str, header: list[str], rows: list[list]) -> None:
    """Write `rows` as a CSV under `out`. A parser with no rows writes nothing:
    an empty (header-only) CSV is just clutter and a 0-row table downstream. The
    run still gets its .done marker (it ran, it just found nothing)."""
    if not rows:
        return
    out.mkdir(parents=True, exist_ok=True)
    with open(out / name, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
