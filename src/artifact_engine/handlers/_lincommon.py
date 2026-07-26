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
import re
from collections import deque
from contextlib import contextmanager
from pathlib import Path

_OPENERS = {".gz": gzip.open, ".xz": lzma.open, ".bz2": bz2.open}
_ROTATION = re.compile(r"\.(\d+)(?:\.(?:gz|xz|bz2))?$")


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
            # Closed by the `with` below; opened apart from it so a failure to
            # OPEN (unreadable, truncated archive) ends the generator quietly.
            fh = open(path, "rt", encoding="utf-8", errors="replace")  # noqa: SIM115
    except (OSError, lzma.LZMAError, EOFError):
        return
    with fh:
        try:
            for line in fh:
                yield line.rstrip("\n")
        except (OSError, EOFError, lzma.LZMAError):
            return


def sort_rotations(files) -> list[Path]:
    """Log files oldest-first: `auth.log.10.gz`, ..., `auth.log.1`, `auth.log`.

    A plain sort is neither chronological nor even monotonic past nine rotations
    (`.10` sorts between `.1` and `.2`). Reading oldest-first puts the rows in time
    order, and puts the lines an overlapping rotation duplicates next to each other
    — which is what lets a caller de-duplicate with a bounded window instead of
    remembering every event in the file set.
    """
    def key(f: Path):
        m = _ROTATION.search(f.name)
        return (-int(m.group(1)) if m else 0, f.name)

    return sorted(files, key=key)


@contextmanager
def stream_csv(out: Path, name: str, header: list[str]):
    """Row-at-a-time sibling of `write_csv`, same no-rows-no-file contract.

    For handlers whose row count is chosen by whoever wrote the log rather than by
    the size of the host: on an internet-facing box that is the attacker, one row
    per failed SSH attempt. Buffering those to hand `write_csv` a list means the
    process grows with the brute force. Yields a callable taking one row.
    """
    out.mkdir(parents=True, exist_ok=True)
    path = out / name
    n = 0
    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(header)

            def emit(row: list) -> None:
                nonlocal n
                n += 1
                w.writerow(row)

            yield emit
    finally:
        if not n:
            path.unlink(missing_ok=True)


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
