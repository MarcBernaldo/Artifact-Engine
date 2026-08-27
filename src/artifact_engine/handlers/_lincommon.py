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

# What a failed read of a log file raises. A truncated archive comes back as an
# EOFError or a codec error rather than an OSError, and a handler that catches
# only OSError lets those out through the generator into the parser's traceback.
LOG_READ_ERRORS = (OSError, EOFError, lzma.LZMAError)

# A rotated log's name, in the two conventions logrotate ships with:
#   numbered   auth.log.1, auth.log.2.gz     (Debian/Ubuntu default)
#   dateext    messages-20260519.xz          (SUSE and RHEL default: `dateext`)
# Only the numbered form was recognised until v0.7.19, which on a dateext host
# left every archive looking like a file with no rotation suffix at all -- and
# a family of handlers reading nothing but the hours in the file being written.
_ROTATION = re.compile(r"(?:\.(?P<n>\d+)|-(?P<date>\d{8}))(?:\.(?:gz|xz|bz2))?$")


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
    """Log files oldest-first: the archives, then the file being written now.

    Neither convention sorts chronologically by name, and each fails differently:

      numbered   auth.log.10.gz ... auth.log.1, auth.log      higher N = older
                 a plain sort is not even monotonic past nine rotations
                 (`.10` sorts between `.1` and `.2`)
      dateext    messages-20260519.xz ... messages            the date IS the order
                 a plain sort puts the CURRENT file first, ahead of every archive

    Reading oldest-first puts the rows in time order, and puts the lines an
    overlapping rotation duplicates next to each other — which is what lets a
    caller de-duplicate with a bounded window instead of remembering every event
    in the file set.

    A directory carrying BOTH conventions is a host whose logrotate config
    changed, and nothing in the names says which era came first; dated archives
    are placed first, as a convention rather than a claim. It costs nothing real:
    the de-duplication that depends on this order only ever sees two adjacent
    rotations of the same file, and adjacency never crosses a convention change.
    """
    def key(f: Path):
        m = _ROTATION.search(f.name)
        if m is None:
            return (2, 0, f.name)                       # written now: read last
        if m.group("date"):
            return (0, int(m.group("date")), f.name)    # 20260519 < 20260826
        return (1, -int(m.group("n")), f.name)          # .10 before .1

    return sorted(files, key=key)


def is_rotation(name: str) -> bool:
    """True when `name` ends in a logrotate rotation suffix, either convention.

    Lets a caller glob `auth.log*` and still tell the file being written now from
    its archives, without matching whatever else in the directory happens to
    start with the same letters.
    """
    return _ROTATION.search(name) is not None


def rotation_date(name: str) -> str:
    """The date a `dateext` rotation carries in its name, as YYYY-MM-DD.

    '' for a numbered rotation or for the file being written now -- neither
    carries a date, which is the whole reason dateext exists.
    """
    m = _ROTATION.search(name)
    d = m.group("date") if m else None
    return f"{d[:4]}-{d[4:6]}-{d[6:]}" if d else ""


def open_log_bytes(path: Path):
    """A log file opened for reading BYTES, transparently decompressed.

    The text sibling of this is `iter_log_lines`; this exists for the binary
    login logs (wtmp/btmp), whose rotations some distros compress. Raises the
    `LOG_READ_ERRORS` family, like `open` does.
    """
    opener = _OPENERS.get(path.suffix.lower())
    return opener(path, "rb") if opener else open(path, "rb")


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
