"""Handler: log integrity / anti-forensics check. Output: log_integrity.csv

Post-mortem tampering signals from /var/log (SANS 'suspicious log data'):
- a key security log present but EMPTY (wiped), and
- a binary login log (wtmp/btmp/lastlog/utmp) whose size is not a whole number
  of fixed-size records (truncated / corrupted).

Both checks run over the ROTATIONS too, and each artifact gets a `rotations`
row saying how many archives it kept and, when the names are dated, the span
they cover. That row answers the question that decides whether a quiet log is
evidence: how far back does this host's logging actually reach? A host holding
a day and a host holding a year both produce an auth.csv, and only one of them
has anything to say about an intrusion from last month.

Filesystem mtimes are NOT used (extracted UAC times are extraction time,
unreliable). Missing logs are informational only -- a distro or collection
profile may simply lack them; only emptied security logs and truncated binaries
are flagged.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.handlers._lincommon import (
    is_rotation,
    root,
    rotation_date,
    sort_rotations,
    write_csv,
)

# Text security logs to check (relative to /var/log). Only one of each
# distro-specific pair (auth.log/secure, syslog/messages) exists per host; the
# other shows as 'missing', which is not flagged.
_TEXT = ["auth.log", "secure", "messages", "syslog", "kern.log", "cron", "audit/audit.log"]

# Binary login logs and their fixed record size (utmp layout = 384, lastlog = 292).
_BINARY = [("wtmp", 384), ("btmp", 384), ("utmp", 384), ("lastlog", 292)]

# Logs whose emptiness is itself suspicious (a live host normally has content);
# btmp/lastlog/utmp/kern.log/cron/audit can legitimately be empty.
_EMPTY_SUSPICIOUS = {"auth.log", "secure", "messages", "syslog", "wtmp"}

# Suffixes whose size says nothing about the content: a compressed archive is
# never a whole number of utmp records and an empty one is ~20 bytes, not 0. The
# rotation is still counted for coverage, it is just not size-checked.
_COMPRESSED = (".gz", ".xz", ".bz2")


def _rotations(log, name: str) -> list[Path]:
    """Archived copies of `name`, oldest first. Excludes the file being written
    now, and anything that merely shares its prefix (`cron*` also matches
    `crontab`); only a real rotation suffix counts."""
    stem = Path(name).name
    d = log / Path(name).parent
    if not d.is_dir():
        return []
    return sort_rotations(f for f in d.glob(f"{stem}*")
                          if f.is_file() and f.name != stem and is_rotation(f.name))


def _span(files: list[Path]) -> str:
    """", 2025-10-31 .. 2026-08-22" for dated archives, "" for numbered ones."""
    dates = sorted(d for d in (rotation_date(f.name) for f in files) if d)
    return f", {dates[0]} .. {dates[-1]}" if dates else ""


def run(ctx) -> None:
    log = root(ctx.evidence) / "var" / "log"
    rows: list[list] = []

    def size_of(path: Path) -> int | None:
        try:
            return path.stat().st_size
        except OSError:
            return None

    def judge(label: str, base: str, size: int, rec: int | None) -> None:
        """One artifact's size, as a row. `base` is the unrotated name, which is
        what decides whether being empty is suspicious."""
        if size == 0:
            rows.append([label, "empty", "0 bytes",
                         "yes" if base in _EMPTY_SUSPICIOUS else ""])
        elif rec and size % rec != 0:
            rows.append([label, "truncated", f"{size} bytes (not a multiple of {rec})", "yes"])
        else:
            detail = f"{size} bytes" + (f" ({size // rec} records)" if rec else "")
            rows.append([label, "present", detail, ""])

    def check(name: str, rec: int | None = None) -> None:
        path = log / name
        if not path.is_file():
            rows.append([name, "missing", "", ""])
        else:
            size = size_of(path)
            if size is not None:
                judge(name, name, size, rec)
        # The archives. Counted always -- how far back this host logs is the
        # context every other Linux parser's output is read in -- but reported
        # individually only when one of them is wrong, so a host with a year of
        # rotations adds one row here, not three hundred.
        rots = _rotations(log, name)
        if not rots:
            return
        rows.append([name, "rotations", f"{len(rots)} archive(s){_span(rots)}", ""])
        subdir = Path(name).parent.as_posix()
        for f in rots:
            if f.suffix.lower() in _COMPRESSED:
                continue
            size = size_of(f)
            if size is None or (size != 0 and not (rec and size % rec != 0)):
                continue                        # a healthy archive stays quiet
            label = f.name if subdir == "." else f"{subdir}/{f.name}"
            judge(label, name, size, rec)

    for n in _TEXT:
        check(n)
    for n, rec in _BINARY:
        check(n, rec)

    rows.sort(key=lambda r: (r[3] != "yes", r[0]))
    write_csv(ctx.out, "log_integrity.csv",
              ["artifact", "status", "detail", "suspicious"], rows)
