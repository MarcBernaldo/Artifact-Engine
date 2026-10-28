"""Handler: every login record of a Linux host in one table. Output: art_logins.csv

One row per record, whatever kept it (v0.7.162; four tables before):

- wtmp (`[root]/var/log/wtmp` and its rotations, binary utmp): logins, logouts,
  boots and run-level changes with an epoch time (`time_utc`). `result` is `ok`
  on a USER_PROCESS record and empty on the others.
- btmp (the same layout): FAILED logins -- the brute-force / password-spray
  artifact, and what the lateral graph builds `brute_success` out of. `result`
  is `failed`.
- last / lastb (UAC's text rendering of the same two files): read only for the
  file whose binary gave no record. `last` truncates the user and the host and
  reads only the current file, so where the binary is there it adds nothing; a
  host keeping its logins elsewhere (wtmpdb) has only the text. Their time is
  the host's local time without a year (`time_local`, `end_local`); `time_utc`
  is filled when the acquisition names the host's zone and says when it ran:
  the year is the latest one, not after the acquisition, whose date falls on
  the weekday `last` printed (a wtmp can span years), and none matching within
  seven years leaves it empty (v0.7.172).
- lastlog (UAC's `lastlog`): the latest login of each account, `type` LASTLOG,
  printing its own year and offset, so in UTC too whenever that date parses.

`source` names which of these a row comes from, `file` the file it was read
from. The binary files are streamed: btmp grows one record per failed login, so
its size is the attacker's to choose.

Rotations are read, and they matter more here than anywhere else in the Linux
set: reading only the file being written now means a spray from three weeks ago
never reaches the graph -- and the graph's silence reads as "no brute force
against this host", which is a different claim entirely.
"""

from __future__ import annotations

import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import (
    LOG_READ_ERRORS,
    live_response,
    open_log_bytes,
    read_lines,
    root,
    sort_rotations,
    stream_csv,
)
from artifact_engine.handlers._syslogtime import Clock

TABLE = "art_logins.csv"
HEADER = ["time_utc", "time_local", "end_local", "result", "type", "user", "tty", "host",
          "source", "file"]

# utmp ut_type codes (bits/utmp.h)
_TYPES = {
    0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
    5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}

_REC = 384  # sizeof(struct utmp) on Linux x86-64
_CHUNK = _REC * 4096   # ~1.5 MB read at a time, always a whole number of records

# Start of the time range, e.g. "Tue May 26 16:07" (with or without seconds).
_WHEN = re.compile(
    r"^(\S+)\s+(\S+)\s+(.*?)\s+("
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w{3}\s+\d+\s+\d{2}:\d{2}(?::\d{2})?)\s*(.*)$"
)


def iter_utmp(path: Path):
    """Yield rows [time, user, type, line, host] from a binary utmp/wtmp/btmp.

    Read in chunks rather than whole: btmp grows by one 384-byte record per FAILED
    login, so on an internet-facing host its size is the attacker's to choose, and
    a multi-GB btmp is exactly what the brute force this parser exists to find
    leaves behind.

    Transparently decompressed, because some distros compress the rotations of
    these files -- and a compressed archive read as raw bytes does not fail, it
    yields garbage records, which is worse than not reading it.
    """
    try:
        # Closed by the `with` below; opened apart from it so a failure to OPEN
        # ends the generator quietly instead of raising through every caller.
        fh = open_log_bytes(path)
    except LOG_READ_ERRORS:
        return
    with fh:
        rest = b""
        while True:
            try:
                buf = fh.read(_CHUNK)
            except LOG_READ_ERRORS:
                return
            if not buf:
                return
            # A decompressed stream hands back whatever it has, not whole records,
            # so a record split across two reads is carried rather than dropped --
            # dropping it would misalign every record after it, silently.
            buf = rest + buf if rest else buf
            end = len(buf) - len(buf) % _REC
            rest = buf[end:]
            for i in range(0, end, _REC):
                r = buf[i:i + _REC]
                try:
                    ut_type = struct.unpack_from("<i", r, 0)[0]
                    line = r[8:40].split(b"\x00", 1)[0].decode("latin1", "replace")
                    user = r[44:76].split(b"\x00", 1)[0].decode("latin1", "replace")
                    host = r[76:332].split(b"\x00", 1)[0].decode("latin1", "replace")
                    sec = struct.unpack_from("<i", r, 340)[0]
                    ts = (datetime.fromtimestamp(sec, tz=timezone.utc)
                          .strftime("%Y-%m-%d %H:%M:%S") if sec > 0 else "")
                except Exception:  # noqa: BLE001 - a torn record, not a reason to stop
                    continue
                if user.strip():
                    yield [ts, user, _TYPES.get(ut_type, str(ut_type)), line, host]


def utmp_files(logdir: Path, stem: str) -> list[Path]:
    """`stem` and its rotations under `logdir`, oldest first.

    Rotations of these files never overlap -- logrotate MOVES the file rather
    than copy-truncating it -- so reading them in order needs no de-duplication,
    unlike the text auth logs.
    """
    if not logdir.is_dir():
        return []
    return sort_rotations(f for f in logdir.glob(f"{stem}*") if f.is_file())


def _parse_last(lines: list[str]):
    """(user, tty, host, start, end) from `last` / `lastb` text."""
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith(("wtmp begins", "btmp begins")):
            continue
        m = _WHEN.match(ln)
        if not m:
            continue
        user, tty, source, start, rest = m.groups()
        end = rest.strip()
        if end.startswith("- "):  # "- 15:07  (02:15)" -> "15:07  (02:15)"
            end = end[2:].strip()
        yield user, tty, source.strip(), start, end


_LAST_TIME = re.compile(r"^(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2})(?::(\d{2}))?$")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_UTC_FMT = "%Y-%m-%d %H:%M:%S"
# `Tue May 26 16:07:21 +0200 2026` at the end of a lastlog line
_LASTLOG_DATE = re.compile(r"\s\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} [+-]\d{4} \d{4}\s*$")


def last_utc(start: str, zone: ZoneInfo | None, bound: datetime | None) -> str:
    """`last`'s `Tue May 26 16:07` (host-local, no year) in UTC: the latest year
    not after `bound` whose date is that weekday. '' when it cannot be placed."""
    m = _LAST_TIME.match(" ".join(start.split()))
    if not m or zone is None or bound is None or m.group(2) not in _MONTHS:
        return ""
    wday, month = m.group(1), _MONTHS.index(m.group(2)) + 1
    day, hh, mm, ss = int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6) or 0)
    for year in range(bound.year, bound.year - 8, -1):
        try:
            local = datetime(year, month, day, hh, mm, ss, tzinfo=zone)
        except ValueError:                     # Feb 29 outside a leap year
            continue
        if local <= bound and local.strftime("%a") == wday:   # C locale, as `last`
            return local.astimezone(timezone.utc).strftime(_UTC_FMT)
    return ""


def lastlog_utc(latest: str) -> str:
    """`lastlog`'s `Tue May 26 16:07:21 +0200 2026` in UTC, or ''."""
    try:
        when = datetime.strptime(" ".join(latest.split()), "%a %b %d %H:%M:%S %z %Y")
    except ValueError:
        return ""
    return when.astimezone(timezone.utc).strftime(_UTC_FMT)


def _parse_lastlog(lines: list[str]):
    """(user, port, host, latest) from `lastlog` text.

    Columns are blank, not dashes, where lastlog has nothing (a console login has
    no `From`), so splitting on whitespace moved the date's weekday into `host`.
    The date is matched at the end of the line; a token before it is the host
    when it starts under the header's `From`, else the port."""
    if not lines:
        return
    from_col = lines[0].find("From")
    for ln in lines[1:]:
        if "**Never logged in**" in ln or not ln.strip():
            continue
        m = _LASTLOG_DATE.search(ln)
        if not m:                     # a date in no form known here: kept as it was
            parts = ln.split(None, 3)
            if len(parts) == 4:
                yield parts[0], parts[1], parts[2], parts[3].strip()
            elif len(parts) >= 2:
                yield parts[0], "", "", " ".join(parts[1:]).strip()
            continue
        head = ln[:m.start()]
        user, port, host = "", "", ""
        for t in re.finditer(r"\S+", head):
            if not user:
                user = t.group()
            elif from_col >= 0 and t.start() >= from_col:
                host = t.group()
            else:
                port = t.group()
        if user:
            yield user, port, host, m.group().strip()


def _rel(path: Path, evidence: Path) -> str:
    try:
        return str(path.relative_to(evidence))
    except ValueError:
        return str(path)


def run(ctx) -> None:
    evidence = Path(ctx.evidence)
    logdir = root(evidence) / "var" / "log"
    sysd = (live_response(evidence) or evidence / "live_response") / "system"
    binaries = {stem: utmp_files(logdir, stem) for stem in ("wtmp", "btmp")}
    texts = [sysd / n for n in ("last.txt", "lastb.txt", "lastlog.txt")]
    if not any(binaries.values()) and not any(t.is_file() for t in texts):
        raise HandlerSkip("no wtmp/btmp under /var/log and no last/lastb/lastlog output")

    clock = None                  # read only for a host whose logins are text
    with stream_csv(ctx.out, TABLE, HEADER) as emit:
        for stem, text, result in (("wtmp", "last", "ok"), ("btmp", "lastb", "failed")):
            n = 0
            for f in binaries[stem]:
                rel = _rel(f, evidence)
                for ts, user, kind, line, host in iter_utmp(f):
                    ok = result if stem == "btmp" or kind == "USER_PROCESS" else ""
                    emit([ts, "", "", ok, kind, user, line, host, stem, rel])
                    n += 1
            if n:
                continue
            # the text rendering only where the binary gave nothing
            f = sysd / f"{text}.txt"
            lines = read_lines(f)
            if lines and clock is None:
                clock = Clock(evidence)
            for user, tty, host, start, end in _parse_last(lines):
                emit([last_utc(start, clock.zone, clock.acquired), start, end, result, "",
                      user, tty, host, text, _rel(f, evidence)])
        f = sysd / "lastlog.txt"
        for user, port, host, latest in _parse_lastlog(read_lines(f)):
            emit([lastlog_utc(latest), latest, "", "ok", "LASTLOG", user, port, host,
                  "lastlog", _rel(f, evidence)])
