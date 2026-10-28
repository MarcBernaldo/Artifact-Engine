"""Handler: every syslog line and every systemd journal entry on the host, in one
table. Output: art_log_syslog.csv

`source` says which of the two a row comes from (v0.7.162; the journal was a
table of its own before), `file` the file it was read from.

syslog: all the files under /var/log written in syslog format -- messages,
syslog, secure, auth.log, warn, mail*, maillog, cron, kern.log, daemon.log and
any other name a host's rsyslog config gives them (`_varlog` decides on
content) -- every rotation, oldest first, one row per line. A host writing the
same event to two files (SUSE: messages and warn) has it twice, once per
`file`. A line that is not a syslog line (a stack trace's continuation) keeps
only `message`. `time_local` is as logged; `time_utc` comes from `_syslogtime`
-- the host's zone and, for a yearless classic line, the year bounded by the
archive's dateext name or the acquisition. Empty when the acquisition does not
say.

journal: every ENTRY object of every journal file (persistent and volatile,
archived, and the `.journal~` a crash leaves), merged across files by time,
after the syslog lines: time (`time_utc`, to the microsecond: the journal stores
microseconds since the epoch), host, identifier as `program`, pid, message, and
the fields only the journal has -- boot, uid, comm, systemd unit, priority,
transport. An entry's payload compressed with a codec this host lacks
(LZ4/ZSTD without their package) is counted, never guessed, like `_journal`
does.

Most journal entries are the same events rsyslog wrote to the text files
(journald forwards them): an entry is left out when a syslog line has its host,
program and message within a second of its time, so each event is one row. Each
syslog line stands for one entry only: a burst of identical events the journal
holds thirty times and rsyslog wrote once (rate limiting, "message repeated")
keeps twenty-nine journal rows. The host is compared (first label, any case) so
a central log server's line from another machine never stands for one of its
own -- except a line whose host is `localhost` or empty, which is this machine:
rsyslog writes `localhost` on every line when the hostname was not set at its
start, and the journal never holds another machine's entries. The lines
compared are only those from the journal's oldest entry on (read from every
entry: on a real host a file's header gave one time for its first and last
entry, and the clock was set back after its first entry), so what is held is
bounded by the journal's period, not by the syslog's size: the years of rotated
text logs before it are never held. The end of that period is the acquisition. A syslog line
with no `time_utc` (no zone known) cannot be compared, and the journal's copy
of it stays.

No filtering beyond that, no flags: art_log_auth, art_log_cron and art_log_sudo are the
classified views over a part of the same lines.
"""

from __future__ import annotations

import csv
import heapq
import mmap
import struct
from collections import Counter
from datetime import datetime, timezone

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._journal import _ENTRY, _SIGNATURE, _File, journal_files
from artifact_engine.handlers._lincommon import iter_log_lines, root
from artifact_engine.handlers._syslogtime import Clock
from artifact_engine.handlers._varlog import SYSLOG_LINE, log_files

_HEADER = ["time_local", "time_utc", "host", "program", "pid", "message", "source", "file",
           "boot_id", "uid", "comm", "unit", "priority", "transport"]
_NO_JOURNAL = [""] * 6

# journal entry fields -> index in the entry row below
_FIELDS = {b"_BOOT_ID": 1, b"_HOSTNAME": 2, b"SYSLOG_IDENTIFIER": 3, b"_PID": 4, b"_UID": 5,
           b"_COMM": 6, b"_SYSTEMD_UNIT": 7, b"PRIORITY": 8, b"_TRANSPORT": 9, b"MESSAGE": 10}
_SYSLOG_PID = b"SYSLOG_PID"
_HEADER_SIZE_AT = 88
_FOREVER = 1 << 62
_CACHE_MAX = 1 << 20
# A forwarded event is written by rsyslog within this many seconds of the journal.
_SKEW = 1
# Margin before the journal's first entry.
_MARGIN = 3600


def _utc(realtime: int) -> str:
    return datetime.fromtimestamp(realtime / 1e6, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _epoch(utc: str) -> int | None:
    """`time_utc` of a syslog row ("YYYY-MM-DD HH:MM:SS") as epoch seconds."""
    try:
        return int(datetime.fromisoformat(utc).replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


_SELF = "\0self"                 # a syslog host that can only be this machine
_SELF_NAMES = {"", "localhost"}


def _host(host: str) -> str:
    h = host.split(".", 1)[0].lower()
    return _SELF if h in _SELF_NAMES else h


def _key(sec: int, host: str, program: str, message: str) -> int:
    return hash((sec, host, program, message.strip()))


def _first_entry(path) -> int | None:
    """Epoch seconds of the oldest entry of one journal file, from every ENTRY
    object, walked without decoding any field. Not the header's head/tail times:
    on a real host an active file's header gave the same time for both, its
    entries spread over days. Not the first entry either: the clock can be set
    back after it (a hardware clock in local time, corrected at boot), and on
    that host entries two hours older came later in the file."""
    oldest = None
    try:
        with open(path, "rb") as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    except (OSError, ValueError):
        return None
    with mm:
        if mm[:8] != _SIGNATURE or len(mm) < 240:
            return None
        jf = _File(mm)
        off = (struct.unpack_from("<Q", mm, _HEADER_SIZE_AT)[0] + 7) & ~7
        while off + 16 <= jf.size:
            o = jf.obj(off)
            if o is None:
                break                                  # the end of the written arena
            if o[0] == _ENTRY and o[2] >= 64:
                realtime = struct.unpack_from("<Q", mm, off + 24)[0]
                if realtime and (oldest is None or realtime < oldest):
                    oldest = realtime
            off += (o[2] + 7) & ~7
    return oldest // 1_000_000 if oldest else None


def _span(files) -> tuple[int, int]:
    """Epoch seconds from the journal's first entry on, to the acquisition. A file
    with no entry adds nothing; with none at all the span is empty and nothing is
    compared."""
    firsts = [t for t in map(_first_entry, files) if t]
    return (min(firsts) - _MARGIN, _FOREVER) if firsts else (0, -1)


def _entries(path, stats: Counter):
    """(realtime, row) for every entry of one file, file order; row is
    [time_utc, boot, host, identifier, pid, uid, comm, unit, priority, transport,
    message]."""
    try:
        with open(path, "rb") as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    except (OSError, ValueError):
        stats["unreadable"] += 1
        return
    with mm:
        if mm[:8] != _SIGNATURE or len(mm) < 240:
            stats["not_journal"] += 1
            return
        jf = _File(mm)
        stats["files"] += 1
        cache: dict[int, tuple[bytes, bytes] | None] = {}
        fmt_one = "<I" if jf.compact else "<Q"
        off = struct.unpack_from("<Q", mm, _HEADER_SIZE_AT)[0]
        off = (off + 7) & ~7
        while off + 16 <= jf.size:
            o = jf.obj(off)
            if o is None:
                break                                  # the end of the written arena
            if o[0] == _ENTRY and o[2] >= 64:
                realtime = struct.unpack_from("<Q", mm, off + 24)[0]
                row = [""] * 11
                spid = ""
                for i in range((o[2] - 64) // jf.item):
                    d_off = struct.unpack_from(fmt_one, mm, off + 64 + i * jf.item)[0]
                    fv = cache.get(d_off)
                    if fv is None and d_off not in cache:
                        fv = jf.data(d_off)
                        if len(cache) >= _CACHE_MAX:
                            cache.clear()
                        cache[d_off] = fv
                    if not fv:
                        continue
                    if fv == (b"", b""):
                        stats["undecoded"] += 1
                        continue
                    k = _FIELDS.get(fv[0])
                    if k is not None:
                        row[k] = fv[1].decode("utf-8", "replace")
                    elif fv[0] == _SYSLOG_PID:
                        spid = fv[1].decode("utf-8", "replace")
                if realtime:
                    row[0] = _utc(realtime)
                    if not row[4]:
                        row[4] = spid
                    row[10] = row[10].replace("\r", " ").replace("\n", " ")
                    stats["entries"] += 1
                    yield realtime, row
            off += (o[2] + 7) & ~7


def _sourced(path, src: str, stats: Counter):
    for t, row in _entries(path, stats):
        yield t, row, src


def run(ctx) -> None:
    files = list(log_files(ctx.evidence, "syslog"))
    jfiles = journal_files(root(ctx.evidence))
    if not files and not jfiles:
        raise HandlerSkip("no syslog-format logs under /var/log and no systemd journal")
    clock = Clock(ctx.evidence)
    span = _span(jfiles) if jfiles else (0, -1)
    seen: Counter = Counter()          # a line stands for one journal entry, not all
    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "art_log_syslog.csv"
    rows = dropped = 0
    stats: Counter = Counter()
    try:
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(_HEADER)
            for f in files:
                src = str(f.relative_to(ctx.evidence))
                bound = clock.bound(f)
                for line in iter_log_lines(f):
                    line = line.rstrip("\r")
                    if not line.strip():
                        continue
                    m = SYSLOG_LINE.match(line)
                    if m:
                        ts = m.group("ts")
                        utc = clock.utc(ts, bound)
                        host, prog, msg = m.group("host"), m.group("program"), m.group("message")
                        w.writerow([ts, utc, host, prog, m.group("pid") or "", msg,
                                    "syslog", src, *_NO_JOURNAL])
                        sec = _epoch(utc) if utc and jfiles else None
                        if sec is not None and span[0] <= sec <= span[1]:
                            seen[_key(sec, _host(host), prog, msg)] += 1
                    else:
                        w.writerow(["", "", "", "", "", line, "syslog", src, *_NO_JOURNAL])
                    rows += 1
            streams = [_sourced(f, str(f.relative_to(ctx.evidence)), stats) for f in jfiles]
            for t, e, src in heapq.merge(*streams, key=lambda x: x[0]):
                sec, ident, msg = t // 1_000_000, e[3], e[10]
                hosts = (_host(e[2]), _SELF)
                k = next((k for k in (_key(sec + d, h, ident, msg)
                                      for d in range(-_SKEW, _SKEW + 1) for h in hosts)
                          if seen[k] > 0), None) if seen else None
                if k is not None:
                    seen[k] -= 1
                    dropped += 1
                    continue
                w.writerow(["", e[0], e[2], ident, e[4], msg, "journal", src,
                            e[1], e[5], e[6], e[7], e[8], e[9]])
                rows += 1
    except BaseException:
        out.unlink(missing_ok=True)          # a prefix is not a shorter table
        raise
    if rows == 0:
        out.unlink(missing_ok=True)
    if ctx.log:
        ctx.log.debug(f"syslog: {rows} row(s) from {len(files)} file(s) and {len(jfiles)} "
                      f"journal file(s); {dropped} journal entr(ies) already in syslog; "
                      f"{seen.total()} "
                      f"line(s) left unmatched of those held; "
                      f"{dict(stats)}")
