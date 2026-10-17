"""Handler: every systemd journal entry on the host. Output: journal.csv

`_journal` reads the entries of a few programs for auth_log and cron_log by
following their `SYSLOG_IDENTIFIER=` lists; this walks every ENTRY object of
every journal file instead (persistent and volatile, archived, and the
`.journal~` a crash leaves), in file order, merged across files by time.

One row per entry, the fields an analyst filters on: time (UTC: the journal
stores microseconds since the epoch), boot, host, identifier, pid, uid, comm,
systemd unit, priority, transport and the message. No filtering, no flags.

Fields repeat across entries (the host, the boot, the unit) and the journal
stores each distinct value once, so decoded DATA objects are cached by offset:
most of an entry is a dictionary hit. An entry's payload compressed with a
codec this host lacks (LZ4/ZSTD without their package) is counted, never
guessed, like `_journal` does.
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
from artifact_engine.handlers._lincommon import root

_HEADER = ["time_utc", "boot_id", "host", "identifier", "pid", "uid", "comm", "unit",
           "priority", "transport", "message", "source"]
_FIELDS = {b"_BOOT_ID": 1, b"_HOSTNAME": 2, b"SYSLOG_IDENTIFIER": 3, b"_PID": 4, b"_UID": 5,
           b"_COMM": 6, b"_SYSTEMD_UNIT": 7, b"PRIORITY": 8, b"_TRANSPORT": 9, b"MESSAGE": 10}
_SYSLOG_PID = b"SYSLOG_PID"
_HEADER_SIZE_AT = 88
_CACHE_MAX = 1 << 20


def _utc(realtime: int) -> str:
    return datetime.fromtimestamp(realtime / 1e6, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _entries(path, stats: Counter):
    """(realtime, row-without-source) for every entry of one file, file order."""
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
    base = root(ctx.evidence)
    files = journal_files(base)
    if not files:
        raise HandlerSkip("no systemd journal files")
    stats: Counter = Counter()
    streams = [_sourced(f, str(f.relative_to(ctx.evidence)), stats) for f in files]
    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "journal.csv"
    rows = 0
    try:
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(_HEADER)
            for _t, row, src in heapq.merge(*streams, key=lambda x: x[0]):
                w.writerow([*row, src])
                rows += 1
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    if rows == 0:
        out.unlink(missing_ok=True)
    if ctx.log:
        ctx.log.debug(f"journal: {rows} entries; {dict(stats)}")
