"""Reader for systemd journal files, standard library only.

Debian 12 and most cloud images keep no auth.log/secure/syslog: the journal is
the only log there is, and it is binary. journalctl does not exist on the host
the engine runs on, so this reads the on-disk format (systemd's "Journal File
Format") directly. Two ways: `syslog_lines` gives the entries of chosen
programs as the syslog lines they would have been (auth, art_log_cron), and the
object primitives here let `lin_syslog` walk every entry (v0.7.153; its
journal rows of art_log_syslog.csv since v0.7.162).

How `syslog_lines` finds them without walking every object: a journal stores each distinct
`FIELD=value` once, as a DATA object, and that object lists every entry that
carries it. So the reader looks for the `SYSLOG_IDENTIFIER=<program>` DATA
objects (a byte search, then the object header around the hit is checked),
follows their entry lists, and decodes only those entries. On a host whose
journal is millions of entries, auth reads sshd's and leaves the rest to `syslog`.

Payloads larger than a few hundred bytes may be compressed: XZ is decoded with
`lzma`; LZ4 and ZSTD only when the `lz4`/`zstandard` package is importable. An
entry whose MESSAGE cannot be decoded is counted in `stats`, never guessed.
"""

from __future__ import annotations

import heapq
import lzma
import mmap
import struct
from array import array
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_SIGNATURE = b"LPKSHHRH"
_INCOMPAT_COMPACT = 16
_DATA, _ENTRY, _ENTRY_ARRAY = 1, 3, 6
_XZ, _LZ4, _ZSTD = 1, 2, 4
_IDENT = b"SYSLOG_IDENTIFIER="
_WANTED = (b"_HOSTNAME", b"SYSLOG_IDENTIFIER", b"_PID", b"SYSLOG_PID", b"MESSAGE")

# Where a host keeps its journal: persistent, then volatile (relative to [root]).
JOURNAL_DIRS = ("var/log/journal", "run/log/journal")


def journal_files(root: Path) -> list[Path]:
    """Every journal file under the host's journal directories (active, archived
    `@...journal`, and the `.journal~` a crash leaves)."""
    out = []
    for rel in JOURNAL_DIRS:
        d = root / rel
        if d.is_dir():
            out += sorted(f for f in d.rglob("*.journal*") if f.is_file())
    return out


def _decompress(flags: int, payload: bytes) -> bytes | None:
    if flags & _XZ:
        try:
            return lzma.decompress(payload)
        except lzma.LZMAError:
            return None
    if flags & _LZ4:
        try:
            import lz4.block
        except ImportError:
            return None
        if len(payload) < 8:
            return None
        size = struct.unpack_from("<Q", payload)[0]
        try:
            return lz4.block.decompress(payload[8:], uncompressed_size=size)
        except Exception:      # noqa: BLE001 -- a damaged block is one lost entry
            return None
    if flags & _ZSTD:
        try:
            import zstandard
        except ImportError:
            return None
        try:
            return zstandard.ZstdDecompressor().decompressobj().decompress(payload)
        except zstandard.ZstdError:
            return None
    return payload


class _File:
    def __init__(self, mm: mmap.mmap):
        self.mm = mm
        self.size = len(mm)
        self.compact = bool(struct.unpack_from("<I", mm, 12)[0] & _INCOMPAT_COMPACT)
        self.data_payload = 72 if self.compact else 64
        self.item = 4 if self.compact else 16
        self.slot = 4 if self.compact else 8

    def obj(self, off: int) -> tuple[int, int, int] | None:
        """(type, flags, size) of the object at `off`, or None if it is not one."""
        if off <= 0 or off % 8 or off + 16 > self.size:
            return None
        otype, flags = self.mm[off], self.mm[off + 1]
        size = struct.unpack_from("<Q", self.mm, off + 8)[0]
        if size < 16 or off + size > self.size:
            return None
        return otype, flags, size

    def data(self, off: int) -> tuple[bytes, bytes] | None:
        """(field, value) of a DATA object, None if it is not one, (b"", b"")
        if its payload is compressed in a form this host cannot decode."""
        o = self.obj(off)
        if o is None or o[0] != _DATA or o[2] < self.data_payload:
            return None
        raw = self.mm[off + self.data_payload: off + o[2]]
        if o[1] & 7:
            raw = _decompress(o[1], raw)
            if raw is None:
                return b"", b""
        field, sep, value = raw.partition(b"=")
        return (field, value) if sep else None

    def identifiers(self) -> dict[str, int]:
        """identifier -> offset of its `SYSLOG_IDENTIFIER=` DATA object."""
        out: dict[str, int] = {}
        mm, start = self.mm, 0
        while True:
            pos = mm.find(_IDENT, start)
            if pos < 0:
                return out
            start = pos + 1
            off = pos - self.data_payload
            o = self.obj(off)
            if o is None or o[0] != _DATA or o[1] & 7:
                continue
            payload = mm[pos: off + o[2]]
            if b"\n" in payload or b"\0" in payload:
                continue
            out[payload[len(_IDENT):].decode("utf-8", "replace")] = off

    def entries_of(self, data_off: int) -> array:
        """Offsets of every entry carrying this DATA object, in append order."""
        mm = self.mm
        first, arr, n = struct.unpack_from("<QQQ", mm, data_off + 40)
        out = array("Q")
        if first:
            out.append(first)
        seen = 0
        while arr and len(out) < n and seen < 1_000_000:
            seen += 1
            o = self.obj(arr)
            if o is None or o[0] != _ENTRY_ARRAY:
                break
            nxt = struct.unpack_from("<Q", mm, arr + 16)[0]
            count = (o[2] - 24) // self.slot
            fmt = f"<{count}{'I' if self.compact else 'Q'}"
            for e in struct.unpack_from(fmt, mm, arr + 24):
                if not e or len(out) >= n:
                    break
                out.append(e)
            arr = nxt
        return out

    def entry(self, off: int, stats: Counter) -> tuple[int, dict[bytes, bytes]] | None:
        o = self.obj(off)
        if o is None or o[0] != _ENTRY or o[2] < 64:
            return None
        realtime = struct.unpack_from("<Q", self.mm, off + 24)[0]
        fields: dict[bytes, bytes] = {}
        for i in range((o[2] - 64) // self.item):
            at = off + 64 + i * self.item
            d_off = struct.unpack_from("<I" if self.compact else "<Q", self.mm, at)[0]
            fv = self.data(d_off)
            if fv is None:
                continue
            if fv == (b"", b""):          # a field we may not even want: counted
                stats["undecoded"] += 1
                continue
            if fv[0] in _WANTED:
                fields[fv[0]] = fv[1]
        return realtime, fields


def _ts(realtime: int) -> str:
    """Microseconds since the epoch -> the ISO form RFC 5424 syslog writes, UTC."""
    return datetime.fromtimestamp(realtime / 1e6, timezone.utc).isoformat(timespec="microseconds")


def _line(realtime: int, f: dict[bytes, bytes]) -> str:
    def s(k: bytes) -> str:
        return f.get(k, b"").decode("utf-8", "replace")
    host = s(b"_HOSTNAME") or "-"
    ident = s(b"SYSLOG_IDENTIFIER")
    pid = s(b"SYSLOG_PID") or s(b"_PID")
    msg = s(b"MESSAGE").replace("\r", " ").replace("\n", " ")
    tag = f"{ident}[{pid}]" if pid.isdigit() else ident
    return f"{_ts(realtime)} {host} {tag}: {msg}"


def _file_lines(path: Path, want, stats: Counter):
    """(realtime, syslog line) for the wanted programs in one file, file order."""
    try:
        with open(path, "rb") as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    except (OSError, ValueError):                # unreadable, empty or unmappable
        stats["unreadable"] += 1
        return
    with mm:
        if mm[:8] != _SIGNATURE or len(mm) < 240:
            stats["not_journal"] += 1
            return
        jf = _File(mm)
        stats["files"] += 1
        offsets = [jf.entries_of(off) for ident, off in jf.identifiers().items()
                   if want(ident)]
        last = -1
        for e_off in heapq.merge(*offsets):
            if e_off == last:
                continue
            last = e_off
            got = jf.entry(e_off, stats)
            if got is None or not got[0]:
                continue
            stats["entries"] += 1
            yield got[0], _line(*got)


def syslog_lines(root: Path, want, stats: Counter | None = None):
    """The journal entries of every program `want(identifier)` accepts, as
    `<ISO-UTC> <host> <ident>[pid]: <message>` lines, oldest first across files."""
    stats = stats if stats is not None else Counter()
    streams = [_file_lines(f, want, stats) for f in journal_files(root)]
    for _, line in heapq.merge(*streams, key=lambda t: t[0]):
        yield line
