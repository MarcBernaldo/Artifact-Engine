"""Handler: login history from var/log/wtmp (binary utmp, x86-64 layout). Output: wtmp.csv

The same record layout backs btmp (failed logins), so `iter_utmp`/`write_utmp`
are shared with lin_btmp.

Rotations are read, and they matter more here than anywhere else in the Linux
set: btmp IS the brute-force artifact, and it is what the lateral graph builds
`brute_success` out of. Reading only the file being written now means a spray
from three weeks ago never reaches the graph -- and the graph's silence reads
as "no brute force against this host", which is a different claim entirely.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.handlers._lincommon import (
    LOG_READ_ERRORS,
    open_log_bytes,
    root,
    sort_rotations,
    stream_csv,
)

# utmp ut_type codes (bits/utmp.h)
_TYPES = {
    0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
    5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}

_REC = 384  # sizeof(struct utmp) on Linux x86-64
_CHUNK = _REC * 4096   # ~1.5 MB read at a time, always a whole number of records

COLUMNS = ["time_utc", "user", "type", "line", "host"]


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


def write_utmp(ctx, logdir: Path, stem: str, name: str) -> None:
    """Stream `stem` and its rotations to `name`; shared with lin_btmp."""
    files = utmp_files(logdir, stem)
    if not files:
        return
    with stream_csv(ctx.out, name, COLUMNS) as emit:
        for f in files:
            for row in iter_utmp(f):
                emit(row)


def run(ctx) -> None:
    write_utmp(ctx, root(ctx.evidence) / "var" / "log", "wtmp", "wtmp.csv")
