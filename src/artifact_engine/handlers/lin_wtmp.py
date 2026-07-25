"""Handler: login history from var/log/wtmp (binary utmp, x86-64 layout). Output: wtmp.csv

The same record layout backs btmp (failed logins), so `parse_utmp` is shared
with lin_btmp.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.handlers._lincommon import root, stream_csv

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
    """
    try:
        fh = open(path, "rb")
    except OSError:
        return
    with fh:
        while True:
            try:
                buf = fh.read(_CHUNK)
            except OSError:
                return
            if not buf:
                return
            for i in range(0, len(buf) - _REC + 1, _REC):
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


def write_utmp(ctx, path: Path, name: str) -> None:
    """Stream one utmp-family file to `name`; shared with lin_btmp."""
    if not path.is_file():
        return
    with stream_csv(ctx.out, name, COLUMNS) as emit:
        for row in iter_utmp(path):
            emit(row)


def run(ctx) -> None:
    write_utmp(ctx, root(ctx.evidence) / "var" / "log" / "wtmp", "wtmp.csv")
