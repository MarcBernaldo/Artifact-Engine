"""Handler: login history from var/log/wtmp (binary utmp, x86-64 layout). Output: wtmp.csv

The same record layout backs btmp (failed logins), so `parse_utmp` is shared
with lin_btmp.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.handlers._lincommon import root, write_csv

# utmp ut_type codes (bits/utmp.h)
_TYPES = {
    0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
    5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}

_REC = 384  # sizeof(struct utmp) on Linux x86-64

COLUMNS = ["time_utc", "user", "type", "line", "host"]


def parse_utmp(path: Path) -> list[list]:
    """Parse a binary utmp/wtmp/btmp file into rows [time, user, type, line, host]."""
    rows: list[list] = []
    try:
        data = path.read_bytes()
    except OSError:
        return rows
    for i in range(0, len(data) - _REC + 1, _REC):
        r = data[i:i + _REC]
        try:
            ut_type = struct.unpack_from("<i", r, 0)[0]
            line = r[8:40].split(b"\x00", 1)[0].decode("latin1", "replace")
            user = r[44:76].split(b"\x00", 1)[0].decode("latin1", "replace")
            host = r[76:332].split(b"\x00", 1)[0].decode("latin1", "replace")
            sec = struct.unpack_from("<i", r, 340)[0]
            ts = (datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                  if sec else "")
        except Exception:  # noqa: BLE001
            continue
        if user.strip():
            rows.append([ts, user, _TYPES.get(ut_type, str(ut_type)), line, host])
    return rows


def run(ctx) -> None:
    wtmp = root(ctx.evidence) / "var" / "log" / "wtmp"
    rows = parse_utmp(wtmp) if wtmp.is_file() else []
    write_csv(ctx.out, "wtmp.csv", COLUMNS, rows)
