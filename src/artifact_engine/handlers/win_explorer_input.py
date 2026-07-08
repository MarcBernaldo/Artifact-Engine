"""Handler: what the user TYPED into Explorer (searches + paths). Output: explorer_input.csv

Two NTUSER MRUs that record literal user input, per user:
  - WordWheelQuery: every search typed in the Explorer/Start search box
    (numbered REG_BINARY values, UTF-16LE; MRUListEx gives most-recent-first
    order). What the operator was LOOKING for.
  - TypedPaths: paths typed into the Explorer address bar (url1 = most
    recent). UNC targets here are hand-typed lateral movement.

`order` is the MRU position (0/url1 = most recent); the key's last-write
time dates only the most recent entry, so it is emitted on that row alone.
Informational - what was searched/typed is case context, so no flag column.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_systeminfo import _open

_BASE = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
_URLN = re.compile(r"^url(\d+)$", re.IGNORECASE)


def _utf16z(data) -> str:
    """UTF-16LE null-terminated REG_BINARY -> str."""
    if isinstance(data, bytes):
        return data.decode("utf-16-le", errors="ignore").split("\x00")[0]
    return str(data or "")


def _mru_order(data) -> dict[int, int]:
    """MRUListEx bytes -> {value_index: position} (0 = most recent)."""
    order: dict[int, int] = {}
    if not isinstance(data, bytes):
        return order
    for pos in range(len(data) // 4):
        (idx,) = struct.unpack_from("<I", data, pos * 4)
        if idx == 0xFFFFFFFF:
            break
        order.setdefault(idx, pos)
    return order


def _key_ts(key) -> str:
    try:
        return key.timestamp().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:  # noqa: BLE001 - fake/corrupt key
        return ""


def _scan_hive(reg) -> list[list]:
    """[[kind, order, value, last_write], ...] for one NTUSER hive."""
    rows: list[list] = []
    try:
        k = reg.open(_BASE + r"\WordWheelQuery")
        vals = {v.name(): v.value() for v in k.values()}
        order = _mru_order(vals.pop("MRUListEx", b""))
        ts = _key_ts(k)
        for name, data in vals.items():
            if not name.isdigit():
                continue
            term = _utf16z(data)
            if term:
                pos = order.get(int(name))
                rows.append(["search", "" if pos is None else pos, term,
                             ts if pos == 0 else ""])
    except Exception:  # noqa: BLE001 - key absent
        pass
    try:
        k = reg.open(_BASE + r"\TypedPaths")
        ts = _key_ts(k)
        for v in k.values():
            m = _URLN.match(v.name() or "")
            path = str(v.value() or "").strip()
            if m and path:
                n = int(m.group(1))
                rows.append(["typed_path", n - 1, path, ts if n == 1 else ""])
    except Exception:  # noqa: BLE001 - key absent
        pass
    return rows


def run(ctx) -> None:
    users_dir = Path(ctx.evidence) / "Users"
    ntusers = sorted(users_dir.glob("*/NTUSER.DAT")) if users_dir.is_dir() else []
    if not ntusers:
        raise HandlerSkip("no NTUSER hives")

    rows: list[list] = []
    for ntuser in ntusers:
        reg = _open(ntuser)
        if reg is None:
            continue
        for kind, order, value, ts in _scan_hive(reg):
            rows.append([ntuser.parent.name, kind, order, value, ts])

    rows.sort(key=lambda r: (r[0].lower(), r[1], r[2] if r[2] != "" else 10**6))
    write_csv(ctx.out, "explorer_input.csv",
              ["user", "kind", "order", "value", "key_last_write_utc"], rows)
