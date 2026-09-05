"""Reading an EvtxECmd CSV row when the map is not enough.

EvtxECmd flattens the interesting fields of a known event into `PayloadData1..6`,
`ExecutableInfo` and `UserName` using a `.map` file, and writes the whole
EventData as JSON in `Payload` regardless. The maps are generous but not
complete -- Defender's action, error code and remediation user are all in the
event and in none of its map's properties -- and a dump produced without the map
folder has nothing but the JSON.

So a handler reads the mapped column first and falls back here, and neither the
finding nor the columns depend on which one this particular case happened to get.

THE JSON HAS TWO SHAPES. A named EventData field can arrive flattened
(`{"Action Name": "Quarantine"}`) or as the XML node it came from
(`{"@Name": "Action Name", "#text": "Quarantine"}`), depending on the event and
the EvtxECmd version. Both are searched, because a handler that knows only one
works on some hosts in a case and not others -- which is worse than not working.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

# Guard against a pathological payload: a malformed blob can nest deeply, and a
# handler must not spend a worker on one row.
_MAX_NODES = 5_000


# EvtxECmd writes `2026-05-19 11:22:33.1234567`, and some versions an ISO form
# with a `T` and an offset. Both start with the same sixteen characters.
_TS = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)")


def when(value: str) -> datetime | None:
    """A `TimeCreated` cell as an aware datetime, or None if it is not one.

    EvtxECmd normalises the channel to UTC, so the value is read as UTC: an
    ordering computed from these is an ordering in real time, which is the whole
    reason a handler asks for it (did the delete follow the create, or replace it).
    """
    m = _TS.match((value or "").strip())
    if not m:
        return None
    try:
        return datetime(*map(int, m.groups()), tzinfo=timezone.utc)
    except ValueError:
        return None


def after(value: str, label: str) -> str:
    """`"Malware name: X"` -> `"X"`, and anything else unchanged.

    A map writes its properties as `Label: value`; a value that arrived some
    other way is returned as it stands rather than mangled.
    """
    text = (value or "").strip()
    want = label.lower() + ":"
    return text[len(want):].strip() if text.lower().startswith(want) else text


def _named(node: dict) -> tuple[str, str] | None:
    """(name, text) when this dict is an XML Data node rather than a mapping."""
    name = node.get("@Name") or node.get("Name")
    if not isinstance(name, str):
        return None
    text = node.get("#text", node.get("Text", ""))
    return name, "" if text is None else str(text)


def payload_field(payload: str, key: str) -> str:
    """One EventData field out of EvtxECmd's raw `Payload` JSON, or "".

    Matching is case-insensitive because Defender's field names carry spaces and
    inconsistent casing (`Action Name`, `Detection User`) and nothing is gained by
    being strict about either.
    """
    text = (payload or "").strip()
    if not text:
        return ""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        # Not JSON (a truncated cell, or a version that wrote something else):
        # the field may still be findable as text, which beats returning nothing.
        m = re.search(rf'"{re.escape(key)}"\s*:\s*"([^"]*)"', text, re.IGNORECASE)
        return m.group(1) if m else ""

    want = key.lower()
    stack, seen = [data], 0
    while stack and seen < _MAX_NODES:
        node = stack.pop()
        seen += 1
        if isinstance(node, dict):
            pair = _named(node)
            if pair and pair[0].lower() == want:
                return pair[1]
            for k, v in node.items():
                if isinstance(k, str) and k.lower() == want and isinstance(v, (str, int, float)):
                    return str(v)
                stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
    return ""


# --------------------------------------------------------------------------- #
# Windows encodes two things in these logs that read as noise until decoded
# --------------------------------------------------------------------------- #
_AF_INET, _AF_INET6 = 2, 23


def sockaddr_from_hex(value: str) -> tuple[str, int]:
    """A SOCKADDR_STORAGE hex blob as (address, port), or ("", 0).

    SMBClient logs the peer as the raw socket address, which reads as thirty-two
    hex characters and is therefore skipped by every eye that passes over it. The
    layout is fixed: two bytes of address family (little-endian), two bytes of
    port (BIG-endian, it is network order), then the address itself. Getting the
    two byte orders the same way round yields a plausible-looking wrong port,
    which is worse than no port at all.
    """
    text = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if text.lower().startswith("0x"):
        text = text[2:]
    if len(text) < 16 or len(text) % 2:
        return "", 0
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return "", 0
    family = int.from_bytes(raw[0:2], "little")
    port = int.from_bytes(raw[2:4], "big")
    if family == _AF_INET and len(raw) >= 8:
        return ".".join(str(b) for b in raw[4:8]), port
    if family == _AF_INET6 and len(raw) >= 24:
        # sockaddr_in6: family, port, 4 bytes flowinfo, then the 16-byte address.
        groups = [f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(8, 24, 2)]
        return _compact_v6(groups), port
    return "", 0


def _compact_v6(groups: list[str]) -> str:
    """`0000` groups collapsed to `::`, the way an address is written down."""
    parts = [g.lstrip("0") or "0" for g in groups]
    best_at = best_len = run_at = run_len = -1
    for i, part in enumerate(parts + ["x"]):
        if part == "0":
            run_at = i if run_len <= 0 else run_at
            run_len = 1 if run_len <= 0 else run_len + 1
            continue
        if run_len > best_len:
            best_at, best_len = run_at, run_len
        run_len = 0
    if best_len < 2:
        return ":".join(parts)
    return ":".join(parts[:best_at]) + "::" + ":".join(parts[best_at + best_len:])


# The NTSTATUS values these channels actually carry. A refused connection and a
# completed one are very different findings, and today both are an opaque
# ten-digit integer. Anything not listed still gets an answer -- the severity
# lives in the top two bits, so "unknown, and it IS an error" is a real one.
_NTSTATUS = {
    0x00000000: "STATUS_SUCCESS",
    0x00000103: "STATUS_PENDING",
    0x80000006: "STATUS_NO_MORE_FILES",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
    0xC000005E: "STATUS_NO_LOGON_SERVERS",
    0xC0000064: "STATUS_NO_SUCH_USER",
    0xC000006A: "STATUS_WRONG_PASSWORD",
    0xC000006D: "STATUS_LOGON_FAILURE",
    0xC000006E: "STATUS_ACCOUNT_RESTRICTION",
    0xC0000072: "STATUS_ACCOUNT_DISABLED",
    0xC00000B5: "STATUS_IO_TIMEOUT",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC00000BE: "STATUS_BAD_NETWORK_PATH",
    0xC00000CC: "STATUS_BAD_NETWORK_NAME",
    0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
    0xC000018D: "STATUS_TRUSTED_RELATIONSHIP_FAILURE",
    0xC0000192: "STATUS_NETLOGON_NOT_STARTED",
    0xC0000193: "STATUS_ACCOUNT_EXPIRED",
    0xC000020C: "STATUS_CONNECTION_DISCONNECTED",
    0xC000020D: "STATUS_CONNECTION_RESET",
    0xC0000203: "STATUS_USER_SESSION_DELETED",
    0xC0000224: "STATUS_PASSWORD_MUST_CHANGE",
    0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
    0xC0000236: "STATUS_CONNECTION_REFUSED",
    0xC000023C: "STATUS_NETWORK_UNREACHABLE",
    0xC000023D: "STATUS_HOST_UNREACHABLE",
    0xC0000241: "STATUS_CONNECTION_ABORTED",
    0xC0000257: "STATUS_PATH_NOT_COVERED",
    0xC0000466: "STATUS_SERVER_UNAVAILABLE",
    0xC0000467: "STATUS_FILE_NOT_AVAILABLE",
}

_SEVERITY = {0b00: "success", 0b01: "informational", 0b10: "warning", 0b11: "error"}


def ntstatus_name(value) -> str:
    """A decimal or hex NTSTATUS as `NAME (0x........)`, or "" when it is not one.

    An unlisted code is still answered, with its severity, because "0xC0000704,
    error" tells an analyst the connection failed and "3221226756" tells them
    nothing at all.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        code = int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return ""
    code &= 0xFFFFFFFF
    name = _NTSTATUS.get(code)
    if name:
        return f"{name} (0x{code:08X})"
    return f"unknown {_SEVERITY[code >> 30]} (0x{code:08X})"
