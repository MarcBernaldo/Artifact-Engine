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
