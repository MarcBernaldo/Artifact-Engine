"""XML parsing for the Windows handlers, with entity expansion refused.

Not a handler (leading underscore). `xml.etree.ElementTree` expands internal
entities at parse time: five nested definitions in a 300-byte file produce half a
megabyte, seven produce gigabytes - the classic "billion laughs". The XML this
engine parses (GPP Preferences under SYSVOL, the on-disk Task Scheduler store)
comes off a host the attacker owned, and SYSVOL in particular is writable by
whoever holds Domain Admin, which in a ransomware case is them. A planted file
would then hang the triage on the *analyst's* workstation - the same reason the
extractor caps archive expansion.

No genuine GPP or Task Scheduler document declares an entity, so refusing the
declaration outright costs nothing and needs no third-party dependency. The
declaration must appear in the DOCTYPE's internal subset, ahead of the root
element, so a scan of the bytes catches it before expansion can start.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

_ENTITY_DECL = re.compile(rb"<!ENTITY", re.IGNORECASE)


def fromstring(data: bytes) -> ET.Element:
    """`ET.fromstring`, raising ParseError on a document that declares entities.

    Callers already treat ParseError as "unreadable XML, move on", so a refused
    file is skipped exactly like a corrupt one.
    """
    if _ENTITY_DECL.search(data):
        raise ET.ParseError("XML entity declaration refused (expansion bomb guard)")
    return ET.fromstring(data)
