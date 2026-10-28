r"""Handler: hayabusa detections by rule and the address they came from. Output: alert_hayabusa.csv

`art_hayabusa.csv` is a per-event timeline, and on an estate holding its own
publicly-routable address space it is mostly one rule saying the same thing:
"External Remote RDP Logon from Public IP", four hundred times, about four hundred
ordinary internal sessions. Triaging that by hand, per host, is pure waste, and
the real cost is that the analyst stops reading the rule class at all.

Two things fix it, and neither is a filter.

AGGREGATE BY SOURCE. The actionable unit is "rule X fired N times from source Y",
not every event -- the same argument `alert_web` already makes about access logs.
Four hundred rows become one per source, which is the shape a person can read.

SAY WHICH SIDE OF THE PERIMETER THE SOURCE IS ON. `internal_networks` (see
`core/netclass.py`) turns the noisy class into a marked one: a source inside a
declared range is annotated `internal`, and where the RULE'S OWN PREMISE is that
the source is public, the row is DOWNGRADED with the reason written next to it.

WHAT IS AND IS NOT DOWNGRADED, because getting this wrong would hide findings.
The marker patterns below were derived by reading the shipped ruleset, not
guessed: of 4,959 rules, the ones whose premise is a public SOURCE all phrase it
"Logon from Public IP" / "Logon from External Network". A substring match on
`external` or `public ip` would have swept in "Outbound Network Connection To
Public IP Via Winlogon" -- a rule about a DESTINATION, where an internal source
means nothing at all -- and "External Disk Drive Or USB Storage Device Was
Recognized". Everything else keeps its level untouched: a webshell rule firing
from an internal address is lateral movement, which is the last thing to quieten.

HAYABUSA'S OWN OUTPUT IS NEVER REWRITTEN. This is a second table beside it. A
tool's verdict is evidence and the engine's reading of it is not the same thing,
and an analyst sorting `art_hayabusa.csv` by `Level` must still see what hayabusa
said.

EVERY DETECTION, NOT ONLY THE ONES WITH AN ADDRESS (v0.7.170). Hayabusa writes
the source as `SrcIP:` inside `Details`, which most rules have no reason to
emit. Those used to be one count line here, and the front page read them from
`art_hayabusa.csv` row by row -- 443,079 rows on one case, three failed-logon rules
94% of them. Now they are rows too, one per (level, rule) with an empty
`source_ip`, so this table is hayabusa's alert: every detection is in exactly
one row, and the front page reads it instead of the timeline, which stays as
the record.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from artifact_engine.core import netclass
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv

_HAYABUSA_CSV = Path("CSVs") / "EventLogs" / "art_hayabusa.csv"

# Hayabusa packs `Key: value` pairs into Details, separated by a broken bar.
_SEP = "¦"
_SRC_KEYS = ("srcip", "sourceip", "ipaddress")

# The rules whose PREMISE is that the source address is public. Read off the
# shipped ruleset rather than guessed: matching `external` or `public ip` loosely
# would also catch rules about a DESTINATION being public, where an internal
# source says nothing. Adding a pattern here is a one-line change; leaving one out
# costs a row that stays at its original level, which is the safe direction.
_EXTERNALITY = re.compile(
    r"logon\s+from\s+(?:a\s+)?(?:public\s+ip|external\s+network)", re.IGNORECASE)

# Levels worth a flag when the source really is outside. Hayabusa 3 and later
# write them short (`crit`, `med`), so `crit` alone never matched `critical`.
_LOUD = {"high", "critical", "crit"}

# `first_seen`/`last_seen` carry NO `_utc` suffix on purpose: hayabusa writes its
# own offset into the value (`2026-05-19 11:22:33.000 +00:00`), and this handler
# passes the string through rather than reparsing it. ARCHITECTURE.md §5.
_COLUMNS = ["level", "rule", "source_ip", "scope", "hits", "first_seen",
            "last_seen", "computer", "channel", "event_ids", "triage",
            "suspicious"]


def source_ip(details: str, extra: str = "") -> str:
    """The source address a detection names, or "".

    `Details` is `Key: value` pairs joined by a broken bar, and the key is what
    makes this safe: scanning the row for anything address-shaped would return the
    TARGET as readily as the source, and a target read as a source inverts the
    finding.
    """
    for blob in (details, extra):
        for part in str(blob or "").split(_SEP):
            key, sep, value = part.partition(":")
            if not sep:
                continue
            if key.strip().lower().replace(" ", "") in _SRC_KEYS:
                text = value.strip()
                if text and text not in ("-", "::1", "127.0.0.1"):
                    return text
    return ""


def downgradeable(rule: str) -> bool:
    """Whether this rule fires ON the source being public, and nothing else."""
    return bool(_EXTERNALITY.search(rule or ""))


class _Source:
    """Every detection of one rule from one address."""

    __slots__ = ("channels", "computers", "eids", "first", "hits", "last")

    def __init__(self) -> None:
        self.hits = 0
        self.first = self.last = ""
        self.eids: set[str] = set()
        self.computers: set[str] = set()
        self.channels: set[str] = set()

    def add(self, when: str, eid: str, computer: str, channel: str) -> None:
        self.hits += 1
        if when:
            self.first = when if not self.first else min(self.first, when)
            self.last = max(self.last, when)
        for value, target in ((eid, self.eids), (computer, self.computers),
                              (channel, self.channels)):
            if value and len(target) < 20:
                target.add(value)


def _collect(src: Path) -> dict[tuple[str, str, str], _Source]:
    """{(level, rule, ip): _Source}; `ip` is "" for a detection naming none."""
    seen: dict[tuple[str, str, str], _Source] = {}
    with src.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(line.replace("\x00", "") for line in fh):
            rule = (row.get("RuleTitle") or "").strip()
            ip = source_ip(row.get("Details") or "", row.get("ExtraFieldInfo") or "")
            key = ((row.get("Level") or "").strip().lower(), rule, ip)
            seen.setdefault(key, _Source()).add(
                (row.get("Timestamp") or "").strip(),
                (row.get("EventID") or "").strip(),
                (row.get("Computer") or "").strip(),
                (row.get("Channel") or "").strip())
    return seen


def verdict(level: str, rule: str, scope: str) -> tuple[str, bool]:
    """(triage note, flagged) for one aggregated source.

    A downgrade is only ever applied where the rule's premise was the source being
    public. Everything else keeps its level: a rule about lateral movement firing
    from an internal address is the case, not the noise.
    """
    if scope in (netclass.INTERNAL, netclass.PRIVATE) and downgradeable(rule):
        where = ("inside a declared internal_networks range"
                 if scope == netclass.INTERNAL else "a private address")
        return f"DOWNGRADED: this rule fires on a public source, and this is {where}", False
    if scope == netclass.PUBLIC:
        return "", level in _LOUD
    return "", False


def run(ctx) -> None:
    src = Path(ctx.evidence) / _HAYABUSA_CSV
    if not src.is_file():
        raise HandlerSkip("no art_hayabusa.csv to read")

    internal = netclass.parse(getattr(ctx, "internal_networks", ()))
    try:
        seen = _collect(src)
    except (OSError, csv.Error) as e:
        raise HandlerSkip(f"art_hayabusa.csv unreadable: {e}") from e
    if not seen:
        return                                # the timeline exists and is empty

    rows: list[list] = []
    for (level, rule, ip), agg in seen.items():
        scope = internal.scope(ip)
        note, flagged = verdict(level, rule, scope)
        rows.append([
            level, rule, ip, scope, agg.hits, agg.first, agg.last,
            " ".join(sorted(agg.computers)), " ".join(sorted(agg.channels)),
            " ".join(sorted(agg.eids)), note, "yes" if flagged else "",
        ])

    # No row cap (v0.7.170): the front page reads this table instead of the
    # timeline, so a row left out here would be on neither.
    rows.sort(key=lambda r: (r[-1] != "yes", bool(r[-2]), -int(r[4])))
    write_csv(ctx.out, "alert_hayabusa.csv", _COLUMNS, rows)
