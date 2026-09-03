"""Handler: how far back Windows logging actually reaches. Output: log_coverage.csv

`lin_log_integrity` already argues this point for /var/log: a host holding a day
and a host holding a year both produce an auth.csv, and only one of them has
anything to say about an intrusion from last month. The Windows side had no
equivalent, and the gap changes conclusions -- a channel that holds ten days
answers "nothing happened three weeks ago" with a silence that reads exactly like
evidence of a quiet host.

Nothing new is extracted. EvtxECmd has already written one CSV per channel by the
time this runs; every question here is a `TimeCreated` away.

TWO KINDS OF SILENCE, TOLD APART. A gap is only interesting once the channel is
known to have been logging on both sides of it, so gaps are measured strictly
INSIDE a channel's own span. Then:

- the channel is dark while SIBLING channels on the same host keep logging --
  the one worth an analyst's attention, and the only verdict flagged here;
- every channel is dark together -- the host was off, or was not collected;
- the channel simply starts later than its siblings -- rotation, a full log that
  no longer reaches back. Not tampering, and not flagged. It is still the fact
  that inverts a conclusion, which is why the coverage table is printed in
  report.txt on every run instead of only when something is wrong.

ONLY AN UNFILTERED DUMP CAN ANSWER THIS. Most `evtx_*` parsers pass `--inc` and
keep a handful of event IDs, so their first and last rows describe the FILTER,
not the channel. Those are reported as a floor -- the channel existed at least
across this range -- and never gap-analysed. Which dumps are unfiltered is the
one fact hardcoded below; the channel names are read back out of the data.
"""

from __future__ import annotations

import csv
import re
from datetime import date, timedelta
from itertools import pairwise
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv

_EVENTLOGS = Path("CSVs") / "EventLogs"

# EvtxECmd dumps written with no `--inc`: every record the channel held.
_FULL = ("evtx_security.csv", "evtx_system.csv", "evtx_application.csv",
         "evtx_sysmon.csv", "evtx_defender.csv")

# Dumps written with `--inc <ids>`. Their span is a floor on the channel's, and
# their gaps are the filter's gaps, not the channel's.
_FILTERED = ("evtx_bits.csv", "evtx_pwsh.csv", "evtx_pwshScrip.csv",
             "evtx_rdpAuth.csv", "evtx_rdpIn.csv", "evtx_rdpOut.csv",
             "evtx_rdpSessions.csv", "evtx_tsch.csv", "evtx_wmi.csv")

# Events that describe the logging itself. Scanned only in the two unfiltered
# dumps that carry them -- 1102 also appears in the RDPClient channel meaning
# something else entirely, and evtx_rdpOut.csv deliberately keeps it.
_SELF_EVENTS = {
    "evtx_security.csv": {"1102": "security log CLEARED",
                          "1100": "event log service shut down",
                          "4719": "system audit policy CHANGED"},
    "evtx_system.csv": {"104": "a log was CLEARED"},
}

# A one-day hole is a quiet Saturday on a workstation; two is a hole.
_GAP_MIN_DAYS = 2

# How much later than its siblings a channel must start before that is worth
# saying out loud rather than reading as the same window.
_LATE_START_DAYS = 7

_DAY = re.compile(r"^\d{4}-\d\d-\d\d")

_COLUMNS = ["channel", "kind", "first_event_utc", "last_event_utc", "span_days",
            "days_with_events", "event_count", "max_gap_days", "gap_start_utc",
            "gap_end_utc", "verdict", "suspicious"]

_FLOOR = ("floor only: this dump keeps selected event IDs, so its span is a "
          "minimum for the channel and its gaps are the filter's")

_ABSENT = ("channel not collected or not parsed: this host is silent here by "
           "absence, not by evidence")


class _Scan:
    """One CSV's answer: which days it saw, and the self-events it carried."""

    def __init__(self, label: str) -> None:
        self.channel = label
        self.days: set[date] = set()
        self.count = 0
        self.events: dict[str, list] = {}      # event id -> [count, first, last]

    @property
    def first(self) -> date | None:
        return min(self.days) if self.days else None

    @property
    def last(self) -> date | None:
        return max(self.days) if self.days else None


def _scan(path: Path, want: dict[str, str]) -> _Scan:
    """Read one EvtxECmd CSV: days seen, rows counted, watched event IDs kept.

    csv.reader over fixed column indexes rather than DictReader: a Security dump
    is routinely over a million rows, and this handler exists to be cheap enough
    that nobody turns it off.
    """
    scan = _Scan(path.stem)
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.reader(line.replace("\x00", "") for line in fh)
            header = next(reader, None)
            if not header:
                return scan
            idx = {name.strip(): i for i, name in enumerate(header)}
            ts_i, eid_i, ch_i = idx.get("TimeCreated"), idx.get("EventId"), idx.get("Channel")
            if ts_i is None:
                return scan
            for row in reader:
                if len(row) <= ts_i:
                    continue
                stamp = row[ts_i]
                if not _DAY.match(stamp):
                    continue
                try:
                    day = date.fromisoformat(stamp[:10])
                except ValueError:
                    continue
                scan.count += 1
                scan.days.add(day)
                if ch_i is not None and len(row) > ch_i and row[ch_i].strip():
                    scan.channel = row[ch_i].strip()
                if not want or eid_i is None or len(row) <= eid_i:
                    continue
                eid = row[eid_i].strip()
                if eid not in want:
                    continue
                hit = scan.events.setdefault(eid, [0, stamp, stamp])
                hit[0] += 1
                hit[1] = min(hit[1], stamp)
                hit[2] = max(hit[2], stamp)
    except (OSError, csv.Error):
        return scan
    return scan


def widest_gap(days: set[date]) -> tuple[int, date | None, date | None]:
    """Longest run of consecutive days with no event, strictly inside the span.

    Outside the span there is no gap, only an edge: a channel that stops on the
    day of collection has not gone silent, and one that starts late is a capacity
    question, answered separately.
    """
    ordered = sorted(days)
    best: tuple[int, date | None, date | None] = (0, None, None)
    for a, b in pairwise(ordered):
        missing = (b - a).days - 1
        if missing > best[0]:
            best = (missing, a + timedelta(days=1), b - timedelta(days=1))
    return best


def _logged_between(scan: _Scan, start: date, end: date) -> bool:
    return any(start <= d <= end for d in scan.days)


def _verdict(scan: _Scan, others: list[_Scan]) -> tuple[str, str, int, date | None, date | None]:
    """(verdict, suspicious, gap_days, gap_start, gap_end) for one full dump."""
    gap, g0, g1 = widest_gap(scan.days)
    if gap >= _GAP_MIN_DAYS and g0 and g1:
        awake = sorted(o.channel for o in others if _logged_between(o, g0, g1))
        if awake:
            return ((f"SILENT {gap}d while {len(awake)} other channel(s) logged: "
                     f"{', '.join(awake[:3])}"), "yes", gap, g0, g1)
        return (f"silent {gap}d, every channel dark (host off, or not collected)",
                "", gap, g0, g1)

    earliest = min((o.first for o in others if o.first), default=None)
    if scan.first and earliest and (scan.first - earliest).days >= _LATE_START_DAYS:
        return ((f"starts {(scan.first - earliest).days}d after the host's earliest "
                 f"event (rotated out, not missing)"), "", gap, g0, g1)
    return ("continuous", "", gap, g0, g1)


def _row(scan: _Scan, kind: str, verdict: str, suspicious: str = "",
         gap: int = 0, g0: date | None = None, g1: date | None = None) -> list:
    first, last = scan.first, scan.last
    span = (last - first).days + 1 if first and last else ""
    return [scan.channel, kind, first or "", last or "", span, len(scan.days),
            scan.count, gap or "", g0 or "", g1 or "", verdict, suspicious]


def run(ctx) -> None:
    logs = Path(ctx.evidence) / _EVENTLOGS
    present_full = [f for f in _FULL if (logs / f).is_file()]
    present_filtered = [f for f in _FILTERED if (logs / f).is_file()]
    if not present_full and not present_filtered:
        raise HandlerSkip("no parsed event log CSVs to measure")

    full = {f: _scan(logs / f, _SELF_EVENTS.get(f, {})) for f in present_full}
    with_days = [s for s in full.values() if s.days]

    rows: list[list] = []
    for scan in full.values():
        if not scan.days:
            rows.append(_row(scan, "full dump", "parsed, but no dated events"))
            continue
        others = [o for o in with_days if o is not scan]
        rows.append(_row(scan, "full dump", *_verdict(scan, others)))

    for fname in present_filtered:
        rows.append(_row(_scan(logs / fname, {}), "filtered dump", _FLOOR))

    for fname in _FULL:
        if fname not in full:
            label = fname.removeprefix("evtx_").removesuffix(".csv")
            rows.append([label, "absent", "", "", "", 0, 0, "", "", "", _ABSENT, ""])

    # The events that describe the logging itself. Their ABSENCE is a statement
    # too, so a row is written either way -- an analyst should not have to infer
    # "no 1102" from a table that simply does not mention it.
    for fname, watched in _SELF_EVENTS.items():
        scan = full.get(fname)
        if scan is None:
            continue
        for eid, meaning in watched.items():
            hit = scan.events.get(eid)
            if hit:
                rows.append([scan.channel, f"event {eid}", hit[1], hit[2], "", "",
                             hit[0], "", "", "", f"{meaning} ({hit[0]}x)", "yes"])
            else:
                rows.append([scan.channel, f"event {eid}", "", "", "", "", 0,
                             "", "", "", f"none found ({meaning})", ""])

    write_csv(ctx.out, "log_coverage.csv", _COLUMNS, rows)
