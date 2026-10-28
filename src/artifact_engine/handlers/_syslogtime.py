"""UTC for syslog timestamps, which classic syslog writes without year or zone.

`Aug  9 14:03:11` is host-local and yearless, so an art_log_auth.csv built from it could
not be laid next to wtmp, the bodyfile or the journal, which are all UTC. Two
things are needed to fix a line in time, and both are in the acquisition:

ZONE -- `/etc/timezone` (Debian), the `Time zone:` line of UAC's
`timedatectl status`, or `TIMEZONE=`/`ZONE=` in `/etc/sysconfig/clock` (SUSE,
old RHEL; `DEFAULT_TIMEZONE` there is the hardware clock's, not the system's).
An IANA name, so daylight saving is applied per line. No zone found, no UTC:
the column stays empty rather than guessing.

YEAR -- the newest moment the file can hold: the date in a dateext archive's name
(`secure-20260920`: rotated that day), otherwise when the acquisition ran (the
first line of UAC's own `uac.log`, written with its offset). A line whose
month/day falls after that moment is from the year before. That holds for any
file spanning less than a year, which is what logrotate keeps per file.

RFC 3339 timestamps (rsyslog's high-precision format, the journal) carry their
own offset and are only converted.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from artifact_engine.handlers._lincommon import live_response, read_lines, read_text, root

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
_LEGACY = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)$")
_TIMEDATECTL = re.compile(r"Time zone:\s*([A-Za-z0-9_+\-/]+)")
_CLOCK = re.compile(r'^(?:TIMEZONE|ZONE)\s*=\s*"?([A-Za-z0-9_+\-/]+)"?')
_UAC_START = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) ([+-]\d{4})\b")
_DATEEXT = re.compile(r"-(\d{8})(?:\.[a-z0-9]+)?$")
_FMT = "%Y-%m-%d %H:%M:%S"


def host_zone(evidence: Path) -> ZoneInfo | None:
    """The host's IANA zone, or None when the acquisition does not say."""
    base = root(evidence)
    names = [read_text(base / "etc" / "timezone").strip()]
    lr = live_response(evidence)
    if lr:
        m = _TIMEDATECTL.search(read_text(lr / "system" / "timedatectl_status.txt"))
        names.append(m.group(1) if m else "")
    for line in read_lines(base / "etc" / "sysconfig" / "clock"):
        m = _CLOCK.match(line.strip())
        if m:
            names.append(m.group(1))
            break
    for name in names:
        if not name:
            continue
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError):
            continue
    return None


def acquired_at(evidence: Path, zone: ZoneInfo) -> datetime | None:
    """When the acquisition ran, in the host's zone."""
    for line in read_lines(Path(evidence) / "uac.log")[:3]:
        m = _UAC_START.match(line)
        if m:
            when = datetime.strptime(f"{m.group(1)} {m.group(2)}", f"{_FMT} %z")
            return when.astimezone(zone)
    return None


def newest_in(path: Path, acquired: datetime | None, zone: ZoneInfo) -> datetime | None:
    """The latest time a log file can hold: the end of its dateext rotation day,
    else the acquisition."""
    m = _DATEEXT.search(path.name)
    if m:
        try:
            day = datetime.strptime(m.group(1) + "+0000", "%Y%m%d%z")
        except ValueError:
            return acquired
        return day.replace(tzinfo=zone) + timedelta(days=1)
    return acquired


class Clock:
    """Turns a syslog timestamp from one host into UTC text."""

    def __init__(self, evidence: Path):
        self.zone = host_zone(Path(evidence))
        self.acquired = acquired_at(Path(evidence), self.zone) if self.zone else None

    def bound(self, path: Path | None) -> datetime | None:
        if path is None or self.zone is None:
            return self.acquired
        return newest_in(path, self.acquired, self.zone)

    def utc(self, ts: str, bound: datetime | None) -> str:
        return _to_utc(ts, self.zone, bound)


@lru_cache(maxsize=1 << 16)
def _to_utc(ts: str, zone: ZoneInfo | None, bound: datetime | None) -> str:
    ts = ts.strip()
    if ts[:4].isdigit():                               # RFC 3339: carries its offset
        try:
            d = datetime.fromisoformat(ts)
        except ValueError:
            return ""
        if d.tzinfo is None:
            if zone is None:
                return ""
            d = d.replace(tzinfo=zone)
        return d.astimezone(timezone.utc).strftime(_FMT)
    m = _LEGACY.match(ts)
    if not m or zone is None or bound is None:
        return ""
    month = _MONTHS.get(m.group(1))
    if month is None:
        return ""
    day, hh, mm, ss = (int(g) for g in m.groups()[1:])
    for year in (bound.year, bound.year - 1, bound.year - 2):
        try:
            local = datetime(year, month, day, hh, mm, ss, tzinfo=zone)
        except ValueError:                             # Feb 29 outside a leap year
            continue
        if local <= bound:
            return local.astimezone(timezone.utc).strftime(_FMT)
    return ""
