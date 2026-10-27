"""Handler: how far back Linux logging actually reaches. Output: log_coverage.csv

The Linux twin of `win_log_coverage`, and the same question: a host holding a
week of auth.log has nothing to say about last month, and its silence reads
exactly like a quiet host. `log_integrity` counts the rotations /var/log kept;
this measures what the PARSED tables span -- the window an analyst actually
searched -- per log, with the widest interior gap and the same verdicts.

Nothing new is extracted. Every question is a `time_utc` away in a CSV another
parser has already written.

TWO KINDS OF LOG. syslog, auth, audit and cron write all day on any running
host, so a hole inside their span means something, and the Windows rule applies:
dark while a sibling kept logging is flagged, dark with everyone is a host that
was off. wtmp, btmp, sudo and the web access log record EVENTS -- a day without
a login, a failed login or a request is an ordinary day -- so they are measured
(first, last, days with events) and never gap-analysed.

The two logs every Linux host writes, syslog and auth, are named when absent:
"not parsed" is a statement about the window, and leaving the row out would
read as nothing to say.
"""

from __future__ import annotations

import csv
from datetime import date, datetime, timezone
from functools import lru_cache
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_log_coverage import (
    _ABSENT,
    _COLUMNS,
    _GAP_MIN_DAYS,
    _row,
    _Scan,
    _verdict,
    widest_gap,
)

_CSVS = Path("CSVs")

# (label, CSV under CSVs/, time column, filter column, filter value). One CSV can
# hold two logs: logins.csv carries wtmp and btmp rows apart by `source`.
_CONTINUOUS = (
    ("syslog", "EventLogs/syslog.csv", "time_utc", None, None),
    ("auth", "EventLogs/auth_log.csv", "time_utc", None, None),
    ("audit", "EventLogs/auditd_events.csv", "time_utc", None, None),
    ("cron", "EventLogs/cron_log.csv", "time_utc", None, None),
)
_SPARSE = (
    ("wtmp", "EventLogs/logins.csv", "time_utc", "source", "wtmp"),
    ("btmp", "EventLogs/logins.csv", "time_utc", "source", "btmp"),
    ("sudo", "EventLogs/sudo_log.csv", "time_utc", None, None),
    # Written with its offset in the value (`2026-05-18 10:00:00 +0200`), so
    # the day is taken after converting to UTC like every other row here.
    ("web access", "Web/web_access.csv", "time", None, None),
)
_ALWAYS = ("syslog", "auth")

_SPARSE_VERDICT = ("event log: span only -- a day with no event here is an ordinary "
                   "day, so its gaps are not read")


@lru_cache(maxsize=1 << 16)
def _utc_day(minute: str, offset: str) -> date | None:
    """The UTC day of `YYYY-MM-DD HH:MM` at `offset`. Cached on the minute: a
    web log is millions of rows over a few thousand distinct minutes, and
    parsing each row was most of a 170 s run."""
    try:
        return datetime.strptime(f"{minute} {offset}", "%Y-%m-%d %H:%M %z") \
            .astimezone(timezone.utc).date()
    except ValueError:
        return None


def _day(stamp: str) -> date | None:
    """The UTC day of a time value: `YYYY-MM-DD ...` as written, or converted
    first when the value carries its own offset."""
    stamp = stamp.strip()
    if len(stamp) < 10:
        return None
    if len(stamp) > 19 and stamp[19:20] == " " and stamp[20:21] in "+-":
        return _utc_day(stamp[:16], stamp[20:25])
    try:
        return date.fromisoformat(stamp[:10])
    except ValueError:
        return None


def _scan(path: Path, label: str, col: str, where: str | None, value: str | None) -> _Scan:
    """Days seen and rows counted in one parsed CSV (or one `source` of it).

    csv.reader over located indexes rather than DictReader: auth_log runs to
    hundreds of thousands of rows on a busy host, and this parser exists to be
    cheap enough that nobody turns it off."""
    scan = _Scan(label)
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.reader(fh)
            header = next(reader, None) or []
            if col not in header:
                return scan
            ti = header.index(col)
            wi = header.index(where) if where and where in header else None
            if where and wi is None:
                return scan
            for row in reader:
                if len(row) <= ti or (wi is not None and (len(row) <= wi or row[wi] != value)):
                    continue
                day = _day(row[ti])
                if day is None:
                    continue
                scan.count += 1
                scan.days.add(day)
    except (OSError, csv.Error):
        return scan
    return scan


def _linux_verdict(scan: _Scan, others: list[_Scan]) -> tuple:
    """The Windows verdict, with one Linux correction. An event channel is one
    circular file; /var/log is rotations, and a host keeps its last weeks plus
    the odd archive from long ago. Measured on real hosts, that read as auth
    "SILENT 331d" while syslog logged -- on a handful of those days, from an old
    archive. A hole counts only when a sibling wrote on at least half its days."""
    gap, g0, g1 = widest_gap(scan.days)
    if gap >= _GAP_MIN_DAYS and g0 and g1:
        awake = {o.channel: sum(1 for d in o.days if g0 <= d <= g1) for o in others}
        busy = sorted(c for c, k in awake.items() if k * 2 >= gap)
        if busy:
            return ((f"SILENT {gap}d while {len(busy)} other log(s) kept writing: "
                     f"{', '.join(busy[:3])}"), "yes", gap, g0, g1)
        most = max(awake.values(), default=0)
        if most:
            return ((f"silent {gap}d; the other logs wrote on {most} of those days at "
                     f"most (archives kept apart, not a hole)"), "", gap, g0, g1)
    return _verdict(scan, others)


def run(ctx) -> None:
    base = Path(ctx.evidence) / _CSVS
    present = [s for s in _CONTINUOUS + _SPARSE if (base / s[1]).is_file()]
    if not present:
        raise HandlerSkip("no parsed Linux log CSVs to measure")

    scans = {s[0]: _scan(base / s[1], s[0], *s[2:]) for s in present}
    continuous = [scans[s[0]] for s in _CONTINUOUS if s[0] in scans]
    with_days = [s for s in continuous if s.days]

    rows: list[list] = []
    for scan in continuous:
        if not scan.days:
            rows.append(_row(scan, "full dump", "parsed, but no dated events"))
            continue
        others = [o for o in with_days if o is not scan]
        rows.append(_row(scan, "full dump", *_linux_verdict(scan, others)))
    for label, *_ in _SPARSE:
        scan = scans.get(label)
        if scan is not None and scan.days:
            rows.append(_row(scan, "event log", _SPARSE_VERDICT))
    for label in _ALWAYS:
        if label not in scans:
            rows.append([label, "absent", "", "", "", 0, 0, "", "", "", _ABSENT, ""])

    write_csv(ctx.out, "log_coverage.csv", _COLUMNS, rows)
