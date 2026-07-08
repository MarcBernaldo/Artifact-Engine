"""Handler: FortiGate/FortiOS logs from a loose drop. Output: fortigate.csv

Counterpart of the web-logs drop for firewall exports: FortiOS key=value logs
(traffic / event / utm) become one queryable timeline. Two on-disk shapes are
accepted transparently:

  - raw syslog:   date=... time=... logid="..." key="value" ...
  - FortiAnalyzer CSV export: one record per line, each field a CSV cell of the
    form key=value, string values wrapped in doubled quotes, no header row.

Every record is surfaced; `flag` marks what the analyst reads first:

  utm_<subtype>       the firewall itself detected/blocked something (virus,
                      ips, webfilter, anomaly, dlp, ssl, ssh, cifs, app-ctrl)
                      - only blocked/dropped actions or high/critical risk
  admin_login[_failed]  administrator logons to the FortiGate (method+source)
  auth_failed         failed user authentication through the firewall
  sslvpn_session      FortiClient SSL-VPN sessions opened/closed (user + IP)

Timestamps: `time_utc` from `eventtime` (epoch; ns/us/ms/s depending on the
FortiOS version), `time_local` from the device-local date/time fields.
Self-gates to loose drops (no `[root]/` in the evidence) and probes each file's
first line for the FortiOS shape, so arbitrary export names are fine and web
logs sharing the case are never mis-parsed. Streaming (multi-GB safe); glued
records (missing newline between two `date=` records) are split apart.
"""

from __future__ import annotations

import csv
import re
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import iter_log_lines
from artifact_engine.handlers._webcommon import iter_access_files

_KV = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
# A record starts at date=YYYY-..; used to split records glued on one line.
_RECORD_SPLIT = re.compile(r"(?=\bdate=\d{4}-\d{2}-\d{2}\b)")
# Probe: raw syslog starts `date=YYYY-..`; the FortiAnalyzer CSV export starts
# with a quoted `"itime=` / `"date=` cell. Either way a real record has logid=.
_PROBE_RAW = re.compile(r"^\s*date=\d{4}-\d{2}-\d{2}\s")
_PROBE_CSV = re.compile(r'^\s*"(?:itime|date)=')

_HEADER = ["time_utc", "time_local", "flag", "type", "subtype", "level", "action",
           "srcip", "srcport", "dstip", "dstport", "service", "user", "country",
           "detail"]

_UTM_ACTIONS = {"blocked", "dropped", "clear_session", "reset"}
_CRLEVELS = {"high", "critical"}


def _epoch_utc(raw: str) -> str:
    """eventtime -> 'YYYY-mm-dd HH:MM:SS' UTC. FortiOS logs seconds, ms, us or ns
    depending on version; disambiguate by digit count."""
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return ""
    n = len(str(abs(v)))
    if n >= 18:
        v //= 1_000_000_000
    elif n >= 15:
        v //= 1_000_000
    elif n >= 12:
        v //= 1_000
    try:
        return datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def _flag(r: dict) -> str:
    typ, sub = r.get("type", ""), r.get("subtype", "")
    action, status = r.get("action", ""), r.get("status", "")
    if typ == "utm":
        if action in _UTM_ACTIONS or r.get("crlevel", "") in _CRLEVELS \
                or r.get("level", "") == "alert":
            return f"utm_{sub or 'other'}"
        return ""
    if typ == "event":
        desc = r.get("logdesc", "")
        if desc.startswith("Admin login"):
            return "admin_login" if status == "success" else "admin_login_failed"
        if sub == "user" and r.get("action") == "authentication" and status != "success":
            return "auth_failed"
        if sub == "endpoint" and r.get("connection_type") == "sslvpn":
            return "sslvpn_session"
    return ""


def _detail(r: dict) -> str:
    parts = []
    for key in ("attack", "virus", "filename", "hostname", "url", "app", "qname",
                "ui", "vpntunnel", "logdesc", "msg"):
        v = r.get(key, "")
        if v and v not in parts:
            parts.append(v)
    return " | ".join(parts)[:300]


def _row(r: dict) -> list:
    return [
        _epoch_utc(r.get("eventtime", "")),
        (r.get("date", "") + " " + r.get("time", "")).strip(),
        _flag(r),
        r.get("type", ""), r.get("subtype", ""), r.get("level", ""),
        r.get("action", ""),
        r.get("srcip", ""), r.get("srcport", ""),
        r.get("dstip", ""), r.get("dstport", ""),
        r.get("service", ""),
        r.get("user", "") or r.get("xauthuser", ""),
        r.get("dstcountry", ""),
        _detail(r),
    ]


def _csv_record(line: str) -> dict | None:
    """One FortiAnalyzer CSV-export record -> key=value dict, or None.

    The line is a CSV row; each cell is `key=value`, string values keep the
    inner quotes (`srcip="1.2.3.4"`) which csv leaves after un-doubling, so they
    are stripped. Uses the csv module for correct handling of the doubled-quote
    escaping and any commas inside quoted values."""
    try:
        cells = next(csv.reader([line]))
    except (csv.Error, StopIteration):
        return None
    rec: dict[str, str] = {}
    for cell in cells:
        if not cell:
            continue
        k, sep, v = cell.partition("=")
        if sep:
            rec[k.strip()] = v.strip().strip('"')
    return rec if ("date" in rec and "logid" in rec) else None


def _records(line: str):
    """key=value dicts in a physical line, for either on-disk shape."""
    if line.lstrip().startswith('"'):          # FortiAnalyzer CSV export
        rec = _csv_record(line)
        if rec:
            yield rec
        return
    for chunk in _RECORD_SPLIT.split(line):    # raw syslog (split glued records)
        if not chunk.strip():
            continue
        rec = {m.group(1): m.group(2) if m.group(2) is not None else m.group(3)
               for m in _KV.finditer(chunk)}
        if "date" in rec and "logid" in rec:
            yield rec


def _is_fortigate(path: Path) -> bool:
    """Probe: the first non-empty line must look like a FortiOS record (raw
    syslog or FortiAnalyzer CSV export)."""
    try:
        for line in iter_log_lines(path):
            if line.strip():
                return "logid=" in line and bool(
                    _PROBE_RAW.match(line) or _PROBE_CSV.match(line))
    except Exception:  # noqa: BLE001 - unreadable/binary file
        return False
    return False


def run(ctx) -> None:
    evidence = Path(ctx.evidence)
    if (evidence / "[root]").is_dir():
        raise HandlerSkip("acquisition layout (loose-drop parser)")

    # clf_only=False: FortiOS key=value lines are not CLF; _is_fortigate is the
    # format probe here (the binary sniff still applies). csv_ok=True: the
    # FortiAnalyzer export is a .csv (kept out of the fallback's skip list).
    files = [f for f in iter_access_files(evidence, clf_only=False, csv_ok=True)
             if _is_fortigate(f)]
    if not files:
        raise HandlerSkip("no FortiOS-format logs")

    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "fortigate.csv"
    rows = 0
    with out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(_HEADER)
        for f in files:
            for line in iter_log_lines(f):
                for rec in _records(line):
                    w.writerow(_row(rec))
                    rows += 1
    if not rows:
        out.unlink(missing_ok=True)
