"""case.html: the way into a case, one self-contained page at its root (AE-048).

`run-summary` counts parsers; it does not say which of many hosts to open first.
This page does: every host with its findings per level, most severe first, the
span of its dated events, and links to its `report.txt` and `.db`; under it, each
host's most severe findings. It is read from case.db (core/casedb.py), so it says
what the machine databases say and nothing else.

No script, no external file, no network: it opens from a USB stick on an air-gapped
machine like the lateral and web pages. Every value is escaped.
"""

from __future__ import annotations

import html
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from artifact_engine.core import casedb
from artifact_engine.logging_setup import get_logger

log = get_logger()

CASE_PAGE = "case.html"

# Findings listed under each host; the rest are in case.db and the host's report.
TOP_PER_HOST = 15

_CSS = """
body{font:14px/1.45 system-ui,Segoe UI,sans-serif;margin:24px;color:#1b1f24;background:#fff}
h1{font-size:20px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 6px}
.muted{color:#5b6470} table{border-collapse:collapse;margin:8px 0;width:100%}
th,td{border-bottom:1px solid #e3e6ea;padding:4px 8px;text-align:left;vertical-align:top}
th{background:#f5f7f9;font-weight:600} td.n{text-align:right;font-variant-numeric:tabular-nums}
.critical{color:#fff;background:#8e1b1b} .high{color:#fff;background:#c2410c}
.medium{background:#fde68a} .low{background:#e0f2fe} .flagged{background:#ede9fe}
span.lv{padding:1px 6px;border-radius:3px;font-size:12px}
td.sum{font-family:Consolas,monospace;font-size:12px;word-break:break-all}
@media (prefers-color-scheme:dark){body{background:#111418;color:#e6e8eb}
th{background:#1c2128} th,td{border-color:#2b323b} .muted{color:#9aa4ae}
.medium{color:#111} .low{color:#111} .flagged{color:#111}}
"""


def _e(value) -> str:
    return html.escape("" if value is None else str(value))


def _link(root: Path, rel: str | None, text: str) -> str:
    """A link to a file under the case root, percent-encoded: a `#`, `%` or `?` in a
    folder name read raw sent the browser elsewhere. A path that is not under the
    root (casedb keeps it absolute) gets no link: `D:/...` reads as a URL scheme."""
    if not rel or Path(rel).is_absolute() or ".." in Path(rel).parts:
        return ""
    if not (root / rel).exists():
        return ""
    return f'<a href="{_e(quote(Path(rel).as_posix()))}">{_e(text)}</a>'


def _anchor(host) -> str:
    return "h-" + quote(str(host), safe="")


def _report_of(db_rel: str | None) -> str | None:
    """The report.txt beside a host's .db, relative to the root."""
    if not db_rel:
        return None
    return (Path(db_rel).parent / "report.txt").as_posix()


def _top_findings(case_db: Path, host: str, limit: int) -> list[tuple]:
    try:
        conn = sqlite3.connect(casedb._ro(case_db), uri=True)
    except sqlite3.Error:
        return []
    try:
        return conn.execute("SELECT level, rule, timestamp, source_table, summary FROM alerts "
                            "WHERE host = ? ORDER BY priority, timestamp LIMIT ?",
                            (host, limit)).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def render(root: Path, case_db: Path, hosts: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = {lv: sum(int(h.get(lv) or 0) for h in hosts) for lv in casedb.LEVELS}
    out = ["<!doctype html><html lang=en><head><meta charset=utf-8>",
           "<meta name=viewport content='width=device-width,initial-scale=1'>",
           f"<title>Case: {_e(root.name)}</title><style>{_CSS}</style></head><body>",
           f"<h1>Case {_e(root.name)}</h1>",
           f"<p class=muted>{len(hosts)} host(s) | "
           + " | ".join(f"{lv} {total[lv]}" for lv in casedb.LEVELS)
           + f" | generated {now} from {casedb.CASE_DB}</p>",
           "<h2>Hosts, most severe first</h2><table><tr><th>Host</th>"
           + "".join(f"<th>{lv}</th>" for lv in casedb.LEVELS)
           + "<th>Dated events (UTC)</th><th>Open</th></tr>"]
    for h in hosts:
        span = (f"{_e(h.get('first_time_utc'))} .. {_e(h.get('last_time_utc'))}"
                if h.get("first_time_utc") else "-")
        if h.get("status") != "ok":
            span += f" <span class=muted>({_e(h.get('status'))})</span>"
        links = " ".join(x for x in (_link(root, _report_of(h.get("db")), "report.txt"),
                                     _link(root, h.get("db"), ".db")) if x)
        out.append(f"<tr><td><a href='#{_e(_anchor(h['host']))}'>{_e(h['host'])}</a></td>"
                   + "".join(f"<td class=n>{int(h.get(lv) or 0) or ''}</td>"
                             for lv in casedb.LEVELS)
                   + f"<td>{span}</td><td>{links}</td></tr>")
    out.append("</table>")
    for h in hosts:
        rows = _top_findings(case_db, h["host"], TOP_PER_HOST)
        count = sum(int(h.get(lv) or 0) for lv in casedb.LEVELS)
        out.append(f"<h2 id='{_e(_anchor(h['host']))}'>{_e(h['host'])}</h2>")
        if h.get("status") != "ok":
            # Its findings are unknown, not none: a .db this run did not build, or
            # could not read. Said where the host's findings would be.
            out.append(f"<p><strong>Not read:</strong> {_e(h.get('status'))}. Its findings "
                       "are not counted above; open its report.txt and .db.</p>")
            continue
        if not rows:
            out.append("<p class=muted>No findings.</p>")
            continue
        more = (f" <span class=muted>(the {len(rows)} most severe of {count}; the rest are in "
                f"{casedb.CASE_DB} and the host's report.txt)</span>") if count > len(rows) else ""
        out.append(f"<p>{more}</p><table><tr><th>Level</th><th>Rule</th><th>When</th>"
                   "<th>Table</th><th>Summary</th></tr>")
        for level, rule, when, table, summary in rows:
            out.append(f"<tr><td><span class='lv {_e(level)}'>{_e(level)}</span></td>"
                       f"<td>{_e(rule)}</td><td>{_e(when)}</td><td>{_e(table)}</td>"
                       f"<td class=sum>{_e(summary)}</td></tr>")
        out.append("</table>")
    out.append("</body></html>")
    return "\n".join(out)


def write(root: Path, case_db: Path | None, hosts: list[dict]) -> Path | None:
    """Write `<root>/case.html`; None (and a warning) when it cannot be written.

    With no case.db or no host to show, a page an earlier run left is removed: kept,
    it would show that run's counts as this one's, beside a run-summary saying
    otherwise."""
    root = Path(root)
    final, tmp = root / CASE_PAGE, root / (CASE_PAGE + ".tmp")
    if case_db is None or not hosts:
        if final.exists():
            try:
                final.unlink()
                log.warning(f"[!] {CASE_PAGE} of an earlier run removed: this run has no "
                            f"{casedb.CASE_DB} to build one from")
            except OSError as e:
                log.warning(f"[!] {CASE_PAGE} is an earlier run's and could not be "
                            f"removed: {type(e).__name__}: {e}")
        return None
    try:
        tmp.write_text(render(root, case_db, hosts), encoding="utf-8")
        os.replace(tmp, final)
    except OSError as e:
        log.warning(f"[!] {CASE_PAGE} not written: {type(e).__name__}: {e}")
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    return final
