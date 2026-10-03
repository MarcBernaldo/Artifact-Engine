"""What this machine could have shown, on the front page: the window, and the copies.

The findings section says what was flagged. This says what could have been
flagged AT ALL -- and it is printed first, because the two are read together or
neither is read correctly. A channel that holds ten days cannot report an
intrusion from three weeks ago, and its silence is indistinguishable from a quiet
host unless somebody says so on the same page.

The measuring is done by the parsers (`log_coverage` on Windows, `log_integrity`
on Linux); this only reads the table back out of the consolidated database and
lays it out. A machine whose parser did not run has no table, and then there is
no section -- an absent measurement is not reported as full coverage.

The same page carries the other half of "what am I actually reading": the
collection's own copy of the disk (`collection_artifacts`). Those paths are
dropped from `aeng sweep` by default, so the report is where an analyst finds out
they exist at all -- and how many entries sit under them.

And the third half of it (v0.7.85): the endpoint-security products whose logs
arrived and were NOT read (`av_products`). Most of the products the acquisition
collects have no reader here, so the detections table alone would read as a
clean machine on a host running any of them. What was not read belongs on the
same page as what was -- and so does the difference between a product with no
reader (a gap) and one whose reader ran and found nothing (a lead).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# Windows: written by win_log_coverage. Linux: by lin_log_integrity, whose
# `rotations` rows answer the same question for /var/log.
_TABLES = ("log_coverage", "log_integrity")

# Order the channels the way an analyst reads them: what is wrong, then what
# limits the window, then the rest.
_KIND_ORDER = {"full dump": 0, "absent": 1, "filtered dump": 2}

_MAX_ROWS = 40


def _s(row: dict, key: str) -> str:
    """A row's value as text. Every column here arrives from SQLite, where an
    all-numeric CSV column comes back as an int and a missing one as None."""
    value = row.get(key)
    return "" if value is None else str(value)


def _rows(conn: sqlite3.Connection, table: str) -> list[dict]:
    cur = conn.execute(f'SELECT * FROM "{table}"')
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def read(db: Path) -> tuple[str, list[dict]]:
    """(table name, rows) from the first coverage table present, or ("", [])."""
    if not db.is_file():
        return "", []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error:
        return "", []
    try:
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        have = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for t in _TABLES:
            if t in have:
                try:
                    return t, _rows(conn, t)
                except sqlite3.Error:
                    return "", []
    finally:
        conn.close()
    return "", []


def _windows_lines(rows: list[dict]) -> list[str]:
    """One line per channel: the span, then the verdict that qualifies it."""
    def key(r: dict) -> tuple:
        return (_KIND_ORDER.get(_s(r, "kind"), 3),
                _s(r, "suspicious") != "yes", _s(r, "channel"))

    channels = [r for r in rows if _s(r, "kind") in _KIND_ORDER]
    events = [r for r in rows if _s(r, "kind").startswith("event ")]
    if not channels and not events:
        return []

    width = max((len(_s(r, "channel")) for r in channels), default=8)
    width = min(max(width, 8), 52)

    out = ["", "Log coverage (how far back this host's logging reaches):"]
    for r in sorted(channels, key=key)[:_MAX_ROWS]:
        first, last = _s(r, "first_event_utc"), _s(r, "last_event_utc")
        span = f"{first} .. {last}" if first and last else "-"
        total = _s(r, "span_days")
        seen = f"{_s(r, 'days_with_events')}/{total}d with events" if total else ""
        mark = "!" if _s(r, "suspicious") == "yes" else " "
        out.append(f"  {mark} {_s(r, 'channel')[:width]:<{width}}  "
                   f"{span:<25}  {seen}".rstrip())
        out.append(f"      {_s(r, 'verdict')}")
    if events:
        out.append("")
        for r in sorted(events, key=lambda e: _s(e, "kind")):
            mark = "!" if _s(r, "suspicious") == "yes" else " "
            out.append(f"  {mark} {_s(r, 'kind'):<10} {_s(r, 'channel'):<10} "
                       f"{_s(r, 'verdict')}".rstrip())
    return out


def _linux_lines(rows: list[dict]) -> list[str]:
    """The Linux table answers the same question in its `rotations` rows: how many
    archives /var/log kept, and the span they cover."""
    rot = [r for r in rows if _s(r, "status") == "rotations"]
    bad = [r for r in rows if _s(r, "suspicious") == "yes"]
    if not rot and not bad:
        return []
    out = ["", "Log coverage (how far back this host's logging reaches):"]
    width = max((len(_s(r, "artifact")) for r in rot + bad), default=8)
    width = min(max(width, 8), 40)
    for r in sorted(rot, key=lambda e: _s(e, "artifact"))[:_MAX_ROWS]:
        out.append(f"    {_s(r, 'artifact'):<{width}}  {_s(r, 'detail')}".rstrip())
    for r in sorted(bad, key=lambda e: _s(e, "artifact"))[:_MAX_ROWS]:
        out.append(f"  ! {_s(r, 'artifact'):<{width}}  "
                   f"{_s(r, 'status')}: {_s(r, 'detail')}".rstrip())
    return out


def render(table: str, rows: list[dict]) -> list[str]:
    """The report.txt section, or nothing when the machine has no such table."""
    if not rows:
        return []
    lines = _windows_lines(rows) if table == "log_coverage" else _linux_lines(rows)
    if not lines:
        return []
    lines.append("")
    lines.append("  A channel is only as good as the window it covers: silence outside")
    lines.append("  these ranges is absence of evidence, not evidence of absence.")
    return lines


# --------------------------------------------------------------------------- #
# The collection's own copy of the disk
# --------------------------------------------------------------------------- #
_COLLECTION_TABLE = "collection_artifacts"

_KIND_TEXT = {
    "mirrored_tree": "a copy of this machine, hidden from `aeng sweep` by default",
    "os_upgrade": "the previous install: real evidence, never hidden",
    "tool_dir": "an operator's tool directory: not hidden",
}


def _read_table(db: Path, table: str) -> list[dict]:
    """One table's rows, or [] when the database or the table is not there --
    which is what a parser that did not run looks like from here, and is not the
    same thing as a parser that ran and found nothing to say."""
    if not db.is_file():
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    try:
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        have = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if table not in have:
            return []
        return _rows(conn, table)
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def read_collection(db: Path) -> list[dict]:
    """The `collection_artifacts` rows, or [] when the parser did not run."""
    return _read_table(db, _COLLECTION_TABLE)


def render_collection(rows: list[dict]) -> list[str]:
    """The report.txt block. Printed only when there is something to say: unlike
    coverage, silence here means the machine was not collected onto itself, which
    is the ordinary case and needs no paragraph."""
    if not rows:
        return []
    out = ["", "Collection artifacts (paths that are copies, not host activity):"]
    for r in sorted(rows, key=lambda e: (_s(e, "kind"), _s(e, "path"))):
        kind = _s(r, "kind")
        mark = "-" if _s(r, "exclude") == "yes" else " "
        window = ""
        first, last = _s(r, "first_created_utc"), _s(r, "last_created_utc")
        if first and last:
            window = f"  written {first[:19]} .. {last[:19]}"
        out.append(f"  {mark} {_s(r, 'path')}  ({_s(r, 'entries')} entries){window}")
        out.append(f"      {_KIND_TEXT.get(kind, kind)}. {_s(r, 'evidence')}")
    out.append("")
    out.append("  Rows marked `-` are dropped from `aeng sweep`; it always reports how")
    out.append("  many it dropped, and `--include-collection` searches them anyway.")
    return out


_AV_TABLE = "av_products"

# Column width for the product name. A product whose name is longer is printed
# in full and pushes its own line right, rather than being cut: the name is the
# one thing on the line the analyst searches the acquisition for.
_AV_NAME = 28


def _i(row: dict, key: str) -> int:
    """A row's value as a count. SQLite hands an all-numeric CSV column back as
    an int and a column that was never written as None."""
    try:
        return int(row.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def read_av(db: Path) -> list[dict]:
    """The `av_products` rows, or [] when the parser did not run."""
    return _read_table(db, _AV_TABLE)


def render_av(rows: list[dict]) -> list[str]:
    """The report.txt block: every endpoint-security product found on this
    machine, and how much of it was read.

    One line per PRODUCT, not per path: a product keeps its logs in up to nine
    directories and nine lines of the same answer is not a front page. The
    per-path counts stay in `av_products.csv`.

    THREE OUTCOMES, KEPT APART. `!` is a gap: no reader exists for that product,
    and nothing above came from it. `?` is a lead: a reader ran over its files
    and produced no row, which is either a clean product or a layout the reader
    does not know -- and reporting that as "no reader" is what stops anyone
    looking at the reader. An unmarked line was read. A product directory that
    exists and is empty says so, rather than being described as files sitting in
    the acquisition.

    Printed whenever there is a product at all, including when everything was
    read -- unlike the collection block, silence here would be ambiguous between
    "no endpoint product on this host" and "the parser did not run", and those
    two lead an analyst to opposite conclusions."""
    if not rows:
        return []
    agg: dict[str, dict] = {}
    for r in rows:
        a = agg.setdefault(_s(r, "product"), {
            "paths": 0, "files": 0, "read": 0, "rows": 0, "raw": 0,
            "reader": False, "first": "", "last": ""})
        a["paths"] += 1
        a["files"] += _i(r, "files")
        a["read"] += _i(r, "files_read")
        a["rows"] += _i(r, "rows")
        a["raw"] += _i(r, "raw_only")
        a["reader"] = a["reader"] or bool(_s(r, "reader"))
        first, last = _s(r, "first_modified_utc"), _s(r, "last_modified_utc")
        if first and (not a["first"] or first < a["first"]):
            a["first"] = first
        if last and last > a["last"]:
            a["last"] = last
    out = ["", "Endpoint-security products on this machine:"]
    marks: dict[str, int] = {"!": 0, "?": 0}
    for name in sorted(agg):
        a = agg[name]
        if a["rows"]:
            mark = " "
            said = f"{a['rows']} detection(s) read"
            if a["raw"]:
                said += f" ({a['raw']} line(s) the reader could not decompose)"
        elif not a["files"]:
            mark = " "
            said = "present, no files in it"
        elif not a["reader"]:
            mark = "!"
            said = "no reader: nothing above came from these"
        else:
            mark = "?"
            said = "a reader ran over these and produced no row"
        marks[mark] = marks.get(mark, 0) + 1
        window = (f"  {a['first'][:19]} .. {a['last'][:19]}"
                  if a["first"] and a["last"] else "")
        out.append(f"  {mark} {name:<{_AV_NAME}} {a['paths']} path(s), "
                   f"{a['files']:>5} file(s), {a['read']} read   {said}{window}")
    out.append("")
    if marks["!"]:
        out.append(f"  `!` -- this engine has no reader for that product"
                   f" ({marks['!']} of {len(agg)} found here). The files ARE in the")
        out.append("  acquisition, at the paths in av_products.csv, and nothing above was")
        out.append("  parsed from them: read them with the vendor's own tooling.")
    if marks["?"]:
        out.append(f"  `?` -- a reader DID run and found nothing"
                   f" ({marks['?']} product(s)): either the product logged no")
        out.append("  detection, or it logged one in a layout this reader does not know.")
        out.append("  Worth half a minute in the files themselves before believing it.")
    if not marks["!"] and not marks["?"]:
        out.append("  Every product found here was read. The per-path counts, and the files")
        out.append("  each reader did not open, are in av_products.csv.")
    out.append("  Windows Defender is not in this list: it has parsers of its own.")
    return out
