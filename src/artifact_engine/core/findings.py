r"""The rows this run flagged, on the front page instead of inside a dump.

Ninety-seven parsers write a `suspicious` column by convention and, until now,
nothing read it. `report.txt` said which parsers RAN; what they FOUND lived in
one to two thousand rows of `.db` per table, reachable only by writing SQL. Every
high-value finding recovered from a real case so far was recovered by hand from
there, which means the tool did the work and then hid it.

This reads the machine's consolidated `.db` -- already built by the time the
report is written -- and puts the flagged rows in front of the reader.

RANKING, WITHOUT AN INVENTED SEVERITY SCALE. Ordering by count puts whichever
table flags most rows on top, which is exactly the table worth reading last.
So tables are ranked by FLAG RATE, ascending: three flagged rows out of three
thousand is a selective signal, twelve hundred out of fifteen hundred is a rule
that fires on the ordinary case. The rarer the flag, the higher it sits. Nothing
here needs configuring, and nothing here invents a severity the parsers did not
claim -- the parsers said `yes`, and only the ordering is this module's opinion.

WHAT IT DOES NOT COVER, STATED. Only some tables carry the column at all: the
external-tool outputs (MFT, EvtxECmd channels, hayabusa) have their own schemas
and no such convention. A findings section built on the flag alone therefore
covers a minority of the evidence, and one that did not say so would be a false
front page -- an analyst reading a short list would take it for a short case.
So the tables with no flag column are counted and named, every run.
"""

from __future__ import annotations

import csv
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from artifact_engine.logging_setup import get_logger

log = get_logger()

FINDINGS_CSV = "findings.csv"

# The column every handler is meant to write (ARCHITECTURE §5: `yes` or empty,
# never `no`).
_FLAG = "suspicious"

# Rows shown per table in report.txt. The report is a front page, not the data:
# past a handful the reader should be in the .db, and the pointer to it is on
# every row.
_SAMPLES = 5

# Rows per table carried into findings.csv. Bounded for the same reason every
# aggregate here is bounded -- a spray-driven table's row count is the attacker's
# to choose -- and a truncated table is named in the report rather than trimmed
# quietly.
_CSV_CAP = 500

# Values joined into a row's one-line summary, and how long that line may get.
_SUMMARY_COLS = 4
_SUMMARY_CHARS = 160


@dataclass
class TableFindings:
    table: str
    flagged: int
    total: int
    rows: list[tuple[int, str]] = field(default_factory=list)   # (rowid, summary)
    truncated: bool = False

    @property
    def rate(self) -> float:
        """Share of the table's rows that carry the flag. The ranking key."""
        return self.flagged / self.total if self.total else 0.0


@dataclass
class Findings:
    tables: list[TableFindings] = field(default_factory=list)
    unflagged: list[str] = field(default_factory=list)   # no `suspicious` column
    unreadable: str = ""                                 # why the .db gave nothing

    @property
    def flagged(self) -> int:
        return sum(t.flagged for t in self.tables)

    @property
    def covered(self) -> int:
        """Tables that carry the flag column, whether or not anything is flagged."""
        return len(self.tables)


def _q(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _summary(cols: list[str], row: tuple) -> str:
    """A one-line rendering of a flagged row: the first few values that are not
    empty, in column order. Enough to recognise the row; the rowid is what takes
    the reader to the rest of it."""
    parts = []
    for col, value in zip(cols, row):
        if col.lower() == _FLAG or value in (None, ""):
            continue
        parts.append(str(value).replace("\n", " ").strip())
        if len(parts) >= _SUMMARY_COLS:
            break
    return " | ".join(parts)[:_SUMMARY_CHARS]


def _table_findings(conn: sqlite3.Connection, table: str) -> TableFindings | None:
    """One table's flagged rows, or None when it carries no flag column."""
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({_q(table)})")]
    flag = next((c for c in cols if c.lower() == _FLAG), None)
    if flag is None:
        return None

    total = conn.execute(f"SELECT COUNT(*) FROM {_q(table)}").fetchone()[0]
    # TRIM + CAST because the convention is "yes or EMPTY", and a column that
    # arrived through a CSV can hold a stray space as easily as a value.
    where = f"TRIM(COALESCE(CAST({_q(flag)} AS TEXT), '')) <> ''"
    flagged = conn.execute(f"SELECT COUNT(*) FROM {_q(table)} WHERE {where}").fetchone()[0]
    out = TableFindings(table=table, flagged=flagged, total=total)
    if not flagged:
        return out

    select = ", ".join(_q(c) for c in cols)
    rows = conn.execute(
        f"SELECT rowid, {select} FROM {_q(table)} WHERE {where} LIMIT {_CSV_CAP}")
    out.rows = [(r[0], _summary(cols, r[1:])) for r in rows]
    out.truncated = flagged > _CSV_CAP
    return out


def collect(db: Path) -> Findings:
    """Every flagged row in a machine's consolidated database, ranked."""
    result = Findings()
    if not db.is_file():
        result.unreadable = "no consolidated database"
        return result
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error as e:
        result.unreadable = f"{type(e).__name__}: {e}"
        return result
    try:
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for t in tables:
            try:
                tf = _table_findings(conn, t)
            except sqlite3.Error as e:
                # One unreadable table is not an unreadable machine, but it is
                # also not a table with nothing in it: name it among the ones
                # this section does not speak for.
                log.debug(f"findings: {db.name}:{t}: {e}")
                result.unflagged.append(t)
                continue
            if tf is None:
                result.unflagged.append(t)
            else:
                result.tables.append(tf)
    except sqlite3.Error as e:
        result.unreadable = f"{type(e).__name__}: {e}"
    finally:
        conn.close()

    # Ascending flag rate: the most selective signal first. Ties break on the
    # smaller absolute count, then the name, so the order is stable across runs.
    result.tables.sort(key=lambda t: (t.rate, t.flagged, t.table))
    return result


def render(f: Findings, case_hint: str = "") -> list[str]:
    """The report.txt section. Printed on every run, including a clean one: an
    absent section and a section saying nothing was flagged are read very
    differently months later."""
    lines = ["", "Findings (rows the parsers flagged):"]
    if f.unreadable:
        lines.append(f"  NOT AVAILABLE - {f.unreadable}")
        return lines

    with_hits = [t for t in f.tables if t.flagged]
    lines.append(f"  {f.flagged} flagged row(s) in {len(with_hits)} of "
                 f"{f.covered} table(s) that carry the flag.")
    if f.unflagged:
        lines.append(f"  {len(f.unflagged)} table(s) have no `{_FLAG}` column and are "
                     f"NOT covered by this section:")
        lines.append(f"    {', '.join(f.unflagged)}")
    lines.append("")

    if not with_hits:
        lines.append("  Nothing flagged. That is a statement about the flags the")
        lines.append("  parsers set, not about the tables listed above as uncovered.")
    for t in with_hits:
        pct = f"{t.rate * 100:.1f}%"
        note = f"  [csv truncated at {_CSV_CAP}]" if t.truncated else ""
        lines.append(f"  {t.table}: {t.flagged} of {t.total} row(s) flagged ({pct}){note}")
        for rowid, summary in t.rows[:_SAMPLES]:
            lines.append(f"      rowid {rowid}: {summary}")
        if t.flagged > _SAMPLES:
            lines.append(f"      ... {t.flagged - _SAMPLES} more, in {FINDINGS_CSV} "
                         f"and the .db")

    lines += [
        "",
        "  Ranked by how SELECTIVE each flag is (rarest first), not by count: a",
        "  rule that fires on most of its table is a rule, not a finding.",
        "  Every row above is `SELECT * FROM <table> WHERE rowid = <rowid>`.",
    ]
    hint = case_hint or "<case>"
    lines.append(f'  To ask the whole case about a value: aeng sweep -p "{hint}" -q <value>')
    return lines


def write_findings_csv(f: Findings, out_dir: Path) -> Path | None:
    """`findings.csv` beside report.txt -- the machine-readable half.

    Deliberately NOT under `CSVs/`: consolidation absorbs every CSV it finds
    there into the .db, so a findings file living in that tree would become a
    table built out of the previous run's summary of itself.
    """
    rows = [(t.table, rowid, t.flagged, t.total, summary)
            for t in f.tables for rowid, summary in t.rows]
    if not rows:
        return None
    path = out_dir / FINDINGS_CSV
    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["table", "rowid", "flagged_in_table", "rows_in_table", "summary"])
            w.writerows(rows)
    except OSError as e:
        log.warning(f"[!] could not write {path.name}: {e}")
        return None
    return path
