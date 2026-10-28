r"""The rows this run flagged, on the front page instead of inside a dump.

Forty of the win_/lin_ handlers write a `suspicious` column by
convention and, until now, nothing read it. `report.txt` said which parsers RAN;
what they FOUND lived in one to two thousand rows of `.db` per table, reachable
only by writing SQL. Every high-value finding recovered from a real case so far
was recovered by hand from there, which means the tool did the work and then hid
it.

This reads the machine's consolidated `.db` -- already built by the time the
report is written -- and puts the flagged rows in front of the reader.

RANKING, WITHOUT AN INVENTED SEVERITY SCALE. Ordering by count puts whichever
table flags most rows on top, which is exactly the table worth reading last.
So inside each severity tier (below) tables are ranked by FLAG RATE, ascending:
three flagged rows out of three thousand is a selective signal, twelve hundred
out of fifteen hundred is a rule that fires on the ordinary case. The rarer the
flag, the higher it sits within its tier. Nothing here needs configuring, and
nothing here invents a severity the parsers did not claim -- the parsers said
`yes` or a severity word, and only the ordering (and the `flagged` label on a
`yes` they did not rate) is this module's opinion.

THE SEVERITY THE PARSERS DID CLAIM (v0.7.168). The detection tables -- Sigma over
the logs and the web, the exfiltration commands, hayabusa, the LiveResponse
verdicts -- never wrote `suspicious`: they rate every row in a `severity` or
`level` column instead, and until now none of them reached this page. A machine
whose only high-severity rows lived there read as clean. They are read now, in
tiers: critical/high first, then the rows flagged with no rating, then medium,
and low as one count line. Rarity still orders the tables inside a tier.

`level` is not always a severity. EvtxECmd, nginx and FortiGate use it for the
LOG level ("Information", "crit", "warning"), so a column counts only when every
value in it is a severity word, and the EvtxECmd channels are left out by name
because one holding only "Info" and "Critical" would pass that test.
Hayabusa's timeline is named and not counted where `alert_hayabusa` holds it
aggregated per rule and source (v0.7.170): counting both would count every
detection twice.

WHAT IT DOES NOT COVER, STATED. Only some tables carry either column: the
external-tool outputs (MFT, EvtxECmd channels) have their own schemas and no
such convention. A findings section built on these columns therefore covers a
minority of the evidence, and one that did not say so would be a false front
page -- an analyst reading a short list would take it for a short case. So the
tables with neither column are counted and named, every run.
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

# The columns a detection table rates its rows in, and the words that make one a
# severity. A column whose values are not ALL in this map is a log level (or
# something else) and is not read. Informational and empty rate nothing.
_SEV_COLS = ("severity", "level")
_SEV_WORDS = {"critical": "critical", "crit": "critical", "high": "high",
              "medium": "medium", "med": "medium", "low": "low",
              "informational": "", "info": "", "": ""}

# Tables whose `Level` is the event's log level whatever values it happens to
# hold: the EvtxECmd channels.
_LOG_LEVEL_PREFIXES = ("art_evtx_",)

# A table whose rows another table holds aggregated, and that one: the front page
# reads the aggregate and names this one, when the aggregate is there. Hayabusa's
# timeline was 443,079 rows on one case; alert_hayabusa holds every one of its
# detections, one row per (level, rule, source address), the address empty for
# the ones naming none, and no row cap (v0.7.170).
_AGGREGATED = {"art_hayabusa": "alert_hayabusa"}

# A column naming the rule that produced the row. A table of rule hits is shown
# per rule: seven hundred rows of one rule are one finding, and listed row by row
# they bury the one row of the rule that fired once.
_RULE_COLS = ("rule", "ruletitle")

# The tiers, in the order the page prints them. `flagged` is a `suspicious` row
# with no rating; `low` is counted on the page and listed only in the CSV.
TIERS = ("high", "flagged", "medium", "low")
_TIER_WORDS = {"high": ("critical", "crit", "high"), "medium": ("medium", "med"),
               "low": ("low",)}
_TIER_TITLE = {"high": "Critical / high", "flagged": "Flagged (no severity given)",
               "medium": "Medium", "low": "Low"}

# Rows (or rules) shown per table in report.txt. The report is a front page, not
# the data: past a handful the reader should be in the .db, and the pointer to it
# is on every row.
_SAMPLES = 5

# Rows per table and tier carried into findings.csv. Bounded for the same reason
# every aggregate here is bounded -- a spray-driven table's row count is the
# attacker's to choose -- and a truncated table is named in the report rather
# than trimmed quietly.
_CSV_CAP = 500

# Values joined into a row's one-line summary, and how long that line may get.
_SUMMARY_COLS = 4
_SUMMARY_CHARS = 160


@dataclass
class RuleGroup:
    rule: str
    count: int
    rowid: int          # the first row of the rule, as the example
    summary: str


@dataclass
class TableFindings:
    table: str
    flagged: int        # rows in this tier
    total: int
    tier: str = "flagged"
    rows: list[tuple[int, str, str]] = field(default_factory=list)  # (rowid, severity, summary)
    groups: list[RuleGroup] = field(default_factory=list)          # per rule, rarest first
    truncated: bool = False

    @property
    def rate(self) -> float:
        """Share of the table's rows in this tier. The ranking key."""
        return self.flagged / self.total if self.total else 0.0


@dataclass
class Findings:
    tables: list[TableFindings] = field(default_factory=list)   # one per table AND tier
    unflagged: list[str] = field(default_factory=list)   # neither column
    restated: list[str] = field(default_factory=list)    # restated or aggregated elsewhere
    covered: int = 0                                     # tables carrying either column
    unreadable: str = ""                                 # why the .db gave nothing

    @property
    def flagged(self) -> int:
        return sum(t.flagged for t in self.tables)

    def tier(self, name: str) -> list[TableFindings]:
        return [t for t in self.tables if t.tier == name and t.flagged]


def _q(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _norm(col: str) -> str:
    """A column value as the lower-case word it is compared as."""
    return f"LOWER(TRIM(COALESCE(CAST({_q(col)} AS TEXT), '')))"


def _summary(cols: list[str], row: tuple, skip: set[str]) -> str:
    """A one-line rendering of a flagged row: the first few values that are not
    empty, in column order. Enough to recognise the row; the rowid is what takes
    the reader to the rest of it."""
    parts = []
    for col, value in zip(cols, row):
        if col.lower() in skip or value in (None, ""):
            continue
        parts.append(str(value).replace("\n", " ").strip())
        if len(parts) >= _SUMMARY_COLS:
            break
    return " | ".join(parts)[:_SUMMARY_CHARS]


def _severity_col(conn: sqlite3.Connection, table: str, cols: list[str]) -> str | None:
    """The table's severity column, or None when it has none or its `level` is a
    log level. Every distinct value must be a severity word; twelve is more than
    the vocabulary holds, so reading past that proves nothing more."""
    if table.lower().startswith(_LOG_LEVEL_PREFIXES):
        return None
    for want in _SEV_COLS:
        col = next((c for c in cols if c.lower() == want), None)
        if col is None:
            continue
        vals = {r[0] for r in conn.execute(
            f"SELECT DISTINCT {_norm(col)} FROM {_q(table)} LIMIT 12")}
        if vals <= _SEV_WORDS.keys():
            return col
    return None


def _table_findings(conn: sqlite3.Connection, table: str) -> list[TableFindings] | None:
    """One table's rows per tier, or None when it carries neither column."""
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({_q(table)})")]
    flag = next((c for c in cols if c.lower() == _FLAG), None)
    sev = _severity_col(conn, table, cols)
    if flag is None and sev is None:
        return None

    total = conn.execute(f"SELECT COUNT(*) FROM {_q(table)}").fetchone()[0]
    rule = next((c for c in cols if c.lower() in _RULE_COLS), None) if sev else None
    skip = {_FLAG} | ({sev.lower()} if sev else set())

    def words(tier: str) -> str:
        return ", ".join(f"'{w}'" for w in _TIER_WORDS[tier])

    rated = (f"{_norm(sev)} IN ({words('high')}, {words('medium')}, {words('low')})"
             if sev else "0")
    where = {}
    if flag is not None:
        # TRIM + CAST because the convention is "yes or EMPTY", and a column that
        # arrived through a CSV can hold a stray space as easily as a value. A
        # flagged row that is also rated sits in its rating's tier, once.
        where["flagged"] = (f"TRIM(COALESCE(CAST({_q(flag)} AS TEXT), '')) <> '' "
                            f"AND NOT ({rated})")
    if sev is not None:
        for tier in ("high", "medium", "low"):
            where[tier] = f"{_norm(sev)} IN ({words(tier)})"

    out = []
    select = ", ".join(_q(c) for c in cols)
    sev_at = cols.index(sev) if sev else -1
    for tier in TIERS:
        if tier not in where:
            continue
        cond = where[tier]
        n = conn.execute(f"SELECT COUNT(*) FROM {_q(table)} WHERE {cond}").fetchone()[0]
        tf = TableFindings(table=table, flagged=n, total=total, tier=tier)
        out.append(tf)
        if not n:
            continue
        rows = conn.execute(f"SELECT rowid, {select} FROM {_q(table)} WHERE {cond} "
                            f"ORDER BY rowid LIMIT {_CSV_CAP}")
        for r in rows:
            label = _SEV_WORDS.get(str(r[1 + sev_at] or "").strip().lower(), "") \
                if sev_at >= 0 else ""
            tf.rows.append((r[0], label or tier, _summary(cols, r[1:], skip)))
        tf.truncated = n > _CSV_CAP
        if rule is not None:
            # Rarest rule first, the same reasoning as the table ranking: the
            # rule that fired once is the one a reader would otherwise miss.
            for name, cnt, first in conn.execute(
                    f"SELECT {_q(rule)}, COUNT(*), MIN(rowid) FROM {_q(table)} "
                    f"WHERE {cond} GROUP BY {_q(rule)} ORDER BY 2, 1"):
                row = conn.execute(f"SELECT {select} FROM {_q(table)} WHERE rowid = ?",
                                   (first,)).fetchone()
                tf.groups.append(RuleGroup(str(name or ""), cnt, first,
                                           _summary(cols, row, skip | {rule.lower()})))
    return out


def collect(db: Path) -> Findings:
    """Every flagged or rated row in a machine's consolidated database, ranked."""
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
        present = {t.lower() for t in tables}
        for t in tables:
            if _AGGREGATED.get(t.lower()) in present:
                result.restated.append(t)
                continue
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
                result.covered += 1
                result.tables.extend(tf)
    except sqlite3.Error as e:
        result.unreadable = f"{type(e).__name__}: {e}"
    finally:
        conn.close()

    # Tier first, then ascending rate: the most selective signal first. Ties
    # break on the smaller absolute count, then the name, so the order is stable
    # across runs.
    result.tables.sort(key=lambda t: (TIERS.index(t.tier), t.rate, t.flagged, t.table))
    return result


def _table_lines(t: TableFindings) -> list[str]:
    word = "flagged" if t.tier == "flagged" else t.tier
    note = f"  [csv truncated at {_CSV_CAP}]" if t.truncated else ""
    head = f"  {t.table}: {t.flagged} of {t.total} row(s) {word} ({t.rate * 100:.1f}%)"
    if t.groups:
        head += f", {len(t.groups)} rule(s)"
    lines = [head + note]
    if t.groups:
        for g in t.groups[:_SAMPLES]:
            lines.append(f"      {g.rule}: {g.count} row(s), e.g. rowid {g.rowid}: {g.summary}")
        if len(t.groups) > _SAMPLES:
            lines.append(f"      ... {len(t.groups) - _SAMPLES} more rule(s), in "
                         f"{FINDINGS_CSV} and the .db")
        return lines
    for rowid, sev, summary in t.rows[:_SAMPLES]:
        mark = f"[{sev}] " if sev == "critical" else ""
        lines.append(f"      rowid {rowid}: {mark}{summary}")
    if t.flagged > _SAMPLES:
        lines.append(f"      ... {t.flagged - _SAMPLES} more, in {FINDINGS_CSV} and the .db")
    return lines


def render(f: Findings, case_hint: str = "") -> list[str]:
    """The report.txt section. Printed on every run, including a clean one: an
    absent section and a section saying nothing was flagged are read very
    differently months later."""
    lines = ["", "Findings (rows the parsers flagged or rated):"]
    if f.unreadable:
        lines.append(f"  NOT AVAILABLE - {f.unreadable}")
        return lines

    with_hits = {t.table for t in f.tables if t.flagged}
    counts = ", ".join(f"{sum(t.flagged for t in f.tier(n))} {n}" for n in TIERS)
    lines.append(f"  {f.flagged} row(s) in {len(with_hits)} of {f.covered} table(s) "
                 f"that carry `{_FLAG}` or a severity: {counts}.")
    if f.unflagged:
        lines.append(f"  {len(f.unflagged)} table(s) have neither column and are "
                     f"NOT covered by this section:")
        lines.append(f"    {', '.join(f.unflagged)}")
    if f.restated:
        lines.append(f"  Not counted again, their rows are in the tables above: "
                     f"{', '.join(f.restated)}")

    if not with_hits:
        lines.append("")
        lines.append("  Nothing flagged. That is a statement about the flags the")
        lines.append("  parsers set, not about the tables listed above as uncovered.")
    for tier in TIERS[:3]:
        group = f.tier(tier)
        if not group:
            continue
        lines += ["", f"  {_TIER_TITLE[tier]}:"]
        for t in group:
            lines += _table_lines(t)
    low = f.tier("low")
    if low:
        lines += ["", f"  {_TIER_TITLE['low']} (counted here, listed in {FINDINGS_CSV}): "
                  + ", ".join(f"{t.table} {t.flagged}" for t in low)]

    lines += [
        "",
        "  Ranked by severity where the parser gave one, then by how SELECTIVE",
        "  each flag is (rarest first), not by count: a rule that fires on most",
        "  of its table is a rule, not a finding.",
        "  Every row above is `SELECT * FROM <table> WHERE rowid = <rowid>`.",
    ]
    hint = case_hint or "<case>"
    lines.append(f'  To ask the whole case about a value: aeng sweep -p "{hint}" -q <value>')
    # The bulk form is the one nobody finds: an IOC list from a partner arrives as
    # twenty values, and `-q` repeated twenty times is what people stop doing.
    lines.append("    ...a whole IOC list: --ioc-file <list.txt>   "
                 "...for the case log: --csv <out.csv>")
    return lines


def write_findings_csv(f: Findings, out_dir: Path) -> Path | None:
    """`findings.csv` beside report.txt -- the machine-readable half.

    Deliberately NOT under `CSVs/`: consolidation absorbs every CSV it finds
    there into the .db, so a findings file living in that tree would become a
    table built out of the previous run's summary of itself.

    `severity` is the row's rating (critical, high, medium, low) or `flagged`
    for a `suspicious` row the parser did not rate; `flagged_in_table` counts
    the table's rows in the same tier.
    """
    rows = [(t.table, rowid, sev, t.flagged, t.total, summary)
            for t in f.tables for rowid, sev, summary in t.rows]
    if not rows:
        return None
    path = out_dir / FINDINGS_CSV
    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["table", "rowid", "severity", "flagged_in_table",
                        "rows_in_table", "summary"])
            w.writerows(rows)
    except OSError as e:
        log.warning(f"[!] could not write {path.name}: {e}")
        return None
    return path
