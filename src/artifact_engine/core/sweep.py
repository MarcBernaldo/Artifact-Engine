r"""Look for a value across every machine in a case, and say where it was not looked for.

Cases are worked one machine at a time, and each machine teaches you something the
earlier ones were never asked about: an address, an account, a filename, a hash.
Going back over the machines already finished is the part a person does badly --
not because it is hard, but because it has to be redone every time the case learns
something, and by machine seven nobody re-checks machine two.

This does the cross product. Give it what you learned and it reports every machine
that carries it, with the table and column it came out of so the claim can be
checked. It reads the consolidated `.db` each machine already has; nothing is
parsed again and nothing is written to a machine's folder.

WHAT IT SAYS WHEN IT FINDS NOTHING. "No hits" is only true if everything was
actually searched, and in a real case it usually was not: a machine may not be
consolidated yet, its database may be open in another program, or the run that
produced it may have failed. Those machines are reported by name, separately from
the hits, because a silent sweep over a case that is half readable is exactly the
answer an analyst must not be given.

THE COLLECTION'S OWN COPY. When the operator pointed the collector at the disk it
was collecting, every artifact it copied is recorded twice, and a search for a
filename returns the real hit next to its duplicate under the output tree. Rows
whose paths sit under such a tree (`collection_artifacts`, written per machine by
`win_collection` / `lin_collection`) are dropped by default -- and COUNTED, and
reported, because a hit that was hidden is not a hit that was absent.
`include_collection=True` puts them back.
"""
from __future__ import annotations

import csv
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from artifact_engine.logging_setup import get_logger

log = get_logger()

# Case-root outputs are not machines: they are the engine's own consolidated views.
_ROOT_OUTPUTS = {"case.db"}

# Text carried around a hit, so a row is recognisable without opening the database.
_CONTEXT_CHARS = 240

# LIKE terms per query. A partner's IOC list is twenty values or two hundred, and
# one OR term per needle per table stops being something SQLite plans well.
_NEEDLE_BATCH = 100

# A needle shorter than this matches half the case. Not refused -- a two-character
# value is occasionally the right question -- but reported, because an analyst who
# pasted a stray line and got 40,000 hits should be told which value did it.
_SHORT_NEEDLE = 4

SWEEP_CSV_COLUMNS = ["status", "needle", "machine", "table", "column", "context"]


@dataclass
class Hit:
    machine: str
    table: str
    column: str
    needle: str
    context: str

    def where(self) -> str:
        return f"{self.machine}:{self.table}.{self.column}"


@dataclass
class Sweep:
    """What was found, and -- just as much of the answer -- what was not searched."""

    hits: list[Hit] = field(default_factory=list)
    searched: list[str] = field(default_factory=list)
    unreadable: list[tuple[str, str]] = field(default_factory=list)   # (machine, why)
    # Rows dropped because they sat under a collection's own output tree, per
    # machine. Never dropped silently: an analyst told "no hits" while three were
    # hidden has been given the wrong answer, not a tidier one.
    hidden: dict[str, int] = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        """True when the sweep covered everything it found. A False here means "no
        hits" is not a finding about the case, it is a finding about the case data."""
        return not self.unreadable


def batches(values: list[str], size: int):
    """`values` in chunks of at most `size`, preserving order."""
    for i in range(0, len(values), size):
        yield values[i:i + size]


@dataclass
class IocFile:
    """One `--ioc-file`, and everything about it worth reporting.

    A partner's list arrives as a file, and the two ways that goes wrong are both
    silent: the path is mistyped (a sweep of nothing reads as a clean case) or
    half the lines are headers and commas (values that never matched anything
    because they were never values). Both are counted here and printed.
    """

    path: Path
    values: list[str] = field(default_factory=list)
    ignored: int = 0          # blank lines and comments
    error: str = ""


def _needle_from(line: str) -> str:
    """One line of an IOC file as a value, or "" when it is not one.

    Written for what people actually paste: a column out of a spreadsheet, with
    quotes around it and a comma after it, or a `#` header line. A `#` only starts
    a comment at the beginning of a line -- it is a legitimate character inside a
    URL, and stripping from the middle would silently truncate one.
    """
    text = line.strip()
    if not text or text.startswith("#"):
        return ""
    text = text.rstrip(",").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    return text


def read_iocs(path: Path) -> IocFile:
    """Values from an IOC file, one per line. Never raises."""
    out = IocFile(Path(path))
    try:
        raw = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    except OSError as e:
        out.error = f"{type(e).__name__}: {e}"
        return out
    for line in raw.splitlines():
        value = _needle_from(line)
        if value:
            out.values.append(value)
        else:
            out.ignored += 1
    return out


def merge_needles(*sources) -> tuple[list[str], int]:
    """Every needle in the order it was given, de-duplicated. (needles, dropped).

    Case-insensitively, because the search itself is: keeping `Example.exe` and
    `example.exe` apart would scan every table twice to report the same row under
    two names.
    """
    seen: set[str] = set()
    out: list[str] = []
    dropped = 0
    for source in sources:
        for value in source or ():
            text = str(value).strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                dropped += 1
                continue
            seen.add(key)
            out.append(text)
    return out, dropped


def short_needles(needles: list[str]) -> list[str]:
    """Needles short enough to match most of a case, for the caller to warn about."""
    return [n for n in needles if len(n) < _SHORT_NEEDLE]


def find_case_databases(root: Path) -> list[tuple[str, Path]]:
    """Every consolidated machine database under `root`, as (label, path).

    Found by walking rather than by re-detecting machines: a merged VSS unit writes
    one database for a host under the collection folder, and a loose drop writes
    one inside the drop, so the set on disk is the authority on what exists. The
    label is the database's own name, which is the machine name the run settled on.
    """
    out: list[tuple[str, Path]] = []
    for p in sorted(root.rglob("*.db")):
        if p.name in _ROOT_OUTPUTS or p.parent == root:
            continue                      # the case's own state, not a machine
        out.append((p.stem, p))
    return out


def _q(name: str) -> str:
    """A SQLite identifier, quoted. Table and column names here come from whatever
    an external tool called its CSV columns, so they carry spaces, dots and the
    occasional quote."""
    return '"' + str(name).replace('"', '""') + '"'


def _text_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    """Columns worth searching. Everything is text in practice -- the consolidator
    writes CSV cells -- but a declared INTEGER column cannot hold an address or a
    path, and scanning it is pure cost."""
    cols = []
    for row in conn.execute(f"PRAGMA table_info({_q(table)})"):
        decl = (row[2] or "").upper()
        if "INT" not in decl and "REAL" not in decl and "BLOB" not in decl:
            cols.append(row[1])
    return cols


COLLECTION_TABLE = "collection_artifacts"


def collection_prefixes(conn: sqlite3.Connection) -> list[str]:
    """Path prefixes this machine says are copies of itself, lower-cased.

    Only the rows the parser marked `exclude`: `Windows.old` and a collector's
    tool directory are in the same table and are deliberately NOT excluded -- the
    first holds real evidence of the previous install, and the second can hold an
    attacker's tools as easily as an operator's.
    """
    sql = (f'SELECT "path" FROM {_q(COLLECTION_TABLE)} '
           f"""WHERE TRIM(COALESCE("exclude", '')) <> ''""")
    try:
        rows = conn.execute(sql).fetchall()
    except sqlite3.Error:
        return []
    out = []
    for (path,) in rows:
        p = str(path or "").strip().rstrip("\\/").lower()
        if p and p not in (".", "/"):
            out.append(p)
    return out


def _boundary(needle: str) -> re.Pattern:
    r"""Match the needle as a value, not as a fragment of a longer one.

    `LIKE '%10.0.0.5%'` also matches `10.0.0.50`, and on an address that is not a
    near miss -- it is a different host, in a report that names it. SQL does the
    coarse pass because it is fast; this decides. The boundary is "not adjacent to
    something a value of this kind could continue with", which for an address means
    a digit or a dot, and for a name means a word character.
    """
    esc = re.escape(needle)
    if re.fullmatch(r"[0-9.]+", needle):                       # IPv4, or part of one
        return re.compile(rf"(?<![\d.]){esc}(?![\d.])", re.IGNORECASE)
    return re.compile(rf"(?<!\w){esc}(?!\w)", re.IGNORECASE)


def sweep_database(label: str, db: Path, needles: list[str],
                   include_collection: bool = False) -> tuple[list[Hit], str, int]:
    """Search one machine. Returns (hits, "", hidden) or ([], why, 0)."""
    patterns = {n: _boundary(n) for n in needles}
    hits: list[Hit] = []
    hidden = 0
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error as e:
        return [], f"{type(e).__name__}: {e}", 0
    try:
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
        copies = [] if include_collection else collection_prefixes(conn)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for table in tables:
            cols = _text_columns(conn, table)
            if not cols:
                continue
            select = ", ".join(_q(c) for c in cols)
            # One scan per table rather than one per column: the coarse filter is a
            # single LIKE over the row's whole text, and which column matched is
            # worked out afterwards in Python, where the boundary check lives too.
            joined = " || '\x1f' || ".join(f"COALESCE({_q(c)}, '')" for c in cols)
            # ...and in batches of needles, because a partner's IOC list is twenty
            # values or two hundred, and one OR term per needle per table turns a
            # bulk sweep into a query SQLite plans badly. Each needle sits in
            # exactly one batch, so a hit is never produced twice -- but a ROW can
            # be seen by two batches, which is why the hidden count is a set of
            # rows and not a running total.
            hidden_rows: set[int] = set()
            try:
                for batch in batches(needles, _NEEDLE_BATCH):
                    where = " OR ".join(f"{joined} LIKE ?" for _ in batch)
                    args = [f"%{n}%" for n in batch]
                    rows = conn.execute(
                        f"SELECT {select} FROM {_q(table)} WHERE {where}", args)
                    for row in rows:
                        # Whole-row test, not per-column: the needle may match a bare
                        # filename while the PATH column beside it is what says the
                        # row is the collector's copy.
                        if copies and table != COLLECTION_TABLE:
                            text = "".join(str(v or "") for v in row).lower()
                            if any(c in text for c in copies):
                                hidden_rows.add(hash(row))
                                continue
                        for col, value in zip(cols, row):
                            if not value:
                                continue
                            text = str(value)
                            for needle in batch:
                                if patterns[needle].search(text):
                                    hits.append(Hit(label, table, col, needle,
                                                    text[:_CONTEXT_CHARS]))
                hidden += len(hidden_rows)
            except sqlite3.Error as e:
                # One unreadable table is not an unreadable machine: a corrupt page
                # in an artifact nobody asked about must not hide hits in the rest.
                log.debug(f"sweep: {label}:{table}: {e}")
        return hits, "", hidden
    except sqlite3.Error as e:
        return [], f"{type(e).__name__}: {e}", 0
    finally:
        conn.close()


def sweep(root: Path, needles: list[str], include_collection: bool = False) -> Sweep:
    """Search every machine in the case for every needle."""
    result = Sweep()
    wanted = [n.strip() for n in needles if n.strip()]
    if not wanted:
        return result
    for label, db in find_case_databases(root):
        hits, why, hidden = sweep_database(label, db, wanted, include_collection)
        if why:
            result.unreadable.append((label, why))
            continue
        result.searched.append(label)
        result.hits.extend(hits)
        if hidden:
            result.hidden[label] = hidden
    return result


def csv_rows(result: Sweep, needles: list[str]) -> list[list[str]]:
    """The whole sweep as rows: the hits AND the rest of the answer.

    A CSV of hits alone is the false reassurance this module exists to avoid. A
    record that goes into a case log has to say which values were asked (`no_hits`
    is a result, and the one most of an IOC list produces), which machines could
    not be opened, and how many rows were held back as the collector's own copy --
    otherwise "we checked twenty IOCs across twelve machines" is not something the
    file can support months later.
    """
    rows = [["hit", h.needle, h.machine, h.table, h.column, h.context]
            for h in sorted(result.hits,
                            key=lambda h: (h.needle.lower(), h.machine, h.table, h.column))]
    struck = {h.needle for h in result.hits}
    searched = f"searched {len(result.searched)} machine(s)"
    rows += [["no_hits", n, "", "", "", searched]
             for n in needles if n not in struck]
    rows += [["hidden", "", m, "", "",
              (f"{result.hidden[m]} row(s) under the collection's own copy of the "
               f"disk; --include-collection searches them")]
             for m in sorted(result.hidden)]
    rows += [["not_searched", "", m, "", "", why]
             for m, why in sorted(result.unreadable)]
    return rows


def write_csv(result: Sweep, needles: list[str], path: Path) -> Path | None:
    """`csv_rows` to `path`. Returns the path, or None when it could not be written."""
    try:
        with Path(path).open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(SWEEP_CSV_COLUMNS)
            w.writerows(csv_rows(result, needles))
    except OSError as e:
        log.warning(f"[!] could not write {path}: {e}")
        return None
    return Path(path)
