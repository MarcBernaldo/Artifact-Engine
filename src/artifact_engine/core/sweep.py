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
"""
from __future__ import annotations

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

    @property
    def clean(self) -> bool:
        """True when the sweep covered everything it found. A False here means "no
        hits" is not a finding about the case, it is a finding about the case data."""
        return not self.unreadable


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


def sweep_database(label: str, db: Path, needles: list[str]) -> tuple[list[Hit], str]:
    """Search one machine. Returns (hits, "") or ([], why it could not be read)."""
    patterns = {n: _boundary(n) for n in needles}
    hits: list[Hit] = []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except sqlite3.Error as e:
        return [], f"{type(e).__name__}: {e}"
    try:
        conn.text_factory = lambda b: b.decode("utf-8", "replace")
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
            where = " OR ".join(f"{joined} LIKE ?" for _ in needles)
            args = [f"%{n}%" for n in needles]
            try:
                rows = conn.execute(f"SELECT {select} FROM {_q(table)} WHERE {where}", args)
                for row in rows:
                    for col, value in zip(cols, row):
                        if not value:
                            continue
                        text = str(value)
                        for needle, pat in patterns.items():
                            if pat.search(text):
                                hits.append(Hit(label, table, col, needle,
                                                text[:_CONTEXT_CHARS]))
            except sqlite3.Error as e:
                # One unreadable table is not an unreadable machine: a corrupt page
                # in an artifact nobody asked about must not hide hits in the rest.
                log.debug(f"sweep: {label}:{table}: {e}")
        return hits, ""
    except sqlite3.Error as e:
        return [], f"{type(e).__name__}: {e}"
    finally:
        conn.close()


def sweep(root: Path, needles: list[str]) -> Sweep:
    """Search every machine in the case for every needle."""
    result = Sweep()
    wanted = [n.strip() for n in needles if n.strip()]
    if not wanted:
        return result
    for label, db in find_case_databases(root):
        hits, why = sweep_database(label, db, wanted)
        if why:
            result.unreadable.append((label, why))
            continue
        result.searched.append(label)
        result.hits.extend(hits)
    return result
