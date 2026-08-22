r"""Incident event-log rows, derived from a parsed case.

The analyst keeps a *bitàcola*: one spreadsheet row per thing that happened, with
the host, the accounts, the direction, the ATT&CK tactic and a sentence of prose.
Most of those columns are already sitting in the case outputs -- `lateral.py`
spent the whole of phase 5 working out who authenticated where, from what, as
whom, and when -- so filling them in by hand is transcription, not analysis.

WHAT THIS DOES AND DOES NOT DECIDE. Every field written here is copied or derived
from a value the engine parsed out of the evidence, and every row names the file
it came from. Nothing is inferred about intent. The relevance column is a
confirmation state in this template, not a severity, and an automatically derived
row is a hypothesis: it goes in as `Potser`, never as `Confirmat`. Deciding a row
is confirmed, key, or wrong is the analyst's, and the tool must not appear to have
done it for them.

Descriptions are generated from the fields, deterministically. A language model
can rewrite them afterwards -- the prose is the one part where it cannot invent a
fact that was not already in the row -- but nothing here needs one to work.
"""
from __future__ import annotations

import csv
import datetime as _dt
from dataclasses import dataclass
from pathlib import Path

from artifact_engine.core import xlsx_inplace as xi
from artifact_engine.logging_setup import get_logger

log = get_logger()

SHEET = "Bitàcola"

# Column letters in the template, so a reordered sheet is a one-line change here
# rather than a hunt through the writer.
COL = {"tipus": "A", "when": "B", "logged": "C", "host": "D", "domain": "E",
       "source": "F", "destination": "G", "user": "H", "relevance": "I",
       "tactic": "J", "description": "K", "evidence": "L"}

# The template validates A, I and J against lists on its Llegenda sheet. These are
# what this code intends to write; `check_vocabulary` confirms the workbook still
# offers them before anything is written, because a value outside the list is not
# rejected by Excel -- it is accepted, and quietly breaks the dropdown for that cell.
TIPUS_EVENT = "Esdeveniment"
TIPUS_ALERT = "Alerta"
RELEVANCE_UNCONFIRMED = "Potser"

# ATT&CK tactic -> the label this template uses. Mapped from the reason vocabulary
# `lateral.py` already assigns, so the tactic is as defensible as the reason is.
T_INITIAL_ACCESS = "Accés Inicial"
T_CREDENTIAL_ACCESS = "Accés a Credencials"
T_DISCOVERY = "Descobriment"
T_LATERAL = "Moviment Lateral"

# First match wins, so the order IS the judgement. An edge that came from a
# routable source is initial access before it is anything else; a failure is about
# credentials whatever mechanism carried it; a null session is enumeration. What
# is left is movement, which is what the graph is for.
_TACTIC_BY_REASON: tuple[tuple[str, str], ...] = (
    ("rdp_public", T_INITIAL_ACCESS),
    ("brute_success", T_CREDENTIAL_ACCESS),
    ("failed_logon", T_CREDENTIAL_ACCESS),
    ("invalid_user", T_CREDENTIAL_ACCESS),
    ("anonymous_logon", T_DISCOVERY),
    ("explicit_creds", T_LATERAL),
    ("rdp_outbound", T_LATERAL),
    ("typed_unc", T_LATERAL),
    ("untrusted_cert", T_LATERAL),
    ("kerberos_service", T_LATERAL),
    ("case_to_case", T_LATERAL),
    ("chain", T_LATERAL),
)


@dataclass
class Entry:
    """One row. Field names are the template's columns, not the CSV's."""

    when_utc: str
    host: str
    source: str
    destination: str
    user: str
    tactic: str
    description: str
    evidence: str
    domain: str = ""
    tipus: str = TIPUS_EVENT
    relevance: str = RELEVANCE_UNCONFIRMED

    def key(self) -> tuple:
        """What makes this row the same finding as another one.

        The description is deliberately not in it: re-running after the wording
        changed must update nothing and duplicate nothing. The evidence file is,
        because the same logon seen in two sources is two pieces of support.
        """
        return (self.when_utc, self.source, self.destination, self.user, self.evidence)

    def cells(self, logged_on: str) -> dict[str, str]:
        return {COL["tipus"]: self.tipus, COL["when"]: self.when_utc,
                COL["logged"]: logged_on, COL["host"]: self.host,
                COL["domain"]: self.domain, COL["source"]: self.source,
                COL["destination"]: self.destination, COL["user"]: self.user,
                COL["relevance"]: self.relevance, COL["tactic"]: self.tactic,
                COL["description"]: self.description, COL["evidence"]: self.evidence}


def tactic_for(reasons: str) -> str:
    """The tactic for a graph edge's reason list, or "" when none of them says."""
    have = {r.strip() for r in reasons.split("+") if r.strip()}
    for reason, tactic in _TACTIC_BY_REASON:
        if reason in have:
            return tactic
    return ""


def _split_account(user: str) -> tuple[str, str]:
    """`CORP\\jdoe` -> ("CORP", "jdoe"). The graph already canonicalised this."""
    if "\\" in user:
        domain, _, account = user.partition("\\")
        return domain, account
    return "", user


def describe(row: dict, tactic: str) -> str:
    """A sentence built only from fields already in the row.

    Every clause names a value the engine parsed. There is nothing here a reader
    could not check against the CSV, which is the point: the prose is a reading
    aid, not a finding of its own.
    """
    mech = row.get("logon_type") or row.get("event_id") or "logon"
    outcome = "fallit" if (row.get("status") or "").lower() == "failed" else "correcte"
    who = row.get("user") or "un compte desconegut"
    src, dst = row.get("src") or "?", row.get("dst") or "?"
    count = (row.get("count") or "").strip()
    times = f", {count} vegades" if count.isdigit() and int(count) > 1 else ""
    detail = f" [{row['chainsaw']}]" if (row.get("chainsaw") or "").strip() else ""
    reasons = (row.get("reasons") or "").strip()
    why = f" ({reasons.replace('+', ', ')})" if reasons else ""
    return f"{mech} {outcome} de {src} cap a {dst} com a {who}{times}{why}{detail}"


def from_lateral(csv_path: Path, only_suspicious: bool = True) -> list[Entry]:
    """Rows from `lateral_movement.csv`, the richest single source for this.

    Every column the template wants about WHO went WHERE, from WHAT, as WHOM and
    WHEN is already in that file, correlated across every machine in the case.
    Restricted to the suspicious edges by default: the CSV is the complete edge
    list on purpose and a routine estate produces thousands of ordinary logons,
    which is a log, not a bitàcola.
    """
    if not csv_path.is_file():
        return []
    out: list[Entry] = []
    with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            if only_suspicious and (row.get("suspicious") or "").strip().lower() != "yes":
                continue
            tactic = tactic_for(row.get("reasons") or "")
            domain, _ = _split_account(row.get("user") or "")
            out.append(Entry(
                when_utc=(row.get("first_seen_utc") or "").strip(),
                host=(row.get("dst") or "").strip(),
                source=(row.get("src") or "").strip(),
                destination=(row.get("dst") or "").strip(),
                user=(row.get("user") or "").strip(),
                domain=domain,
                tactic=tactic,
                description=describe(row, tactic),
                evidence=csv_path.name,
                # A rule fired on the underlying event, so it is an alert rather
                # than something that merely happened.
                tipus=TIPUS_ALERT if (row.get("chainsaw") or "").strip() else TIPUS_EVENT,
            ))
    return out


def check_vocabulary(xlsx: Path) -> list[str]:
    """Values this code writes that the workbook's own lists no longer contain.

    Excel does not refuse an out-of-list value written into a validated cell: it
    stores it, and the dropdown for that cell stops working. So the check happens
    here, before writing, and a mismatch is reported rather than filed.
    """
    try:
        legend = xi.read_rows(xlsx, "Llegenda")
    except KeyError:
        return ["the workbook has no Llegenda sheet to validate against"]
    known = {v for cells in legend.values() for v in cells.values()}
    intended = {TIPUS_EVENT, TIPUS_ALERT, RELEVANCE_UNCONFIRMED,
                *(t for _, t in _TACTIC_BY_REASON)}
    return sorted(v for v in intended if v not in known)


def free_rows(xlsx: Path, sheet: str = SHEET) -> tuple[list[int], set[tuple]]:
    """(template rows still empty, keys of rows already filled).

    "Empty" means every column this tool writes except A is blank: a fresh
    template pre-fills A with `Esdeveniment` on every row, so treating that as
    content would find no room at all.
    """
    rows = xi.read_rows(xlsx, sheet)
    if not rows:
        raise KeyError(f"{sheet!r} is empty; is this the right workbook?")
    header = min(rows)
    watched = [c for k, c in COL.items() if k != "tipus"]
    free: list[int] = []
    taken: set[tuple] = set()
    for n in sorted(rows):
        if n == header:
            continue
        cells = rows[n]
        if any(cells.get(c) for c in watched):
            taken.add((cells.get(COL["when"], ""), cells.get(COL["source"], ""),
                       cells.get(COL["destination"], ""), cells.get(COL["user"], ""),
                       cells.get(COL["evidence"], "")))
        else:
            free.append(n)
    return free, taken


def write(xlsx: Path, entries: list[Entry], sheet: str = SHEET,
          logged_on: str | None = None) -> tuple[int, int, int]:
    """Fill empty template rows with `entries`. Returns (written, skipped, unplaced).

    Never touches a row that already has anything in it. A re-run adds what is new
    and leaves everything else exactly as the analyst left it, including rows they
    edited by hand -- the row's identity does not include its wording.
    """
    missing = check_vocabulary(xlsx)
    if missing:
        raise ValueError(
            "the workbook's Llegenda does not offer these values, so writing them "
            f"would break the dropdown on those cells: {missing}")

    stamp = logged_on or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    free, taken = free_rows(xlsx, sheet)

    fresh = []
    seen: set[tuple] = set()
    skipped = 0
    for e in sorted(entries, key=lambda x: (x.when_utc, x.source, x.destination)):
        k = e.key()
        if k in taken or k in seen:
            skipped += 1
            continue
        seen.add(k)
        fresh.append(e)

    placed = dict(zip(free, fresh))
    unplaced = len(fresh) - len(placed)
    if unplaced:
        log.warning(f"[!] bitacola: {unplaced} row(s) had nowhere to go - the sheet "
                    f"has {len(free)} empty row(s) left. Add rows to the template "
                    f"and re-run; nothing was dropped from the case.")
    if placed:
        xi.write_cells(xlsx, sheet, {n: e.cells(stamp) for n, e in placed.items()})
    return len(placed), skipped, unplaced
