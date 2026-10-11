"""The detections that read one artifact, gathered in one table per artifact.

Each detection writes its own table with its own columns -- ransomware traces,
timestamp manipulation, credential stores and collection staging all come out
of the `$MFT`, in four tables an analyst opens one by one. Here every row that
is an alert is restated in a common shape and gathered by the artifact it was
read from (`alerts_mft`, `alerts_execution`, `alerts_bodyfile`, `alerts_shell`),
so one table answers "what did the MFT say" (v0.7.99). The source tables are
untouched; `source_table` names where each row came from.

Columns: `alert` (the detection, and its own kind when it has one), `severity`,
`subject` (the path, binary or command it is about), `time_utc` (the first
time the row carries), `detail` (every non-empty column but the kind, subject
and `suspicious` ones, `k=v`) and
`source_table`.
"""

from __future__ import annotations

import csv
from pathlib import Path

HEADER = ["alert", "severity", "subject", "time_utc", "detail", "source_table"]

_RANK = {"high": 0, "medium": 1, "low": 2}
_DETAIL_CHARS = 400

csv.field_size_limit(2**31 - 1)


def _suspicious(row: dict) -> str:
    """Tables with a `suspicious` column: flagged rows high, the rest context."""
    return "high" if (row.get("suspicious") or "").strip().lower() == "yes" else "low"


def _byovd(row: dict) -> str:
    return "high" if (row.get("category") or "").lower() == "malicious" else "medium"


def _gtfobins(row: dict) -> str:
    return "high" if (row.get("sudo") or "").strip().lower() in ("yes", "true", "1") else "medium"


def _medium(_row: dict) -> str:
    return "medium"


def _own(row: dict) -> str:
    """Tables that rank their own rows (`severity` column)."""
    return (row.get("severity") or "").strip().lower() or "low"


# One spec per source table: (table, alert name, kind column or "",
# subject column, severity, keep).  `keep` None takes every row.
def _flagged(row: dict) -> bool:
    return bool((row.get("flag") or "").strip())


SPECS = {
    "windows": {
        "alerts_mft": [
            ("ransomware_traces", "ransomware", "kind", "example", _suspicious, None),
            ("timestomp", "timestomp", "", "path", _suspicious, None),
            ("credential_access", "credential_access", "kind", "path", _suspicious, None),
            ("collection_artifacts", "collection", "kind", "path", _suspicious, None),
        ],
        "alerts_execution": [
            ("byovd", "byovd", "category", "path", _byovd, None),
            ("lolbas", "lolbas", "", "path", _medium, None),
            ("rmm", "rmm", "tool", "path", _medium, None),
            ("suspicious_tools", "tool", "category", "path", _medium, None),
        ],
        # every command line the machine kept (cmd_hunt, v0.7.104): PowerShell history
        # is one of its sources, so consolehost's own flag column is not read twice
        "alerts_shell": [
            ("suspicious_commands", "shell", "category", "command", _medium, None),
            ("exfil_commands", "exfil", "tool", "command", _own, None),
        ],
    },
    "linux": {
        "alerts_bodyfile": [
            ("ransomware_traces", "ransomware", "kind", "example", _suspicious, None),
            ("timestomp", "timestomp", "", "path", _suspicious, None),
            ("collection_artifacts", "collection", "kind", "path", _suspicious, None),
        ],
        "alerts_shell": [
            ("bash", "shell", "flag", "command", _medium, _flagged),
            ("gtfobins", "gtfobins", "function", "command", _gtfobins, None),
        ],
    },
}


def machine_root(out: Path) -> Path:
    """The machine folder: the parent of the CSVs/ tree a handler writes into."""
    out = Path(out)
    for p in (out, *out.parents):
        if p.name.lower() == "csvs":
            return p.parent
    return out


def find_table(csvs: Path, table: str) -> Path | None:
    """`<table>.csv` under the machine's CSVs/, outside any parser's scratch dir."""
    for p in sorted(csvs.rglob(f"{table}.csv")):
        if not any(part.startswith(".work") for part in p.relative_to(csvs).parts):
            return p
    return None


def _first_utc(row: dict, header: list[str]) -> str:
    for col in header:
        if col.endswith("_utc") and (row.get(col) or "").strip():
            return row[col].strip()
    return ""


def gather(csvs: Path, specs: list[tuple]) -> list[list]:
    """The rows of one artifact's alert table, most severe first."""
    out: list[tuple] = []
    for table, name, kind_col, subject_col, severity, keep in specs:
        path = find_table(csvs, table)
        if path is None:
            continue
        with path.open(encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            header = list(reader.fieldnames or [])
            for row in reader:
                if keep is not None and not keep(row):
                    continue
                kind = (row.get(kind_col) or "").strip() if kind_col else ""
                alert = f"{name}: {kind}" if kind else name
                sev = severity(row)
                used = {kind_col, subject_col, "suspicious"}
                detail = "; ".join(f"{c}={row[c]}" for c in header
                                   if c not in used and (row.get(c) or "").strip())
                out.append((_RANK.get(sev, 3), alert, [
                    alert, sev, (row.get(subject_col) or "").strip(), _first_utc(row, header),
                    detail[:_DETAIL_CHARS], table]))
    out.sort(key=lambda x: (x[0], x[1]))
    return [r for _, _, r in out]
