"""Where a handler finds the machine folder and another parser's table."""

from __future__ import annotations

from pathlib import Path


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
