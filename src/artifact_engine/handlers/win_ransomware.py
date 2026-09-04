r"""Handler: ransom notes and mass renames in the $MFT. Output: ransomware_traces.csv

The whole answer is already in the transcoded `$MFT` -- every filename on the
volume, with the time its content was last written -- and until now nothing asked
it the one question a ransomware case turns on. See `_ransom` for why a match on
the extension list is a count and never a verdict, and what is allowed to turn a
count into a finding.

The window reported is `LastModified0x10`, not the creation time, because that is
when the content was written. A rename in place carries the original `$SI`
creation time forward, so a run that renames rather than rewrites would look
years old if this measured creation -- and it is the shape of the WINDOW, a whole
share rewritten inside an hour, that separates a run from a filesystem.
"""

from __future__ import annotations

import csv
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _ransom
from artifact_engine.handlers._lincommon import write_csv

_MFT_CSV = Path("CSVs") / "Filesystem" / "MFT.csv"


def _true(value: str) -> bool:
    return (value or "").strip().lower() in ("true", "1", "yes")


def run(ctx) -> None:
    src = Path(ctx.evidence) / _MFT_CSV
    if not src.is_file():
        raise HandlerSkip("no MFT.csv to read")

    notes, exts = _ransom.load_lists(Path(ctx.assets))
    traces = _ransom.Traces()
    try:
        fh = src.open("r", encoding="utf-8-sig", errors="replace", newline="")
    except OSError as e:
        raise HandlerSkip(f"MFT.csv unreadable: {e}") from e
    with fh:
        reader = csv.reader(line.replace("\x00", "") for line in fh)
        header = next(reader, None)
        if not header:
            raise HandlerSkip("MFT.csv is empty")
        idx = {name.strip(): i for i, name in enumerate(header)}
        if "FileName" not in idx:
            raise HandlerSkip("MFT.csv has no FileName column")

        def cell(row: list, name: str) -> str:
            i = idx.get(name)
            return row[i] if i is not None and i < len(row) else ""

        for row in reader:
            if _true(cell(row, "IsDirectory")):
                continue
            name = cell(row, "FileName")
            found = _ransom.classify(name, notes, exts)
            if found is None:
                continue
            kind, marker, family, reference, double = found
            parent = cell(row, "ParentPath")
            traces.add(kind, marker, f"{parent}\\{name}" if parent else name,
                       parent, cell(row, "LastModified0x10"), double,
                       family, reference)

    rows = _ransom.rows(traces)
    if not rows:
        return                                # nothing to say, and no empty table
    write_csv(ctx.out, "ransomware_traces.csv", _ransom.columns(), rows)
