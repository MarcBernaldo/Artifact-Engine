r"""Handler: ransom notes and mass renames in the bodyfile. Output: ransomware_traces.csv

The Linux half of the same question -- see `_ransom` for why an extension match
is a count and not a verdict.

Linux ransomware is where the SERVER shares are, so the volume that matters here
is usually not the operating system: an ESXi datastore, an NFS export or a Samba
tree, all of which are ordinary directories in the bodyfile. Nothing in this
handler is Linux-specific beyond the path separator and the directory test, which
is the point -- the artifact differs, the reasoning does not.
"""

from __future__ import annotations

import csv
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _ransom
from artifact_engine.handlers._lincommon import write_csv

_BODYFILE = Path("CSVs") / "Filesystem" / "bodyfile.csv"


def is_directory(mode: str) -> bool:
    """The bodyfile's mode field is `d/drwxr-xr-x` for a directory."""
    tail = (mode or "").split("/")[-1]
    return tail.startswith("d")


def run(ctx) -> None:
    src = Path(ctx.evidence) / _BODYFILE
    if not src.is_file():
        raise HandlerSkip("no bodyfile.csv to read")

    notes, exts = _ransom.load_lists(Path(ctx.assets))
    traces = _ransom.Traces()
    try:
        fh = src.open("r", encoding="utf-8", errors="replace", newline="")
    except OSError as e:
        raise HandlerSkip(f"bodyfile.csv unreadable: {e}") from e
    with fh:
        for row in csv.DictReader(fh):
            if is_directory(row.get("mode") or ""):
                continue
            path = (row.get("name") or "").strip()
            folder, _, name = path.rpartition("/")
            found = _ransom.classify(name or path, notes, exts)
            if found is None:
                continue
            kind, marker, family, reference, double = found
            traces.add(kind, marker, path, folder or "/",
                       row.get("mtime_utc") or "", double, family, reference)

    rows = _ransom.rows(traces)
    if not rows:
        return                                # nothing to say, and no empty table
    write_csv(ctx.out, "ransomware_traces.csv", _ransom.columns(), rows)
