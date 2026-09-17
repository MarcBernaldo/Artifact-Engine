"""Handler: timestamps that disagree with each other ($MFT). Output: timestomp.csv

An attacker who copies a reference file's times onto their own drop (`touch -r`,
`SetMace`, the `timestomp` module in any post-exploitation kit) gets a file whose
mtime is years old. What they cannot set the same way is the record of the change
itself, and NTFS keeps two independent copies of the times:

- `$STANDARD_INFORMATION` -- what every API and every tool shows, and what a
  stomping tool rewrites;
- `$FILE_NAME` -- written by the kernel when the name was created in its parent
  directory, and not settable through the ordinary API.

MFTECmd already computes the comparison and writes it as the `SI<FN` column. It
has been sitting in MFT.csv since the parser was added and nothing has ever read
it. Two more columns come free with it: `uSecZeros` (a whole-second timestamp,
which a real filesystem write essentially never produces) and MFTECmd's `Copied`.

WHY THE LOCATION IS PART OF THE RULE. `SI<FN` is true for a large share of a
healthy Windows volume: an installer that copies files preserving their times
produces exactly that shape, and WinSxS is full of them. Reported on its own it
is a rule, not a finding. So a row is emitted only where a forged timestamp would
buy something -- a writable staging directory, or an executable -- and the flag
needs the writable location AND one of: `SI<FN`, a delta measured in years, or a
second indicator agreeing with the first. An executable in a system directory
still gets its row; what it does not get is the flag.

Nothing is extracted here: MFTECmd has already written MFT.csv by the time this
runs, and every question below is three of its columns.
"""

from __future__ import annotations

import csv
import re
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers._topn import TopN
from artifact_engine.handlers.win_liveresponse_velociraptor import _in_staging

_MFT_CSV = Path("CSVs") / "Filesystem" / "MFT.csv"

# `LastRecordChange0x10` is the $SI record-change time: NTFS's ctime, which the
# ordinary API cannot set. Older than the mtime by this much means the file was
# modified long before the record that describes it changed -- backdating.
_MIN_DELTA_DAYS = 30

# A delta this large stops being an installer preserving build times.
_STRONG_DELTA_DAYS = 365

# Extensions where a forged timestamp is worth forging.
_EXEC = {".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".msi", ".msp", ".cpl",
         ".ocx", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
         ".wsf", ".wsh", ".hta", ".jar", ".lnk"}

# Writable locations the shared staging list does not name. Kept local rather
# than added to `_STAGING`: that tuple is imported by several parsers, and
# widening it would re-fingerprint every one of them for a check only used here.
_EXTRA_WRITABLE = ("\\programdata\\", "\\appdata\\roaming\\", "\\appdata\\local\\",
                   "\\inetpub\\", "\\intel\\", "\\recovery\\")

# Rows written. A stomped volume is the attacker's to inflate, so the table is
# bounded and says so in a row of its own rather than trimming quietly.
_CAP = 2000

_COLUMNS = ["path", "extension", "size", "si_created_utc", "fn_created_utc",
            "mtime_utc", "ctime_utc", "delta_days", "indicators", "location",
            "note", "suspicious"]

_TS = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)")


def _dt(value: str) -> datetime | None:
    m = _TS.match((value or "").strip())
    if not m:
        return None
    try:
        return datetime(*map(int, m.groups()), tzinfo=timezone.utc)
    except ValueError:
        return None


def _true(value: str) -> bool:
    return (value or "").strip().lower() in ("true", "1", "yes")


def writable(path: str) -> bool:
    """A location whose contents an ordinary account can choose."""
    low = "\\" + (path or "").strip().strip("\\").lower() + "\\"
    return _in_staging(path) or any(tok in low for tok in _EXTRA_WRITABLE)


def _row(path: str, ext: str, size: str, times: tuple[str, str, str, str],
         indicators: list[str], delta: int, where: bool, flagged: bool) -> list:
    si_created, fn_created, mtime, ctime = times
    return [path, ext, size, si_created, fn_created, mtime, ctime,
            delta if delta else "", " ".join(indicators),
            "writable" if where else "system", "", "yes" if flagged else ""]


def run(ctx) -> None:
    src = Path(ctx.evidence) / _MFT_CSV
    if not src.is_file():
        raise HandlerSkip("no MFT.csv to read")

    top = TopN(_CAP)
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
        need = ("ParentPath", "FileName", "LastModified0x10", "LastRecordChange0x10")
        if any(k not in idx for k in need):
            raise HandlerSkip("MFT.csv has no $SI timestamp columns")

        def cell(row: list, name: str) -> str:
            i = idx.get(name)
            return row[i] if i is not None and i < len(row) else ""

        for row in reader:
            if _true(cell(row, "IsDirectory")):
                continue
            mtime = _dt(cell(row, "LastModified0x10"))
            ctime = _dt(cell(row, "LastRecordChange0x10"))
            delta = (ctime - mtime).days if mtime and ctime else 0

            indicators = []
            if _true(cell(row, "SI<FN")):
                indicators.append("si_before_fn")
            if delta >= _MIN_DELTA_DAYS:
                indicators.append(f"ctime_{delta}d_after_mtime")
            if _true(cell(row, "uSecZeros")):
                indicators.append("usec_zeros")
            if _true(cell(row, "Copied")):
                indicators.append("copied")
            if not indicators:
                continue

            parent, name = cell(row, "ParentPath"), cell(row, "FileName")
            path = f"{parent}\\{name}" if parent else name
            ext = (cell(row, "Extension") or Path(name).suffix).lower()
            where = writable(path)
            if not where and ext not in _EXEC:
                continue                     # a stomped timestamp buys nothing here

            flagged = where and ("si_before_fn" in indicators
                                 or delta >= _STRONG_DELTA_DAYS
                                 or len(indicators) >= 2)
            times = (cell(row, "Created0x10"), cell(row, "Created0x30"),
                     cell(row, "LastModified0x10"), cell(row, "LastRecordChange0x10"))
            # Rank: flagged first, then the biggest disagreement, then the most
            # indicators.
            top.add((0 if flagged else 1, -delta, -len(indicators)),
                    _row(path, ext, cell(row, "FileSize"), times, indicators,
                         delta, where, flagged))

    rows = top.best()
    if not rows:
        return                                # nothing to say, and no empty table
    if top.dropped:
        rows.append(["(not listed)", "", "", "", "", "", "", "", "cap", "",
                     (f"{top.total:,} file(s) matched; the {len(rows):,} with "
                      f"the largest disagreement are listed"), ""])
    write_csv(ctx.out, "timestomp.csv", _COLUMNS, rows)
