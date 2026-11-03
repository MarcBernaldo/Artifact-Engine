"""Handler: Program Compatibility Assistant (PCA) app-launch log.

Windows 11 22H2+ records every GUI program launch (including binaries run from a
network share or USB) in:
    Windows/appcompat/pca/PcaAppLaunchDic.txt

The file is pipe-delimited "full path|last execution time". This is an
execution-evidence artifact comparable to Prefetch/Amcache.

Windows writes that time in the HOST'S LOCAL ZONE with no offset in the string,
and it is passed through verbatim -- hence the `last_executed_local` column name.
Resolve what "local" was for that host with `art_machine_info.json`'s timezone; do
NOT compare it to a `_utc` column without converting first.

Output: art_pca.csv

`run_general` reads the service's other two files, PcaGeneralDb0.txt and
PcaGeneralDb1.txt: one line per run it watched, pipe-delimited
"run time|run status|path|description|vendor|version|program id|exit code", the
program id being Amcache's ProgramId and the exit code a sentence ("Abnormal process
exit with code 0x80"). Microsoft does not document the format; the field order is
the community's (aboutdfir.com, 2022), so a line with more or fewer fields is kept
whole in `extra` rather than forced into columns, and the parser records how many
lines it could not split. The run time is written like PcaAppLaunchDic's, in the
same unstated zone, so it takes the same `_local` name. A path is kept as written:
it may start with an environment variable (`%USERPROFILE%`); the doubled
backslashes the file sometimes carries are folded. Output: art_pca_general.csv
"""

from __future__ import annotations

import csv
from pathlib import Path

from artifact_engine.handlers._lincommon import write_csv

_PCA = "Windows/appcompat/pca/PcaAppLaunchDic.txt"


def _read_text(path: Path) -> str:
    """Decode by BOM (PCA files are UTF-16-LE w/ BOM); never guess UTF-16 endianness."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass
    if raw[:3] == b"\xef\xbb\xbf":
        return raw.decode("utf-8-sig", errors="replace")
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def run(ctx) -> None:
    src = ctx.evidence / _PCA
    rows: list[tuple[str, str]] = []
    if src.is_file():
        for line in _read_text(src).splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            path, _, ts = line.rpartition("|")
            rows.append((path.strip(), ts.strip()))

    if not rows:
        return                       # nothing parsed -> no CSV
    ctx.out.mkdir(parents=True, exist_ok=True)
    with open(ctx.out / "art_pca.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["executable_path", "last_executed_local"])
        w.writerows(rows)


_GENERAL = ("PcaGeneralDb0.txt", "PcaGeneralDb1.txt")
GENERAL_HEADER = ["run_time_local", "run_status", "executable_path", "description", "vendor",
                  "version", "program_id", "exit_code", "extra", "file"]
_FIELDS = 8


def run_general(ctx) -> None:
    folder = ctx.evidence / Path(_PCA).parent
    rows, odd = [], 0
    for name in _GENERAL:
        src = folder / name
        if not src.is_file():
            continue
        for line in _read_text(src).splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != _FIELDS:
                odd += 1
                rows.append(["", "", "", "", "", "", "", "", line, name])
                continue
            parts[2] = parts[2].replace("\\\\", "\\")
            rows.append([*parts, "", name])
    if odd and ctx.log:
        ctx.log.warning(f"[!] PCA general: {odd} line(s) without the {_FIELDS} expected fields, "
                        f"kept whole in `extra`")
    write_csv(ctx.out, "art_pca_general.csv", GENERAL_HEADER, rows)
