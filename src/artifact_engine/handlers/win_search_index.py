"""Handler: Windows Search index (Windows.edb / Windows.db) via SIDR.

SIDR reads an ESE Windows.edb where it lies, dirty shutdown or not, so that is the
first run: a real one can be gigabytes, and copying it every time would cost more
than the parse. A database with a torn page stops SIDR instead (a panic on "wrong
checksum"). Then the folder is copied to a temp dir, replayed from its MSS logs
and repaired with esentutl there -- never on the evidence -- and SIDR reads the
copy. A repair drops what it cannot mend, so the run log says it happened.

Windows 11's SQLite Windows.db is always read from a copy: SQLite opening a WAL
database writes its -shm (and may checkpoint the -wal) beside it.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

from artifact_engine.core import procs
from artifact_engine.handlers.win_sum import _esentutl

_SEARCH = "ProgramData/Microsoft/Search/Data/Applications/Windows"
# SIDR's reports, anchored on their names: the computer name before them may hold
# underscores of its own.
_REPORT = re.compile(r"_((?:File|Activity_History|Internet_History)_Report)_\d{8}_[\d.]+$")


def _sidr(tool: Path, db_dir: Path, out: Path) -> tuple[int, str]:
    rc, stdout, err = procs.run([str(tool), "-f", "csv", "-r", "to-file", "-o", str(out),
                                 str(db_dir)], timeout=1800)
    said = (err or "").strip() or (stdout or "").strip()
    return rc, said.splitlines()[0][:160] if said else ""


def _clear(out: Path) -> bool:
    """Empty the work dir, keeping it: the runner merges what is left in it."""
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    return not any(out.iterdir())


def _tidy(out: Path) -> None:
    """`<computer>_File_Report_<run time>.csv` -> `File_Report.csv`: a table named
    after the evidence and the clock would change name on every run."""
    for f in list(out.glob("*.csv")):
        m = _REPORT.search(f.stem)
        if m:
            f.replace(out / f"{m.group(1)}.csv")


def _from_copy(tool: Path, src: Path, out: Path) -> tuple[int, str]:
    esentutl = _esentutl()
    with tempfile.TemporaryDirectory(prefix="aeng_search_") as tmp:
        work = Path(tmp) / "Windows"
        shutil.copytree(src, work)
        # /d: the copy, not the path the logs recorded (the analyst's own index).
        # cwd=work so esentutl's <db>.INTEG.RAW byproducts land in the temp dir.
        procs.run([esentutl, "/r", "MSS", "/i", "/l", str(work), "/s", str(work),
                   "/d", str(work)], timeout=900, cwd=str(work))
        for edb in work.rglob("*.edb"):
            procs.run([esentutl, "/p", str(edb), "/o"], timeout=900, cwd=str(work))
        return _sidr(tool, work, out)


def run(ctx) -> None:
    src = ctx.evidence / _SEARCH
    tool = ctx.tools / "sidr.exe"
    if not tool.is_file():
        raise RuntimeError("sidr.exe not found (run 'aeng setup')")
    ctx.out.mkdir(parents=True, exist_ok=True)
    try:
        rc, said = (1, "")
        if not any(src.glob("*.db")):
            rc, said = _sidr(tool, src, ctx.out)
            if rc != 0:
                ctx.log.warning(
                    f"[!] art_search_index: SIDR exit {rc} on the database as collected "
                    f"({said}) - reading a repaired copy; what the repair drops is missing")
                if not _clear(ctx.out):
                    raise RuntimeError("could not clear the first SIDR run's output")
        if rc != 0:
            rc, said = _from_copy(tool, src, ctx.out)
            if rc != 0:
                raise RuntimeError(f"SIDR exit {rc} on the repaired copy: {said}")
    except BaseException:
        _clear(ctx.out)              # a partial table named for the host and clock
        raise
    _tidy(ctx.out)
