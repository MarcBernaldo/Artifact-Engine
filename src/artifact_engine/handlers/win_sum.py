"""Handler: SUM (User Access Logging) database via SumECmd.

The SUM ESE databases (Windows/System32/LogFiles/SUM/*.mdb) are collected from a
live system in a dirty-shutdown state; SumECmd refuses to parse them (and still
exits 0, so a plain command parser silently produces nothing). We copy them to a
temp dir, recover/repair with esentutl (never touching the evidence), then run
SumECmd. `short: sum` normalizes the output names.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from artifact_engine.core import procs

_SUM = "Windows/System32/LogFiles/SUM"


def _esentutl() -> str:
    found = shutil.which("esentutl")
    if found:
        return found
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "esentutl.exe")


def run(ctx) -> None:
    src = ctx.evidence / _SUM
    if not src.is_dir() or not any(src.glob("*.mdb")):  # no SUM dbs -> nothing to do
        return
    tool = ctx.tools / "SumECmd.exe"
    if not tool.is_file():
        raise RuntimeError("SumECmd.exe not found (run 'aeng setup')")

    ctx.out.mkdir(parents=True, exist_ok=True)
    esentutl = _esentutl()
    with tempfile.TemporaryDirectory(prefix="aeng_sum_") as tmp:
        work = Path(tmp)
        # Copy the whole SUM dir (mdb + edb logs) so repair never touches evidence.
        for f in src.iterdir():
            if f.is_file():
                try:
                    shutil.copy2(f, work / f.name)
                except OSError:
                    pass
        # Soft recovery via the log stream, then hard repair (live dumps are dirty).
        # cwd=work so esentutl's <db>.INTEG.RAW byproducts land in the temp dir.
        procs.run([esentutl, "/r", "edb", "/i", "/l", str(work), "/s", str(work)],
                  timeout=300, cwd=str(work))
        for mdb in work.glob("*.mdb"):
            procs.run([esentutl, "/p", str(mdb), "/o"], timeout=300, cwd=str(work))
        procs.run([str(tool), "-d", str(work), "--csv", str(ctx.out)], timeout=1800, cwd=str(work))
