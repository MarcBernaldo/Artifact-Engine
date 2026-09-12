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

from artifact_engine.core import evidence, procs

_SUM = "Windows/System32/LogFiles/SUM"


def _esentutl() -> str | None:
    """The ESE repair tool, or None where this host has none.

    Windows-only by construction: it ships with the operating system, is not
    something `aeng setup` can fetch, and has no equivalent elsewhere. The
    `%SystemRoot%` path is a LAST RESORT for a Windows host whose PATH does not
    carry System32 -- unusual, but it happens under service accounts -- and it is
    never returned off Windows, where it would be a path that cannot exist and a
    FileNotFoundError three calls later.
    """
    found = shutil.which("esentutl")
    if found:
        return found
    if os.name != "nt":
        return None
    fallback = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "esentutl.exe"
    return str(fallback) if fallback.is_file() else None


def run(ctx) -> None:
    src = evidence.in_tree(ctx.evidence, _SUM)
    if not src.is_dir() or not evidence.iglob(src, "*.mdb"):  # no SUM dbs -> nothing to do
        return
    # Both tools through the one resolver, like every other parser (see win_usn).
    if ctx.tool is None or not ctx.tool.ok:
        raise RuntimeError(ctx.tool.reason if ctx.tool else "SumECmd is not declared")

    ctx.out.mkdir(parents=True, exist_ok=True)
    esentutl = _esentutl()
    if esentutl is None:
        # Not a skip. The databases ARE here and they are readable -- by a host
        # that can repair them. Skipping would put this in the same count as "no
        # SUM database on this machine", which is a statement about the evidence
        # and not about the installation.
        raise RuntimeError("esentutl is not available on this host: the SUM databases "
                           "are collected in a dirty state and SumECmd reads them as "
                           "empty rather than failing")
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
        procs.run([*ctx.tool.argv, "-d", str(work), "--csv", str(ctx.out)],
                  timeout=1800, cwd=str(work))
