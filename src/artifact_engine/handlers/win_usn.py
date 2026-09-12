"""Handler: NTFS USN change journal ($Extend/$UsnJrnl:$J) via MFTECmd.

KAPE saves $J under $Extend with varying names ($UsnJrnl%3A$J, $UsnJrnl$J, $J...);
find it and let MFTECmd (which auto-detects $J) parse it. Output: usn.csv
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core import evidence as ev
from artifact_engine.core import procs


def _find_usn(evidence: Path) -> Path | None:
    ext = ev.in_tree(evidence, "$Extend")
    if ext.is_dir():
        for p in ext.iterdir():
            if p.is_file() and p.name.endswith("$J"):
                return p
    return next((p for p in ev.iglob(evidence, "**/*$J") if p.is_file()), None)


def run(ctx) -> None:
    usn = _find_usn(ctx.evidence)
    if usn is None:  # $Extend present but no journal collected -> nothing to do
        return
    # The manifest declares MFTECmd and `core/toolchain` decides how to start it,
    # exactly as it does for the command parsers -- this used to join `ctx.tools`
    # to the `.exe` by hand, which is the Windows apphost and nothing else. On a
    # host that runs the assembly through `dotnet`, `aeng preflight` reported the
    # tool as available and then this failed on it.
    if ctx.tool is None or not ctx.tool.ok:
        raise RuntimeError(ctx.tool.reason if ctx.tool else "MFTECmd is not declared")
    ctx.out.mkdir(parents=True, exist_ok=True)
    cmd = [*ctx.tool.argv, "-f", str(usn), "--csv", str(ctx.out), "--csvf", "usn.csv"]
    procs.run(cmd, timeout=1800)
