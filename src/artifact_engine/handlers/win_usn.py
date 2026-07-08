"""Handler: NTFS USN change journal ($Extend/$UsnJrnl:$J) via MFTECmd.

KAPE saves $J under $Extend with varying names ($UsnJrnl%3A$J, $UsnJrnl$J, $J...);
find it and let MFTECmd (which auto-detects $J) parse it. Output: usn.csv
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core import procs


def _find_usn(evidence: Path) -> Path | None:
    ext = evidence / "$Extend"
    if ext.is_dir():
        for p in ext.iterdir():
            if p.is_file() and p.name.endswith("$J"):
                return p
    return next((p for p in evidence.rglob("*$J") if p.is_file()), None)


def run(ctx) -> None:
    usn = _find_usn(ctx.evidence)
    if usn is None:  # $Extend present but no journal collected -> nothing to do
        return
    mftecmd = ctx.tools / "MFTECmd" / "MFTECmd.exe"
    if not mftecmd.is_file():
        raise RuntimeError("MFTECmd.exe not found (run 'aeng setup')")
    ctx.out.mkdir(parents=True, exist_ok=True)
    cmd = [str(mftecmd), "-f", str(usn), "--csv", str(ctx.out), "--csvf", "usn.csv"]
    procs.run(cmd, timeout=1800)
