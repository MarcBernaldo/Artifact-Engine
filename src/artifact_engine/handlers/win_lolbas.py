"""The LOLBAS catalog: binaries that are suspect outside their home. Searched by
`win_exec_hunt` (v0.7.103), which writes alert_lolbas.csv.

A LOLBAS binary (certutil, mshta, regsvr32, msbuild, ...) is a legitimate Windows
executable that belongs in System32 / WinSxS / the .NET dirs. A COPY of one sitting
in a user- or attacker-writable staging dir (\\Temp\\, \\Downloads\\, Public,
$Recycle.Bin, ...) is a masquerade / relocation -- running the LOLBIN from a
writable location to dodge path-based rules (T1036). `win_exec_hunt` surfaces those
from every execution artifact that keeps a path.

In-place LOLBIN abuse (the real binary with malicious arguments) is a different
signal, handled live by the LiveResponse command-line check; this is its on-disk,
universal counterpart. Binary list bundled from LOLBAS (lolbas-project.github.io).
"""

from __future__ import annotations

from pathlib import Path

import yaml


def _load_lolbas(assets: Path) -> set[str]:
    """Set of LOLBAS executable basenames (lower-case) from the bundled list."""
    p = assets / "lolbas.yaml"
    if not p.is_file():
        return set()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return set()
    return {b.lower() for b in (data.get("binaries") or []) if b}
