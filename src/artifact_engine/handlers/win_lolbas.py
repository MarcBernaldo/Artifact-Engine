"""Handler: LOLBAS binaries relocated into a staging dir. Output: lolbas.csv

A LOLBAS binary (certutil, mshta, regsvr32, msbuild, ...) is a legitimate Windows
executable that belongs in System32 / WinSxS / the .NET dirs. A COPY of one sitting
in a user- or attacker-writable staging dir (\\Temp\\, \\Downloads\\, Public,
$Recycle.Bin, ...) is a masquerade / relocation -- running the LOLBIN from a
writable location to dodge path-based rules (T1036). This surfaces those via Amcache
(name + on-disk path).

In-place LOLBIN abuse (the real binary with malicious arguments) is a different
signal, handled live by the LiveResponse command-line check; this is its on-disk,
universal counterpart. Binary list bundled from LOLBAS (lolbas-project.github.io).
category: detections. Self-gates (HandlerSkip) when the list or Amcache is absent.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_liveresponse_velociraptor import _in_staging
from artifact_engine.handlers.win_rmm import _iter_amcache   # shared Amcache reader


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


def run(ctx) -> None:
    lolbas = _load_lolbas(Path(ctx.assets))
    if not lolbas:
        raise HandlerSkip("no LOLBAS list (lolbas.yaml)")
    base = Path(ctx.evidence)
    if not (base / "CSVs" / "Execution").is_dir():
        raise HandlerSkip("no Amcache output to scan")

    rows: list[list] = []
    seen: set[str] = set()
    for name, fullpath, sha1, first_seen, _src in _iter_amcache(base):
        base_name = (name or Path(fullpath).name).strip().lower()
        if base_name not in lolbas or not _in_staging(fullpath):
            continue
        key = fullpath.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append([base_name, fullpath, sha1, first_seen])

    rows.sort(key=lambda r: (r[0], r[1]))
    write_csv(ctx.out, "lolbas.csv", ["binary", "path", "sha1", "first_seen"], rows)
