"""The LOLDrivers catalog: known vulnerable/malicious drivers by hash. Searched by
`win_exec_hunt` (v0.7.103), which writes byovd.csv.

"Bring Your Own Vulnerable Driver": attackers load a signed-but-vulnerable (or
outright malicious) kernel driver to get kernel-level code execution and kill EDR.
This matches the SHA1 that Amcache records for every executable/driver seen on the
box against the LOLDrivers hash set (loldrivers.io), bundled as
`data/assets/loldrivers_hashes.json`.

Hash match is exact, so it is essentially FP-free; the `category` tells a confirmed
`malicious` driver apart from a merely `vulnerable` (legitimate but exploitable, and
common on normal systems -- attack surface rather than proof of compromise). The
driver's on-disk name is kept next to the known name so a renamed sample stands out.

Source: Amcache Associated/Unassociated file entries -- the only execution
artifact that records a SHA1, and universal in a KAPE collection.
"""

from __future__ import annotations

import json
from pathlib import Path


def _load_hashes(assets: Path) -> dict:
    """Load {hash(lower): {"n": name, "c": category}} from the bundled LOLDrivers set."""
    p = assets / "loldrivers_hashes.json"
    if not p.is_file():
        return {}
    try:
        return (json.loads(p.read_text(encoding="utf-8")) or {}).get("hashes", {})
    except (OSError, ValueError):
        return {}


def _norm_sha1(v: str) -> str:
    v = (v or "").strip().lower()
    if len(v) == 44 and v.startswith("0000"):   # some Amcache SHA1 carry a 4-char prefix
        v = v[4:]
    return v
