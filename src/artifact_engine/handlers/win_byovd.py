"""Handler: BYOVD -- known vulnerable/malicious drivers by hash. Output: byovd.csv

"Bring Your Own Vulnerable Driver": attackers load a signed-but-vulnerable (or
outright malicious) kernel driver to get kernel-level code execution and kill EDR.
This matches the SHA1 that Amcache records for every executable/driver seen on the
box against the LOLDrivers hash set (loldrivers.io), bundled as
`data/assets/loldrivers_hashes.json`.

Hash match is exact, so it is essentially FP-free; the `category` tells a confirmed
`malicious` driver apart from a merely `vulnerable` (legitimate but exploitable, and
common on normal systems -- attack surface rather than proof of compromise). The
driver's on-disk name is kept next to the known name so a renamed sample stands out.

Source: Amcache Associated/Unassociated file entries (the .sys drivers there carry a
SHA1). Universal in a KAPE collection, so this runs on every Windows machine.
category: detections. Self-gates (HandlerSkip) when the hash set or Amcache is absent.
"""

from __future__ import annotations

import json
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_rmm import _iter_amcache   # shared Amcache reader


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


def run(ctx) -> None:
    hashes = _load_hashes(Path(ctx.assets))
    if not hashes:
        raise HandlerSkip("no LOLDrivers hash set (loldrivers_hashes.json)")
    base = Path(ctx.evidence)
    if not (base / "CSVs" / "Execution").is_dir():
        raise HandlerSkip("no Amcache output to scan")

    rows: list[list] = []
    seen: set[str] = set()
    for name, fullpath, sha1, first_seen, _src in _iter_amcache(base):
        h = _norm_sha1(sha1)
        info = hashes.get(h)
        if not info or h in seen:
            continue
        seen.add(h)
        rows.append([info.get("c", ""), info.get("n", ""), name, fullpath, h, first_seen])

    # malicious first, then by known driver name
    rows.sort(key=lambda r: (r[0] != "malicious", r[0], r[1]))
    write_csv(ctx.out, "byovd.csv",
              ["category", "known_driver", "amcache_name", "path", "sha1", "first_seen"], rows)
