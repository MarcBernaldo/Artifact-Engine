"""Handler: YARA scan of high-risk Windows directories. Output: yara.csv

Windows counterpart of lin_yara. Compiles the same rule set (bundled rules plus,
when `aeng setup` fetched it, Florian Roth's signature-base) and scans the
locations an attacker stages payloads in on a KAPE collection: per-user Temp /
Downloads / Desktop / AppData\\Roaming, Windows\\Temp, ProgramData, Public,
$Recycle.Bin and inetpub.

FP / perf discipline: the evidence root also holds THIS tool's own output
(CSVs/, JSONs/, the .db/.xlsx, report.txt) -- we scan only the staging subdirs,
never the root, so the output is never re-scanned or self-matched. Browser and
package caches are pruned (huge, binary, noisy), and anything over the size cap
is skipped (implants/webshells are small). category: detections.

Self-gates (HandlerSkip) when yara-python or the rules are unavailable, or no
target directory has content.
"""

from __future__ import annotations

import os
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv

# Reuse the generic (OS-independent) rule compilation and match helpers.
from artifact_engine.handlers.lin_yara import _compile_rules, _externals_for, _match_ids

_MAX_BYTES = 30_000_000          # implants/webshells are small; skip big blobs

# Staging dirs relative to the evidence (volume) root.
_SCAN_DIRS = ("Windows/Temp", "ProgramData", "Users/Public", "$Recycle.Bin",
              "inetpub", "PerfLogs")
# Plus, for every user under Users/, these subtrees.
_USER_SUBDIRS = ("AppData/Local/Temp", "AppData/Roaming", "Downloads", "Desktop")

# Directory names never worth scanning: this tool's own output, rule repos
# (self-match), and the big binary cache trees that only yield FPs and slow.
_PRUNE_EXACT = {
    "CSVs", "JSONs", "signature-base", "yara", "yara-rules", "sigma",
    "__pycache__", "node_modules", "Cache", "Code Cache", "GPUCache",
    "CacheStorage", "Service Worker", "Crashpad", "ShaderCache", "GrShaderCache",
}
# Compiled/own-output extensions that are never the target.
_SKIP_EXT = {".db", ".xlsx", ".pyc", ".pyo", ".map", ".etl", ".evtx"}


def _scan_roots(base: Path):
    """Existing staging dirs under the evidence root (user homes expanded)."""
    for d in _SCAN_DIRS:
        p = base / d
        if p.is_dir():
            yield p
    users = base / "Users"
    if users.is_dir():
        for user in users.iterdir():
            if not user.is_dir():
                continue
            for sub in _USER_SUBDIRS:
                p = user / sub
                if p.is_dir():
                    yield p


def run(ctx) -> None:
    rules = _compile_rules(ctx.assets, ctx.log)
    base = Path(ctx.evidence)
    roots = list(_scan_roots(base))
    if not roots:
        raise HandlerSkip("no target directory present")

    rows: list[list] = []
    seen: set[str] = set()
    for start in roots:
        for dirpath, dirnames, filenames in os.walk(start):
            dirnames[:] = [d for d in dirnames if d not in _PRUNE_EXACT]
            for fn in filenames:
                if Path(fn).suffix.lower() in _SKIP_EXT:
                    continue
                f = Path(dirpath) / fn
                try:
                    if not f.is_file() or f.is_symlink():
                        continue
                    if f.stat().st_size > _MAX_BYTES:
                        continue
                    rel = f.relative_to(base).as_posix()
                    if rel in seen:            # a user dir can be reached once only, but be safe
                        continue
                    ext = f.suffix.lower().lstrip(".")
                    matches = rules.match(
                        str(f), externals=_externals_for(fn, rel, ext), timeout=60)
                except (OSError, ValueError):
                    continue
                except Exception:  # noqa: BLE001 - yara timeout/error on one file
                    continue
                if not matches:
                    continue
                seen.add(rel)
                size = f.stat().st_size
                for m in matches:
                    rows.append([m.rule, ",".join(m.tags), rel, size, _match_ids(m), "yes"])

    rows.sort(key=lambda r: (r[0], r[2]))
    write_csv(ctx.out, "yara.csv", ["rule", "tags", "file", "size", "strings", "suspicious"], rows)
