"""Handler: detect Remote Monitoring & Management (RMM) tools on disk. Output: rmm.csv

RMM / remote-access tools (AnyDesk, TeamViewer, ScreenConnect, Atera, ...) are
dual-use: legitimate IT software that intruders routinely (ab)use for hands-on
access and persistence. This surfaces every RMM binary the box has seen so the
analyst can confirm whether it is authorised. Tool fingerprints are curated from
LOLRMM (lolrmm.io), bundled in `data/assets/rmm_tools.yaml`.

Source: Amcache (AmcacheParser's Associated/Unassociated file entries) -- the
universal on-disk execution/presence index in a KAPE collection, so this runs on
every Windows machine, including a DC with no live response. Matching is on the
exact executable basename or a specific install-path substring (low FP), and each
hit carries the SHA1 + first-seen time already recorded by Amcache. category:
detections.

Self-gates (HandlerSkip) when the RMM list or the Amcache CSVs are absent.
"""

from __future__ import annotations

import csv
from pathlib import Path

import yaml

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv

# Amcache rows (esp. rich PE metadata) can exceed csv's default field limit.
csv.field_size_limit(10_000_000)

_AMCACHE = ("amcache_AssociatedFileEntries.csv", "amcache_UnassociatedFileEntries.csv")


def _load_rmm(assets: Path) -> list[dict]:
    """Load the curated RMM fingerprints: name + exact filenames + path substrings."""
    p = assets / "rmm_tools.yaml"
    if not p.is_file():
        return []
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    tools = []
    for t in data.get("tools", []):
        files = {f.lower() for f in (t.get("files") or []) if f}
        paths = [s.lower() for s in (t.get("paths") or []) if s]
        if files or paths:
            tools.append({"name": t.get("name") or "?", "files": files, "paths": paths})
    return tools


def _match(name: str, path: str, tools: list[dict]) -> tuple[str, str] | None:
    """(tool, indicator) if the file name / path fingerprints an RMM tool, else None."""
    base = (name or "").strip().lower()
    fp = (path or "").strip().lower()
    if not base and not fp:
        return None
    for t in tools:
        if base and base in t["files"]:
            return t["name"], base
        for sub in t["paths"]:
            if sub and sub in fp:
                return t["name"], sub.strip("\\")
    return None


def _iter_amcache(base: Path):
    """Yield (name, fullpath, sha1, first_seen, source_file) from the Amcache CSVs."""
    exe = base / "CSVs" / "Execution"
    for fname in _AMCACHE:
        p = exe / fname
        if not p.is_file():
            continue
        try:
            with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
                # some Amcache dumps carry stray NUL bytes that csv rejects ("line
                # contains NUL"); strip them per line before parsing.
                reader = csv.DictReader(line.replace("\x00", "") for line in fh)
                for row in reader:
                    yield (row.get("Name") or "", row.get("FullPath") or "",
                           row.get("SHA1") or "",
                           row.get("FileKeyLastWriteTimestamp") or "", fname)
        except (OSError, csv.Error):
            continue


def run(ctx) -> None:
    tools = _load_rmm(Path(ctx.assets))
    if not tools:
        raise HandlerSkip("no RMM tool list (rmm_tools.yaml)")
    base = Path(ctx.evidence)
    if not (base / "CSVs" / "Execution").is_dir():
        raise HandlerSkip("no Amcache output to scan")

    rows: list[list] = []
    seen: set[tuple] = set()
    for name, fullpath, sha1, first_seen, source_file in _iter_amcache(base):
        hit = _match(name, fullpath, tools)
        if not hit:
            continue
        tool, indicator = hit
        key = (tool, fullpath.lower(), sha1.lower())
        if key in seen:                     # Associated + Unassociated may overlap
            continue
        seen.add(key)
        rows.append([tool, "amcache", indicator, fullpath, sha1, first_seen, source_file])

    rows.sort(key=lambda r: (r[0], r[3]))
    write_csv(ctx.out, "rmm.csv",
              ["tool", "source", "match", "path", "sha1", "first_seen", "source_file"], rows)
