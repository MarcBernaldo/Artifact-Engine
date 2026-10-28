"""The RMM / remote-access / tunnel catalog: which file names and install folders
name a tool. Searched by `win_exec_hunt` (v0.7.103), which writes alert_rmm.csv.

RMM / remote-access tools (AnyDesk, TeamViewer, ScreenConnect, Atera, ...) are
dual-use: legitimate IT software that intruders routinely (ab)use for hands-on
access and persistence. This surfaces every RMM binary the box has seen so the
analyst can confirm whether it is authorised. Tool fingerprints come from LOLRMM
(lolrmm.io): a hand-curated list in `data/assets/rmm_tools.yaml`, read first, and
the whole catalog generated into `rmm_lolrmm.yaml` by `core/lol_import.py`
(v0.7.100) -- about 300 tools instead of 39. Tunnelling tools (ngrok, cloudflared,
chisel...) come from LOTTunnels' list, which `aeng setup` / `update` write to
`assets/lottunnels/` because its licence keeps it out of the package (v0.7.102).

Matching is on the exact executable basename or a specific install-path
substring (low FP). Until v0.7.103 this module also read Amcache itself; the
search now covers every execution artifact (`_execution`), once, for every
catalog.
"""

from __future__ import annotations

from pathlib import Path

import yaml

# Read in this order: the first list to fingerprint a file names the tool.
_LISTS = ("rmm_tools.yaml", "rmm_lolrmm.yaml", "lottunnels/tunnels.yaml")


def _load_rmm(assets: Path) -> list[dict]:
    """The RMM fingerprints: name + exact filenames + path substrings, from the
    curated list then the generated catalog."""
    tools = []
    for name in _LISTS:
        p = assets / name
        if not p.is_file():
            continue
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        for t in data.get("tools", []) or []:
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
