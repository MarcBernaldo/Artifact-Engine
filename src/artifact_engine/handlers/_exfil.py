"""Command lines that look like data leaving the host, by LOLExfil's patterns.

The patterns are the bundled `exfil_lolexfil.yaml` (generated from LOLExfil by
`core/lol_import.py exfil`, each with its regex). `scan` takes command lines
from wherever a source keeps them -- shell history, a live process list, a
memory image -- and writes one table, `exfil_commands`, with the same columns
from every source (v0.7.101): per command line and tool, the most telling of
its matches (an exfil action over staging over the tool merely running).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from artifact_engine.core.lol_exfil import ASSET, SEVERITY

TABLE = "exfil_commands.csv"
HEADER = ["severity", "tool", "detect_type", "purpose", "source", "who", "command",
          "pattern"]

_RANK = {"high": 0, "medium": 1, "low": 2}
_COMMAND_CHARS = 400


def load(assets: Path) -> list[tuple[dict, re.Pattern]]:
    """The compiled patterns, or [] when the asset is missing or unreadable."""
    p = Path(assets) / ASSET
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    out = []
    for e in data.get("patterns") or []:
        try:
            out.append((e, re.compile(e["regex"], re.IGNORECASE)))
        except (KeyError, TypeError, re.error):
            continue
    return out


def scan(lines, patterns: list[tuple[dict, re.Pattern]]) -> list[list]:
    """`lines` yields (source, who, command). One row per command line and tool."""
    rows: list[tuple] = []
    seen: set[tuple] = set()
    for source, who, command in lines:
        cmd = " ".join(str(command or "").split())
        if not cmd:
            continue
        best: dict[str, tuple] = {}
        for e, rx in patterns:
            if not rx.search(cmd):
                continue
            sev = SEVERITY.get(e.get("detect_type", ""), "low")
            cur = best.get(e["tool"])
            if cur is None or _RANK[sev] < _RANK[cur[0]]:
                best[e["tool"]] = (sev, e)
        for tool, (sev, e) in best.items():
            key = (source, who, cmd, tool)
            if key in seen:
                continue
            seen.add(key)
            rows.append((_RANK[sev], tool, [sev, tool, e.get("detect_type", ""),
                                            e.get("purpose", ""), source, who,
                                            cmd[:_COMMAND_CHARS], e.get("pattern", "")]))
    rows.sort(key=lambda r: (r[0], r[1]))
    return [r for _, _, r in rows]
