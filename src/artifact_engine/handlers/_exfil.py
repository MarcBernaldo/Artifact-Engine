"""Command lines that look like data leaving the host, by LOLExfil's patterns.

The patterns are the bundled `exfil_lolexfil.yaml` (generated from LOLExfil by
`core/lol_import.py exfil`, each with its regex and its required `literal`).
`scan` takes command lines from wherever a source keeps them -- shell history,
a live process list, a memory image, PowerShell's event logs -- and writes one
table, `exfil_commands`, with the same columns from every source (v0.7.101):
per command line and tool, the most telling of its matches (an exfil action
over staging over the tool merely running).

Since v0.7.104 the text is first reduced to its distinct lines (`collect`): a
script block is searched line by line, each line at most _LINE_CHARS long, and a
line repeated ten thousand times is searched once and reported with its count
and its first and last time. A pattern whose `literal` is not in the line is
not run at all.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

import yaml

from artifact_engine.core.lol_exfil import ASSET, SEVERITY

TABLE = "exfil_commands.csv"
HEADER = ["severity", "tool", "detect_type", "purpose", "source", "who", "command",
          "first_seen_utc", "last_seen_utc", "count", "pattern"]

_RANK = {"high": 0, "medium": 1, "low": 2}
_COMMAND_CHARS = 400
_LINE_CHARS = 2000


class Line(NamedTuple):
    """One distinct command line of one source and account."""
    source: str
    who: str
    text: str
    first_utc: str
    last_utc: str
    count: int


def collect(items) -> list[Line]:
    """`items` yields (source, who, text) or (source, who, text, time_utc); a text may
    hold many lines (a script block). Distinct lines, in first-seen order."""
    seen: dict[tuple, list] = {}
    for item in items:
        source, who, text = item[0], item[1], item[2]
        when = item[3] if len(item) > 3 else ""
        for raw in str(text or "").splitlines():
            line = " ".join(raw.split())[:_LINE_CHARS]
            if not line:
                continue
            key = (source, who, line)
            cur = seen.get(key)
            if cur is None:
                seen[key] = [when, when, 1]
                continue
            cur[2] += 1
            if when and (not cur[0] or when < cur[0]):
                cur[0] = when
            cur[1] = max(cur[1], when)
    return [Line(s, w, t, v[0], v[1], v[2]) for (s, w, t), v in seen.items()]


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
    """`lines` is what `collect` takes, or its result. One row per line and tool."""
    lines = lines if isinstance(lines, list) and all(isinstance(x, Line) for x in lines) \
        else collect(lines)
    rows: list[tuple] = []
    for ln in lines:
        low = ln.text.lower()
        best: dict[str, tuple] = {}
        for e, rx in patterns:
            lit = e.get("literal") or ""
            if lit and lit not in low:
                continue
            if not rx.search(ln.text):
                continue
            sev = SEVERITY.get(e.get("detect_type", ""), "low")
            cur = best.get(e["tool"])
            if cur is None or _RANK[sev] < _RANK[cur[0]]:
                best[e["tool"]] = (sev, e)
        for tool, (sev, e) in best.items():
            rows.append((_RANK[sev], tool, [sev, tool, e.get("detect_type", ""),
                                            e.get("purpose", ""), ln.source, ln.who,
                                            ln.text[:_COMMAND_CHARS], ln.first_utc, ln.last_utc,
                                            ln.count, e.get("pattern", "")]))
    rows.sort(key=lambda r: (r[0], r[1]))
    return [r for _, _, r in rows]
