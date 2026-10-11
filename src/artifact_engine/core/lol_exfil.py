"""LOLExfil's command-line patterns as regular expressions (v0.7.101).

LOLExfil (https://lolexfil.github.io, MIT) documents 200 tools used to move
data out and, for each, `endpoint_detection_patterns`: what its command line
looks like when it is used for that (`rclone copy * sftp:*|s3:*|mega:*`). They
are written for people, in a loose glob with conventions this module turns into
one regex each:

  *               any run of characters
  a b             tokens in this order, a later one possibly inside a longer
                  word (`curl * ix.io` matches `curl -F f=@x https://ix.io`)
  a|b|c           inside one token: alternatives for that token
  ` | `           with spaces around it: the shell's own pipe, literally
  `(...)` at the end, after a space: the author's comment, dropped
  first token    a bare program name also matches with `.exe` and with a path
                 in front (`rclone copy` matches `C:\\t\\rclone.exe copy`)

Each regex is built to stay cheap on a long script block (v0.7.104): no leading
`.*?` (a lookbehind keeps the whole-word edge), no optional path prefix (the
lookbehind already accepts a backslash or `/` before the name), no `.*` at either
end, and a bare `*` between words is one lazy gap rather than three nested
quantifiers. Each entry also keeps its longest fixed run of characters,
`literal`: a command line without it cannot match, so the regex is not run.
Measured before: 855 patterns took 9.6 s on one 500-character line.

A pattern that is prose rather than a command line (`... via script to
external WebDAV`, `... with requests|urllib and external URL`, `A OR B`) is
not a pattern a command line can match and is left out, as is one with fewer
than _MIN_LITERAL fixed characters -- it would match everything.
"""

from __future__ import annotations

import json
import re

ASSET = "exfil_lolexfil.yaml"
SOURCE_URL = "https://raw.githubusercontent.com/lolexfil/lolexfil.github.io/main/tools.json"

_MIN_LITERAL = 5
# Words that mark a description, not a command line.
_PROSE = re.compile(r"\b(via|with|from|when|after|before|containing|and external|OR)\b")
_COMMENT = re.compile(r"\s+\([^()]*\)\s*$")
# What each detect_type says about a match, as a severity.
SEVERITY = {"exfil_action": "high", "bulk_transfer_or_staging": "medium",
            "remote_destination": "medium", "tool_execution": "low",
            "tool_configuration": "low"}


def _token(tok: str) -> str:
    alts = [a for a in tok.split("|") if a] if "|" in tok else [tok]
    parts = ["".join(".*" if ch == "*" else re.escape(ch) for ch in a) for a in alts]
    return parts[0] if len(parts) == 1 else "(?:" + "|".join(parts) + ")"


_EDGE = r"""(?:^|(?<=[\s\\/"']))"""


def _clean(pattern: str) -> str | None:
    p = _COMMENT.sub("", str(pattern or "").strip())
    if not p or _PROSE.search(p):
        return None
    if len(re.sub(r"[*|\s]", "", p)) < _MIN_LITERAL:
        return None
    return p


def to_regex(pattern: str) -> str | None:
    """The regex for one LOLExfil pattern, or None when it is not one."""
    p = _clean(pattern)
    if p is None:
        return None
    segments = [s.strip() for s in p.split(" | ")]       # the shell's pipe
    out = []
    for si, seg in enumerate(segments):
        toks = seg.split()
        if not toks:
            return None
        body = ""
        gap = ""
        for i, tok in enumerate(toks):
            if tok.strip("*") == "":
                gap = r"\s.*?" if body else ""          # a bare `*`: anything, once
                continue
            rx = _token(tok)
            if i == 0 and si == 0 and "*" not in tok and "\\" not in tok and "/" not in tok \
                    and "|" not in tok and "." not in tok:
                rx = re.escape(tok) + r"(?:\.exe)?"    # a bare program name, `.exe` too
            if body:
                # a later token may sit inside a longer word (`ix.io` in `https://ix.io/x`)
                body += gap or r"\s+\S*?"
            body += rx
            gap = ""
        if not body:
            if si == 0:
                return None
            out.append("")                               # `... | *`: piped into anything
            continue
        if gap and si < len(segments) - 1:
            body += ".*?"                                # `tar * | nc`: anything before the pipe
        out.append(body)
    body = r"\s*\|\s*".join(out)
    while body.endswith(".*"):                           # nothing to find after it
        body = body[:-2]
    if body.startswith(".*"):
        return body[2:] or None                          # floats anyway: no edge to keep
    # anywhere in the command line, whole words at the edges
    return _EDGE + body


def literal(pattern: str) -> str:
    """The longest run of fixed characters every match must contain, lower-case."""
    p = _clean(pattern)
    if p is None:
        return ""
    runs = []
    for tok in p.replace(" | ", " ").split():
        if "|" in tok:
            continue                                     # alternatives: none is required
        runs += [r for r in tok.split("*") if r]
    return max(runs, key=len, default="").lower()


def exfil(catalog: list[dict]) -> list[dict]:
    """[{tool, category, detect_type, purpose, pattern, regex}], usable ones only."""
    out = []
    for t in catalog:
        for p in t.get("endpoint_detection_patterns") or []:
            rx = to_regex(p.get("pattern", ""))
            if rx is None:
                continue
            try:
                re.compile(rx, re.IGNORECASE)
            except re.error:
                continue
            out.append({"tool": str(t.get("name") or "?"), "category": t.get("category") or "",
                        "detect_type": p.get("detect_type") or "",
                        "purpose": str(p.get("purpose") or "")[:200],
                        "pattern": p.get("pattern"), "regex": rx,
                        "literal": literal(p.get("pattern", ""))})
    return out


def entry(e: dict) -> list[str]:
    return [f"  - tool: {json.dumps(e['tool'])}",
            f"    category: {json.dumps(e['category'])}",
            f"    detect_type: {json.dumps(e['detect_type'])}",
            f"    purpose: {json.dumps(e['purpose'], ensure_ascii=False)}",
            f"    pattern: {json.dumps(e['pattern'], ensure_ascii=False)}",
            f"    regex: {json.dumps(e['regex'])}",
            f"    literal: {json.dumps(e['literal'])}"]


def render(entries: list[dict], source_date: str, total: int, blocked=None) -> str:
    blocks = [entry(e) for e in entries]
    kept = [b for b in blocks if not (blocked and blocked("\n".join(b)))]
    lines = [
        "# GENERATED by `python -m artifact_engine.core.lol_import exfil` -- do not edit.",
        f"# Source: LOLExfil, {SOURCE_URL} (retrieved {source_date}).",
        "# LOLExfil is licensed MIT (https://github.com/lolexfil/lolexfil.github.io).",
        f"# {len(kept)} of the catalog's {total} endpoint patterns, as regexes",
        "# (core/lol_exfil.py says which are left out and why).",
    ]
    if len(blocks) != len(kept):
        lines.append(f"# {len(blocks) - len(kept)} pattern(s) left out: they hold a term this "
                     "repository's publication filter blocks.")
    lines.append("patterns:")
    for b in kept:
        lines.extend(b)
    return "\n".join(lines) + "\n"
