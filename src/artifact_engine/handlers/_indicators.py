"""User-editable indicator lists (assets/*.txt).

A plain-text list the analyst can grow without touching code -- one indicator
per line, matched as a case-insensitive regex against a decoded haystack:

    # comment, and blank lines, are ignored
    sqlmap                      <- plain substring (label = the text itself)
    scanner_ua = nikto|nuclei   <- label = regex  (the label is the category)
    pat = x|y      # note      <- a trailing comment (2+ spaces then "# ") is
                                  stripped; a '#' inside the pattern is kept

A line with `=` gives an explicit label (the category shown in the output);
otherwise the line is both the pattern and its own label. A bad regex is warned
about and skipped, never aborts the load. The bundled starter files are
versioned; edits/additions survive because they are read at run time.

Shared by the web hunt today; any handler can load its own list the same way.
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.logging_setup import get_logger

log = get_logger()


def load_indicators(path: Path) -> list[tuple[str, re.Pattern]]:
    """Parse an indicator file into (label, compiled_regex) pairs ([] if absent)."""
    rules: list[tuple[str, re.Pattern]] = []
    if not path.is_file():
        return rules
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        # Trailing inline comment: 2+ spaces, then "# ". Conservative on purpose
        # so a '#' INSIDE a pattern (e.g. OGNL's #context) is never touched.
        s = re.sub(r"\s{2,}#\s.*$", "", s).strip()
        label, sep, pat = s.partition("=")
        label, pat = (label.strip(), pat.strip()) if sep else (s, s)
        if not pat:
            continue
        try:
            rules.append((label, re.compile(pat, re.IGNORECASE)))
        except re.error as e:
            log.warning(f"[!] {path.name}: bad indicator regex {s!r} ({e})")
    return rules


def combined(rules: list[tuple[str, re.Pattern]]) -> re.Pattern | None:
    """One alternation regex over all patterns for a cheap raw-line pre-check,
    or None if there are no rules / they can't be combined (callers then match
    each rule individually)."""
    if not rules:
        return None
    try:
        return re.compile("|".join(f"(?:{r.pattern})" for _, r in rules), re.IGNORECASE)
    except re.error:
        return None


def match_labels(rules: list[tuple[str, re.Pattern]], haystack: str) -> list[str]:
    """Distinct labels whose pattern matches the haystack (in file order)."""
    out: list[str] = []
    for label, rx in rules:
        if label not in out and rx.search(haystack):
            out.append(label)
    return out
