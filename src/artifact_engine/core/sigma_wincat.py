"""Compile the Sigma categories that are not process_creation, for the Windows tables.

`alert_win_sigma` runs SigmaHQ's rules over what the engine itself parsed: files
(`file_event`, `file_delete`), registry (`registry_set`, `registry_event`,
`registry_add`) and connections (`network_connection`). SigmaHQ's copy that ships
with the engine is converted for hayabusa, which matches EVTX: each rule carries one
extra selection naming the channel (and event id) and a condition written
`<that selection> and <the original condition>`. That selection says where the event
came from, which these tables do not have, so it is taken out and the condition
unwrapped. A condition that cannot be unwrapped without changing its meaning
(`W and a or b` reads `(W and a) or b`; the wrapper named again; an `of` pattern that
would match it) is skipped and counted, never guessed.

The analyst's own rules, `sigma_custom/windows/<category>/`, are plain Sigma and are
compiled as they are.

Kept apart from core/sigma_engine.py and core/sigma_windows.py on purpose: those are
in the import closure of the Linux, web and memory Sigma parsers, so editing them
would re-parse every case they already processed. This module reuses their backend
unchanged.
"""

from __future__ import annotations

import fnmatch
import re
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

import yaml

from artifact_engine.core.sigma_engine import (
    CompiledRule,
    _backend,
    _retable,
    _say_nothing_compiled,
)
from artifact_engine.logging_setup import get_logger

log = get_logger()

# category -> (table name the rules read, hayabusa sub-folder under sigma/sysmon)
CATEGORIES = {
    "file_event": ("file", "file/file_event"),
    "file_delete": ("file", "file/file_delete"),
    "registry_set": ("reg", "registry/registry_set"),
    "registry_event": ("reg", "registry/registry_event"),
    "registry_add": ("reg", "registry/registry_add"),
    "network_connection": ("net", "network_connection"),
}

_WRAPPER_KEYS = {"EventID", "Channel"}
_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class Loaded(NamedTuple):
    rules: tuple[CompiledRule, ...]
    unwrap_skipped: int        # hayabusa rules whose condition could not be unwrapped


def unwrap(rule: dict) -> dict | None:
    """The rule as Sigma wrote it, or None when hayabusa's wrapper cannot be
    taken off without changing what the rule says."""
    det = rule.get("detection")
    if not isinstance(det, dict):
        return None
    wrappers = [k for k, v in det.items()
                if k != "condition" and isinstance(v, dict) and "Channel" in v
                and set(v) <= _WRAPPER_KEYS]
    cond = det.get("condition")
    if len(wrappers) != 1 or not isinstance(cond, str):
        return None
    name = wrappers[0]
    m = re.match(rf"\s*{re.escape(name)}\s+and\s+(.+)\Z", cond, re.DOTALL)
    if not m:
        return None
    rest = m.group(1).strip()
    depth = 0
    tokens = _TOKEN.findall(rest)
    for i, tok in enumerate(tokens):
        if tok == "(":
            depth += 1
        elif tok == ")":
            depth -= 1
        elif depth == 0 and tok.lower() == "or":
            return None                       # `W and a or b`: b would lose W
        if tok == name:
            return None                       # the wrapper used again
        if i and tokens[i - 1].lower() == "of" and fnmatch.fnmatchcase(name, tok):
            return None                       # `1 of pattern` would count it
    if depth != 0 or not tokens:
        return None
    out = dict(rule)
    out["detection"] = {k: v for k, v in det.items() if k != name}
    out["detection"]["condition"] = rest
    return out


def _compile(dicts_or_text, table: str, category: str, be, source: str,
             out: list[CompiledRule]) -> int:
    """Compile one rule file's rules into `out`; the number that failed."""
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaRule
    failed = 0
    try:
        col = (SigmaCollection.from_yaml(dicts_or_text) if isinstance(dicts_or_text, str)
               else SigmaCollection.from_dicts(dicts_or_text))
    except Exception as e:  # noqa: BLE001 - malformed/unparseable rule file
        log.debug(f"sigma-wincat: parse {source}: {e}")
        return 1
    for rule in col.rules:
        if not isinstance(rule, SigmaRule):
            continue
        try:
            for q in be.convert_rule(rule):
                out.append(CompiledRule(
                    title=rule.title or Path(source).stem,
                    level=(rule.level.name.lower() if rule.level else ""),
                    rule_id=str(rule.id) if rule.id else "",
                    tags=",".join(t.name for t in rule.tags) if rule.tags else "",
                    table=table, service="", sql=_retable(q, table), category=category))
        except Exception as e:  # noqa: BLE001 - feature unsupported by backend
            failed += 1
            log.debug(f"sigma-wincat: skip {source}: {e}")
    return failed


@lru_cache(maxsize=16)
def load_category(category: str, custom: Path | None = None,
                  hayabusa_sigma: Path | None = None) -> Loaded:
    """The rules of one category: hayabusa's converted SigmaHQ copy (`hayabusa_sigma`
    is its `rules/sigma/sysmon` folder) unwrapped, plus the analyst's own under
    `custom / "windows" / category`. Cached for the process."""
    table, sub = CATEGORIES[category]
    try:
        be = _backend()
    except ImportError as e:
        log.warning(f"[!] pysigma unusable ({type(e).__name__}: {e}); skipping Sigma over "
                    f"{category}. If it IS installed, the version is incompatible "
                    f"-- pyproject pins >=1.4,<2")
        return Loaded((), 0)
    compiled: list[CompiledRule] = []
    skipped = unwrapped = 0
    if hayabusa_sigma is not None and (Path(hayabusa_sigma) / sub).is_dir():
        for f in sorted((Path(hayabusa_sigma) / sub).rglob("*.yml")):
            try:
                docs = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
            except Exception as e:  # noqa: BLE001
                log.debug(f"sigma-wincat: parse {f.name}: {e}")
                skipped += 1
                continue
            ready = []
            for d in docs:
                if not isinstance(d, dict):
                    continue
                plain = unwrap(d)
                if plain is None:
                    unwrapped += 1
                    log.debug(f"sigma-wincat: {f.name}: condition not unwrappable")
                    continue
                # hayabusa adds bare tags (`sysmon`) pySigma refuses
                plain["tags"] = [t for t in plain.get("tags") or [] if "." in str(t)]
                ready.append(plain)
            if ready:
                skipped += _compile(ready, table, category, be, f.name, compiled)
    if custom is not None:
        for f in sorted((Path(custom) / "windows" / category).rglob("*.yml")):
            try:
                text = f.read_text(encoding="utf-8")
            except OSError:
                continue
            skipped += _compile(text, table, category, be, f.name, compiled)
    _say_nothing_compiled(f"sigma-wincat/{category}", len(compiled), skipped)
    return Loaded(tuple(compiled), unwrapped)
