"""Compile SigmaHQ's Windows process_creation rules to SQLite (v0.7.94).

The rules are written for process-creation EVENTS (Sysmon 1, Security 4688),
but what they ask about -- the image, its command line, its parent and the
account -- is exactly what a memory image holds for every process still in it.
So they run against a `proc` table built per memory unit (handlers/mem_sigma.py),
one row per process, with the columns named as the Sigma taxonomy names them.

A field memory does not give (OriginalFileName, Hashes, IntegrityLevel, ...) is
a NULL column: a condition on it is never true, and `NOT` of it is NULL too, so
a rule leaning on one can miss but never fires because of it.

Kept apart from core/sigma_engine.py on purpose: that module is in the import
closure of the Linux and web Sigma parsers, so editing it would re-parse every
case they already processed. This one reuses its backend and helpers unchanged.
"""

from __future__ import annotations

from functools import lru_cache

from artifact_engine.config import DATA_DIR
from artifact_engine.core.sigma_engine import (
    CompiledRule,
    _backend,
    _retable,
    _say_nothing_compiled,
)
from artifact_engine.logging_setup import get_logger

log = get_logger()
SIGMA_PROC_DIR = DATA_DIR / "sigma" / "windows_process_creation"
TABLE = "proc"


@lru_cache(maxsize=1)
def load_process_rules() -> tuple[CompiledRule, ...]:
    """Compile every bundled process_creation rule (cached for the process)."""
    if not SIGMA_PROC_DIR.is_dir():
        log.warning(f"[!] Sigma process_creation ruleset not found at {SIGMA_PROC_DIR}")
        return ()
    try:
        from sigma.collection import SigmaCollection
        from sigma.rule import SigmaRule
        be = _backend()
    except ImportError as e:
        log.warning(f"[!] pysigma unusable ({type(e).__name__}: {e}); skipping Sigma over "
                    f"memory processes. If it IS installed, the version is incompatible "
                    f"-- pyproject pins >=1.4,<2")
        return ()
    compiled: list[CompiledRule] = []
    skipped = 0
    for f in sorted(SIGMA_PROC_DIR.glob("*.yml")):
        try:
            col = SigmaCollection.from_yaml(f.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001 - malformed/unparseable rule file
            log.debug(f"sigma-proc: parse {f.name}: {e}")
            continue
        for rule in col.rules:
            if not isinstance(rule, SigmaRule):
                continue
            try:
                for q in be.convert_rule(rule):
                    compiled.append(CompiledRule(
                        title=rule.title or f.stem,
                        level=(rule.level.name.lower() if rule.level else ""),
                        rule_id=str(rule.id) if rule.id else "",
                        tags=",".join(t.name for t in rule.tags) if rule.tags else "",
                        table=TABLE, service="",
                        sql=_retable(q, TABLE),
                    ))
            except Exception as e:  # noqa: BLE001 - feature unsupported by backend
                skipped += 1
                log.debug(f"sigma-proc: skip {f.name}: {e}")
    _say_nothing_compiled("sigma-proc", len(compiled), skipped)
    return tuple(compiled)
