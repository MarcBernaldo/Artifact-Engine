"""Compile the bundled SigmaHQ Linux ruleset to SQLite queries (pysigma).

Each rule is routed to a target event table by its logsource:
  - service == auditd, or category in process/network/file -> the "auditd" table
  - everything else (product: linux keyword rules)         -> the "syslog" table

The SQLite backend can't do unbound full-text ("keywords") searches, so a small
pipeline maps fieldless values onto the syslog `message` column as substring
(LIKE) matches - the standard Sigma keyword semantics.

Rules that use features the backend doesn't support are skipped (logged at debug),
so one unsupported rule never aborts the batch.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from artifact_engine.config import DATA_DIR
from artifact_engine.logging_setup import get_logger

log = get_logger()
SIGMA_DIR = DATA_DIR / "sigma" / "linux"
SIGMA_WEB_DIR = DATA_DIR / "sigma" / "web"

# Sigma categories whose events come from auditd execve/path/sockaddr records.
_AUDITD_CATEGORIES = {
    "process_creation", "network_connection", "file_event",
    "file_create", "file_delete", "file_change", "file_rename",
}


@dataclass
class CompiledRule:
    title: str
    level: str
    rule_id: str
    tags: str
    table: str    # "auditd" | "syslog"
    service: str  # logsource service (cron/sshd/...), "" if none
    sql: str      # full SELECT with the real table name substituted in


def _backend():
    from sigma.backends.sqlite import sqlite
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations.base import DetectionItemTransformation
    from sigma.types import SigmaString

    class _UnboundToMessage(DetectionItemTransformation):
        """Map a fieldless keyword onto `message` as a substring (LIKE) match."""

        def apply_detection_item(self, di):
            if di.field is None:
                di.field = "message"
                vals = []
                for v in di.value:
                    if isinstance(v, SigmaString):
                        s = str(v)
                        vals.append(v if "*" in s else SigmaString(f"*{s}*"))
                    else:
                        vals.append(v)
                di.value = vals
            return di

    pipe = ProcessingPipeline([ProcessingItem(_UnboundToMessage())])
    return sqlite.sqliteBackend(processing_pipeline=pipe)


def _table_for(rule) -> str:
    ls = rule.logsource
    if (ls.service or "").lower() == "auditd":
        return "auditd"
    if (ls.category or "").lower() in _AUDITD_CATEGORIES:
        return "auditd"
    return "syslog"


@lru_cache(maxsize=1)
def load_rules() -> tuple[CompiledRule, ...]:
    """Load + compile every bundled Linux Sigma rule (cached across machines)."""
    if not SIGMA_DIR.is_dir():
        log.warning(f"[!] Sigma ruleset not found at {SIGMA_DIR}")
        return ()

    try:
        from sigma.collection import SigmaCollection
        from sigma.rule import SigmaRule
        be = _backend()
    except ImportError as e:
        log.warning(f"[!] pysigma not installed ({e}); skipping Sigma detections. "
                    f"Install with: pip install pysigma pysigma-backend-sqlite")
        return ()
    compiled: list[CompiledRule] = []
    skipped = 0
    for f in sorted(SIGMA_DIR.rglob("*.yml")):
        try:
            col = SigmaCollection.from_yaml(f.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001 - malformed/unparseable rule file
            log.debug(f"sigma: parse {f.name}: {e}")
            continue
        for rule in col.rules:
            if not isinstance(rule, SigmaRule):   # skip correlation rules
                continue
            try:
                table = _table_for(rule)
                service = (rule.logsource.service or "").lower()
                for q in be.convert_rule(rule):
                    sql = q.replace("<TABLE_NAME>", table)
                    # syslog rules that name a service (cron/sshd/...) must only
                    # match that service's lines, else a broad keyword (e.g. cron's
                    # 'REPLACE') matches unrelated daemons. Constrain by `proc`.
                    if table == "syslog" and service and " WHERE " in sql:
                        head, cond = sql.split(" WHERE ", 1)
                        sql = f"{head} WHERE proc LIKE '%{service}%' AND ({cond})"
                    compiled.append(CompiledRule(
                        title=rule.title or f.stem,
                        level=(rule.level.name.lower() if rule.level else ""),
                        rule_id=str(rule.id) if rule.id else "",
                        tags=",".join(t.name for t in rule.tags) if rule.tags else "",
                        table=table, service=service,
                        sql=sql,
                    ))
            except Exception as e:  # noqa: BLE001 - feature unsupported by backend
                skipped += 1
                log.debug(f"sigma: skip {f.name}: {e}")
    log.debug(f"sigma: {len(compiled)} rules compiled, {skipped} skipped")
    return tuple(compiled)


@lru_cache(maxsize=1)
def load_web_rules() -> tuple[CompiledRule, ...]:
    """Compile the bundled SigmaHQ web ruleset (rules/web: webserver + proxy).

    All rules run against one `web` table whose columns are named after the Sigma
    webserver/proxy field taxonomy (`cs-method`, `cs-uri-query`, `cs-user-agent`,
    `c-useragent`, `sc-status`, ...) so no field-mapping pipeline is needed -- the
    backend emits those names verbatim (back-quoted). Fieldless `keywords` map onto
    the `message` column (reusing the same pipeline as the Linux rules). Proxy rules
    that reference fields an inbound access log doesn't have (`cs-host`, `c-uri`
    outbound, ...) simply never match; the handler adds any missing column as NULL.
    """
    if not SIGMA_WEB_DIR.is_dir():
        log.warning(f"[!] Sigma web ruleset not found at {SIGMA_WEB_DIR}")
        return ()
    try:
        from sigma.collection import SigmaCollection
        from sigma.rule import SigmaRule
        be = _backend()
    except ImportError as e:
        log.warning(f"[!] pysigma not installed ({e}); skipping web Sigma detections. "
                    f"Install with: pip install pysigma pysigma-backend-sqlite")
        return ()
    compiled: list[CompiledRule] = []
    skipped = 0
    for f in sorted(SIGMA_WEB_DIR.rglob("*.yml")):
        try:
            col = SigmaCollection.from_yaml(f.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001 - malformed/unparseable rule file
            log.debug(f"sigma-web: parse {f.name}: {e}")
            continue
        for rule in col.rules:
            if not isinstance(rule, SigmaRule):   # skip correlation rules
                continue
            # proxy-log rules (category: proxy) exact-match malware default UAs
            # that are also legit old browsers/Googlebot -> heavy FPs on inbound
            # access logs. Only webserver + apache/nginx-service rules apply here.
            if (rule.logsource.category or "").lower() == "proxy":
                continue
            try:
                for q in be.convert_rule(rule):
                    compiled.append(CompiledRule(
                        title=rule.title or f.stem,
                        level=(rule.level.name.lower() if rule.level else ""),
                        rule_id=str(rule.id) if rule.id else "",
                        tags=",".join(t.name for t in rule.tags) if rule.tags else "",
                        table="web", service=(rule.logsource.service or "").lower(),
                        sql=q.replace("<TABLE_NAME>", "web"),
                    ))
            except Exception as e:  # noqa: BLE001 - feature unsupported by backend
                skipped += 1
                log.debug(f"sigma-web: skip {f.name}: {e}")
    log.debug(f"sigma-web: {len(compiled)} rules compiled, {skipped} skipped")
    return tuple(compiled)
