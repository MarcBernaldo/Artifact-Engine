"""Compile the bundled SigmaHQ Linux ruleset to SQLite queries (pysigma).

Each rule is routed to a target event table by its logsource:
  - service == auditd, or category in process/network/file -> the "auditd" table
  - everything else (product: linux keyword rules)         -> the "syslog" table

The SQLite backend can't do unbound full-text ("keywords") searches, so a small
pipeline maps fieldless values onto the syslog `message` column as substring
(LIKE) matches - the standard Sigma keyword semantics.

Rules that use features the backend doesn't support are skipped, so one unsupported
rule never aborts the batch: each is logged at debug, but a ruleset that compiled
NOTHING is logged as a warning -- that is what the backend and this module falling
out of step looks like, and it leaves the run with no Sigma detection at all.
"""

from __future__ import annotations

import re
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

# A logsource `service` is spliced straight into the generated SQL, and the ruleset
# is refreshed from upstream SigmaHQ -- so it is whitelisted rather than trusted.
# Real service names are daemon names (sshd, cron, auditd, systemd-logind).
_SAFE_SERVICE = re.compile(r"[a-z0-9_.\-]{1,64}")

# Which table a generated query reads. The backend decides how it writes that, and
# it changed under us: up to pySigma-backend-sqlite 1.x every query began
# `SELECT * FROM <TABLE_NAME>`, a placeholder this module substituted, and 2.0.0
# emits `SELECT * FROM logs` instead. The substitution is therefore written
# against the SHAPE of the query rather than against one release's spelling of the
# placeholder -- a query whose FROM still named the backend's own default would
# run against a table no case has, match nothing, and report nothing, which on a
# report reads exactly like a host where nothing happened.
_FROM = re.compile(r"^(SELECT\s+\*\s+FROM\s+)(\S+)", re.IGNORECASE)


def _retable(sql: str, table: str) -> str:
    """The backend's query, reading from `table`. Raises on a shape it cannot
    recognise, so an unusable query is counted and logged instead of stored."""
    if not _FROM.match(sql):
        raise ValueError(f"unrecognised query from the sqlite backend: {sql[:80]!r}")
    return _FROM.sub(lambda m: m.group(1) + table, sql, count=1)


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


def _say_nothing_compiled(what: str, compiled: int, skipped: int) -> None:
    """A ruleset that compiled NOTHING is an event, not a debug line.

    Every rule being skipped means the backend and this module no longer agree on
    anything -- which is what a major release of it did -- and the run that
    follows is a run with no Sigma detection at all. At debug level nobody sees
    that, and a case with zero hits is indistinguishable from a quiet host.
    """
    msg = f"{what}: {compiled} rules compiled, {skipped} skipped"
    if compiled == 0 and skipped:
        log.warning(f"[!] {msg} -- no Sigma detection will run; the installed "
                    f"pysigma/backend pair is not one this build understands")
    else:
        log.debug(msg)


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
        # "not installed" is only one of the two ways to land here. The other is
        # pysigma present but reorganised: the backend reaches into
        # sigma.processing.transformations.base, an internal path, so an upstream
        # move disables every Sigma detection while the message sends the analyst
        # to reinstall something they already have.
        log.warning(f"[!] pysigma unusable ({type(e).__name__}: {e}); skipping Sigma "
                    f"detections. If it IS installed, the version is incompatible -- "
                    f"pyproject pins >=1.4,<2")
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
                    sql = _retable(q, table)
                    # syslog rules that name a service (cron/sshd/...) must only
                    # match that service's lines, else a broad keyword (e.g. cron's
                    # 'REPLACE') matches unrelated daemons. Constrain by `proc`.
                    if table == "syslog" and service:
                        if not _SAFE_SERVICE.fullmatch(service):
                            # `service` is interpolated into SQL, and it comes from a
                            # ruleset refreshed from upstream: a quote in it would
                            # break the query and the rule would be silently counted
                            # as "skipped". Drop the constraint instead, loudly.
                            log.debug(f"sigma: {f.name}: unusable service name "
                                      f"{service!r}; running the rule unconstrained")
                        elif " WHERE " in sql:
                            head, cond = sql.split(" WHERE ", 1)
                            sql = f"{head} WHERE proc LIKE '%{service}%' AND ({cond})"
                        else:
                            # No WHERE means the rule matches every row; without the
                            # service constraint that is every syslog line in the
                            # case. Skip it rather than emit thousands of hits.
                            log.debug(f"sigma: {f.name}: unconditional rule for "
                                      f"service {service!r} skipped (would match all)")
                            continue
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
    _say_nothing_compiled("sigma", len(compiled), skipped)
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
        log.warning(f"[!] pysigma unusable ({type(e).__name__}: {e}); skipping web "
                    f"Sigma detections. If it IS installed, the version is "
                    f"incompatible -- pyproject pins >=1.4,<2")
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
                        sql=_retable(q, "web"),
                    ))
            except Exception as e:  # noqa: BLE001 - feature unsupported by backend
                skipped += 1
                log.debug(f"sigma-web: skip {f.name}: {e}")
    _say_nothing_compiled("sigma-web", len(compiled), skipped)
    return tuple(compiled)
