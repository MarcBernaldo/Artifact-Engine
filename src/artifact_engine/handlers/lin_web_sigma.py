"""Handler: run the bundled SigmaHQ web ruleset over access logs. Output: web_sigma.csv

Same access logs as web_access (Apache/nginx, current+rotated+per-vhost,
and the loose `weblogs[-label]` drop), but scored with the SigmaHQ `rules/web`
ruleset (webserver_generic + apache/nginx + proxy_generic) via pysigma.

Each request a rule could match is loaded into an in-memory `web` table (v0.7.109:
`core/sigma_prefilter.py` drops the rest, and a rule it cannot read sees every
request) whose columns are named after the Sigma webserver/proxy field taxonomy (`cs-method`, `cs-uri-query`,
`cs-user-agent`, `c-useragent`, `sc-status`, ...), so the compiled rule SQL matches
directly (see core.sigma_engine.load_web_rules). Fieldless `keywords` match the
`message` column, set to the raw request URI (path?query) -- the rules already list
both URL-encoded and decoded payload variants, so the log is matched as-is.

Rows are streamed in batches (bounded memory on multi-GB logs) and matches are
aggregated to ONE row per (rule, client IP): hit count, first/last seen, a sample
URI, and the offline IP origin (country + Tor/hosting tag) -- the actionable unit
for web triage is "rule X fired N times from source Y", not every scanner request
(every request is in web_access).

THE ANALYST'S OWN INDICATORS (v0.7.170). `assets/web_suspicious.txt` -- scanner
User-Agents, web-shell names, backup leaks, CVE fingerprints no Sigma rule has --
was read by `web_hunt`, a second engine over the same requests, which is gone. Its
lines are rules here now: a hit is a row like a Sigma one, rule
`web_suspicious.txt: <label>`, level medium. A path or query counts on a SERVED
(200) request only -- a probe the server refused is not a finding -- and a
User-Agent, who is asking, at any status (v0.7.144 rules, unchanged).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import NamedTuple

from artifact_engine.core.regex_literals import LiteralGate
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.core.sigma_engine import load_web_rules
from artifact_engine.core.sigma_prefilter import Gate, necessary
from artifact_engine.handlers._indicators import combined, load_indicators, match_labels
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers._webcommon import Geo, decode, iter_records
from artifact_engine.handlers.lin_sigma import _run_rule

_HEADER = ["level", "rule", "mitre", "hits", "first_seen", "last_seen", "ip",
           "country", "origin", "asn", "method", "status", "sample_uri", "ua",
           "rule_id", "source"]

# Flush the in-memory table every N parsed requests so a multi-GB access log
# never has to be held whole (matches are aggregated across batches).
_BATCH = 100_000

# The `web` table columns, in a stable CREATE/INSERT order. The first group is the
# Sigma webserver/proxy field taxonomy the rules query (named exactly so the
# back-quoted rule SQL binds straight to them); the `x_*` group is per-request
# metadata carried only so a matched row can be read back for the output (no rule
# references it). Rules naming a field we don't populate (cs-host, outbound c-uri,
# c-uri-extension, ...) get the column added as NULL on demand by _run_rule.
_COLS = ("cs-method", "cs-uri", "cs-uri-stem", "cs-uri-query", "c-uri",
         "c-uri-query", "c-uri-extension", "cs-user-agent", "c-useragent",
         "cs-referer", "cs-host", "cs-cookie", "sc-status", "message",
         "x_time", "x_ip", "x_uri", "x_ua", "x_method", "x_status", "x_source")
_X_URI = _COLS.index("x_uri")


# What a web_suspicious.txt line becomes: a rule as the output reads one.
class _Indicator(NamedTuple):
    title: str
    level: str = "medium"
    tags: str = ""
    rule_id: str = ""


class _Indicators:
    """`labels(rec)` -> the web_suspicious.txt labels this request hits."""

    def __init__(self, assets) -> None:
        self.rules = load_indicators(Path(assets) / "web_suspicious.txt")
        # a cheap pre-check of the fixed text the regexes need (v0.7.110)
        self.gate = LiteralGate([rx for _, rx in self.rules], combined(self.rules))
        self.made: dict[str, _Indicator] = {}

    def rule(self, label: str) -> _Indicator:
        r = self.made.get(label)
        if r is None:
            r = self.made[label] = _Indicator(f"web_suspicious.txt: {label}")
        return r

    def labels(self, rec) -> list[str]:
        if not self.rules:
            return []
        # the UA and the URI apart, so an indicator's `$` is the end of either
        hit_ua = self.gate(rec.ua or "")
        hit_uri = rec.status == "200" and self.gate(
            rec.path + ("?" + rec.query if rec.query else ""))
        if not (hit_ua or hit_uri):
            return []
        out = match_labels(self.rules, (rec.ua or "").lower()) if hit_ua else []
        if hit_uri:
            uri = decode(rec.path) + ("?" + decode(rec.query) if rec.query else "")
            out += [x for x in match_labels(self.rules, uri) if x not in out]
        return out


def _fold(agg: dict, r, ip: str, t: str, seen: dict) -> None:
    """One match of rule `r` from `ip` at `t`; `seen` is the matched row's fields
    (uri, ua, method, status, source), kept for the first match only."""
    key = (r.rule_id or r.title, ip)
    a = agg.get(key)
    if a is None:
        agg[key] = {"rule": r, "ip": ip, "hits": 1, "first": t, "last": t, **seen}
        return
    a["hits"] += 1
    if t and (not a["first"] or t < a["first"]):
        a["first"] = t
    if t and t > a["last"]:
        a["last"] = t


def _ext(path: str) -> str | None:
    """File extension of the requested path (no dot, lowercase), or None."""
    seg = path.rsplit("/", 1)[-1]
    if "." in seg:
        return seg.rsplit(".", 1)[-1].lower() or None
    return None


def _row(rec, src: str) -> list:
    """Map a parsed access-log Record onto the `_COLS` columns.

    Absent/`-` User-Agent and Referer become NULL (so the `IS NULL` filters in
    e.g. the ReGeorg rule work); status is stored as an INTEGER so `sc-status=404`
    comparisons match; the URI is kept raw (rules carry the encoded payloads)."""
    uri = rec.path + ("?" + rec.query if rec.query else "")
    ua = rec.ua if (rec.ua and rec.ua != "-") else None
    ref = rec.referer if (rec.referer and rec.referer != "-") else None
    q = rec.query or None
    status = int(rec.status) if rec.status.isdigit() else None
    return [rec.method or None, uri, rec.path or None, q, uri, q, _ext(rec.path),
            ua, ua, ref, None, None, status, uri,
            rec.time, rec.ip, uri, (rec.ua or ""), (rec.method or ""),
            (rec.status or ""), src]


def _scan(batch: list[list], rules, agg: dict) -> None:
    """Run every web rule over one batch; fold matches into `agg` keyed by
    (rule id, client IP)."""
    q = lambda c: "`" + c + "`"      # backtick like the compiled rule SQL
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute(f"CREATE TABLE web ({', '.join(q(c) for c in _COLS)})")
        conn.executemany(
            f"INSERT INTO web ({', '.join(q(c) for c in _COLS)}) "
            f"VALUES ({', '.join(['?'] * len(_COLS))})", batch)
        for r in rules:
            cols, matches = _run_rule(conn, r.sql)
            if not matches:
                continue
            idx = {c: i for i, c in enumerate(cols)}
            for row in matches:
                ip = row[idx["x_ip"]] or "" if "x_ip" in idx else ""
                t = row[idx["x_time"]] if "x_time" in idx else ""
                _fold(agg, r, ip, t, {
                    "uri": row[idx["x_uri"]] if "x_uri" in idx else "",
                    "ua": row[idx["x_ua"]] if "x_ua" in idx else "",
                    "method": row[idx["x_method"]] if "x_method" in idx else "",
                    "status": row[idx["x_status"]] if "x_status" in idx else "",
                    "source": row[idx["x_source"]] if "x_source" in idx else "",
                })
    finally:
        conn.close()


def run(ctx) -> None:
    records = iter_records(ctx)
    rules = load_web_rules()
    own = _Indicators(ctx.assets)
    if not rules and not own.rules:
        raise HandlerSkip("no web Sigma rules available")

    # Rows no rule could match never enter the table (v0.7.109). What each rule
    # needs is read from its own compiled SQL (core/sigma_prefilter.py); a rule
    # it cannot read sees every row, as before.
    needs = [necessary(r.sql, _COLS) for r in rules]
    gated = [r for r, n in zip(rules, needs) if n is not None]
    ungated = [r for r, n in zip(rules, needs) if n is None]
    gate = Gate([n for n in needs if n is not None], {c: i for i, c in enumerate(_COLS)})
    if ungated and ctx.log is not None:
        ctx.log.debug(f"web_sigma: {len(ungated)} rule(s) read every request: "
                      + ", ".join(r.title for r in ungated))

    agg: dict = {}
    batch: list[list] = []          # rows a gated rule could match
    every: list[list] = []          # every row, only while a rule needs them all

    def flush():
        if batch:
            _scan(batch, gated, agg)
            batch.clear()
        if every:
            _scan(every, ungated, agg)
            every.clear()

    for rec, src in records:
        row = _row(rec, src)
        for label in own.labels(rec):
            _fold(agg, own.rule(label), rec.ip or "", rec.time, {
                "uri": row[_X_URI], "ua": rec.ua or "", "method": rec.method or "",
                "status": rec.status or "", "source": src})
        if ungated:
            every.append(row)
        if gated and gate(row):
            batch.append(row)
        if len(batch) >= _BATCH or len(every) >= _BATCH:
            flush()
    flush()

    geo = Geo(ctx.assets)
    geo_cache: dict[str, tuple[str, str, str]] = {}
    rows: list[list] = []
    for a in agg.values():
        r = a["rule"]
        ip = a["ip"] or ""
        gi = geo_cache.get(ip)
        if gi is None:
            gi = geo.lookup(ip) if ip else ("?", "unknown", "")
            geo_cache[ip] = gi
        country, origin, asn = gi
        rows.append([r.level, r.title, r.tags, a["hits"], a["first"], a["last"],
                     ip, country, origin, asn, a["method"], a["status"],
                     a["uri"][:300], (a["ua"] or "")[:200], r.rule_id, a["source"]])

    # most severe first, then most hits within a level
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rows.sort(key=lambda x: (_order.get(x[0], 9), -x[3]))
    write_csv(ctx.out, "web_sigma.csv", _HEADER, rows)
