"""Handler: web access-log security metrics. Outputs: web_ip_stats.csv,
web_404_paths.csv, web_auth_fail.csv

The ready-made audit queries an analyst would otherwise run by hand over the
access logs (`awk '{print $1}' | sort | uniq -c | sort -nr` and friends),
computed in one streaming pass over the same requests as `web_access` (or,
for a large timeline, in slices merged to the same result -- see `_Tally`):

  - web_ip_stats.csv   one row per source IP: volume, status breakdown,
                       distinct paths, odd HTTP methods (PUT/PROPFIND/TRACE...),
                       payload hits (huntweb's signatures -- ANY status, so
                       probes count here too), MB served, first/last seen and
                       the offline origin. Sorted by volume: scanners and
                       brute-forcers float to the top.
  - web_404_paths.csv  404 target ranking: what the recon was looking for.
                       Kept when hit >= 3 times or the path is sensitive
                       (wp-login, /.env, /.git, phpmyadmin, backups, ...).
  - web_auth_fail.csv  401/403 clusters per (ip, path): credential stuffing,
                       brute force and permission probing.

Plus `web_metrics.html` at the machine root: a self-contained interactive
panel (world map, timeline, volume/error scatter, cross-filtered IP table --
see handlers/_web_report.py) built from the same counts.

`web_access` stays the raw record and `huntweb` the payload-level detail; this
is the statistics layer that tells the analyst WHERE to pivot first.
"""

from __future__ import annotations

import re
import sys
import time
from collections import Counter
from heapq import nlargest
from operator import itemgetter
from pathlib import Path

from artifact_engine.handlers import _web_report, _webshard
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers._webcommon import Geo, decode, iter_records
from artifact_engine.handlers._webrules import classify, prefilter

_IP_HEADER = ["ip", "country", "origin", "asn", "requests", "s2xx", "s3xx",
              "s401", "s403", "s404", "s4xx", "s5xx", "mb_sent", "paths",
              "odd_methods", "attack_hits", "first_seen", "last_seen",
              "suspicious"]
_404_HEADER = ["path", "count", "distinct_ips", "suspicious"]
_AUTH_HEADER = ["ip", "path", "s401", "s403", "total", "first_seen",
                "last_seen", "suspicious"]

# Everything else (PUT/DELETE/PROPFIND/TRACE/CONNECT/PATCH, TLS-in-plain-HTTP
# garbage, ...) is recon/abuse-shaped and worth surfacing per IP. "?" is the
# method-less placeholder (malformed request field), not an odd method.
_NORMAL_METHODS = {"GET", "HEAD", "POST", "OPTIONS", "", "?"}

# Endpoints attackers probe for; matched on the DECODED lowercase path, used to
# keep/flag rows in the 404 and auth-failure views (low FP cost there -- these
# are error responses, not normal traffic).
_SENSITIVE = re.compile(
    r"wp-login\.php|xmlrpc\.php|/\.env\b|/\.git\b|/\.svn\b|/\.aws\b|/\.ssh\b|"
    r"phpmyadmin|adminer|phpinfo|/wp-admin\b|/administrator\b|/admin\b|"
    r"/setup\b|/config|web\.config|\.htaccess|\.htpasswd|id_rsa|/etc/passwd|"
    r"/server-status\b|/actuator\b|/console\b|/cgi-bin/|"
    r"\.(sql|bak|old|backup|tar|tgz|gz|zip|7z|rar)\b")

_MIN_404 = 3          # unrepeated non-sensitive 404s are just noise
_AUTH_IP_CLUSTER = 20  # 401+403 per IP that smells like brute/stuffing...
_AUTH_RATIO = 0.10     # ...IF they are also a real share of its traffic
_AUTH_ROW_CLUSTER = 10  # same, per (ip, path) row
_SCAN_404 = 50        # 404s per IP that smells like a scanner...
_SCAN_RATIO = 0.25     # ...same: a busy proxy hits dead links too
_PATH_CAP = 5000      # distinct-path sets are capped (wordlist scans)


_SAMPLES = 5     # attack-payload samples kept per IP (for the HTML detail)
_IP_404_CAP = 1500  # distinct 404 paths tracked per IP (wordlist scans)

# Ceilings on the number of DISTINCT keys tracked. Everything per IP was already
# bounded, but the top-level accumulators were not -- and their keys are supplied by
# whoever hits the server: one `_IpStat` per client IP, one entry per 404 path, per
# user-agent, per (ip, path) auth pair. A months-long log from a public site, or a
# scanner rotating its UA on every request, grows those without limit; on a web case
# the logs ARE the evidence and they are the biggest thing we parse.
# Past a ceiling an unseen key stops being tracked while known keys keep counting,
# so the cap only ever costs the long tail -- and how much it cost is reported, never
# swallowed. `_MAX_IPS` dominates: an `_IpStat` carries seven counts and a set.
#
# The number is measured, not guessed. A one-request source -- the shape of the
# long tail these ceilings exist for -- costs ~1.8 KB including its dict key, and a
# busy one ~2.9 KB. A real public-site case here produced 619k distinct sources from
# one drop, so a 250k ceiling would have thrown away 60% of the ranking on evidence
# the tool had already handled; 1M keeps that case whole at ~1.8 GB worst case and
# still stops a genuinely unbounded log. Trade it against the analyst box's RAM.
_MAX_IPS = 1_000_000
_MAX_404_PATHS = 200_000
_MAX_UAS = 100_000
_MAX_AUTH_ROWS = 200_000
# The smaller ceilings, named so the merge (below) and its tests use the same ones.
_MAX_PATHS = 200_000    # global top requested paths
_MAX_QUERIES = 100_000  # global top query strings
_UA_IPS = 2000          # distinct IPs counted per user-agent
_404_IPS = 1000         # distinct IPs counted per 404 path
_IP_PATHS = 400         # per IP: own paths, for the HTML
_IP_UAS = 20            # per IP: own user-agents
_IP_QUERIES = 30        # per IP: own query strings


class _Count(dict):
    """A Counter for the per-IP tallies: `c[k] += 1` on a new key starts at 0.
    Hundreds of thousands are made, and `Counter()` runs Python code to make
    each one (~2.5 us) and again to unpickle it from a slice (v0.7.112)."""
    __slots__ = ()

    def __missing__(self, key):
        return 0


def _top(c: dict, n: int) -> list[tuple]:
    """`Counter.most_common(n)`: `heapq.nlargest` over the items by count,
    documented as equivalent to `sorted(..., reverse=True)[:n]` -- which is the
    faster of the two for the few entries most IPs have."""
    if len(c) > 32:
        return nlargest(n, c.items(), key=itemgetter(1))
    return sorted(c.items(), key=itemgetter(1), reverse=True)[:n]


def _t(s: str, n: int) -> str:
    """Truncate for the HTML embed (full values stay in the CSVs)."""
    return s if len(s) <= n else s[: n - 1] + "…"


class _IpStat:
    # Grouped by meaning, not sorted: the status buckets belong next to each other
    # (alphabetical puts s4xx/s5xx before s401/s403/s404).
    __slots__ = ("requests", "s2xx", "s3xx", "s401", "s403", "s404", "s4xx",  # noqa: RUF023
                 "s5xx", "size", "paths", "capped", "methods", "attack",
                 "first", "last", "days", "samples", "p404", "allm", "tp",
                 "uas", "qs")

    def __init__(self):
        self.requests = 0
        self.s2xx = self.s3xx = self.s401 = self.s403 = self.s404 = 0
        self.s4xx = self.s5xx = 0
        self.size = 0
        self.paths: set[str] = set()
        self.capped = False
        self.methods = _Count()     # odd methods only
        self.attack = 0
        self.first = ""
        self.last = ""
        self.days = _Count()        # 'YYYY-MM-DD' -> requests
        self.samples: list[list] = []       # [category, uri] of payload hits
        self.p404 = _Count()        # own 404 paths (capped)
        self.allm = _Count()        # every method (GET/POST/...)
        self.tp = _Count()          # own paths (capped, for the HTML)
        self.uas = _Count()         # own user-agents (capped)
        self.qs = _Count()          # own query strings (capped)

    def within_ceilings(self) -> bool:
        """True when no per-IP ceiling would have refused anything counted here."""
        return (len(self.paths) <= _PATH_CAP and len(self.p404) <= _IP_404_CAP
                and len(self.tp) <= _IP_PATHS and len(self.uas) <= _IP_UAS
                and len(self.qs) <= _IP_QUERIES)

    def merge(self, o: _IpStat) -> None:
        """Fold in the same IP's requests from a later, unbounded slice."""
        self.requests += o.requests
        self.s2xx += o.s2xx
        self.s3xx += o.s3xx
        self.s401 += o.s401
        self.s403 += o.s403
        self.s404 += o.s404
        self.s4xx += o.s4xx
        self.s5xx += o.s5xx
        self.size += o.size
        paths = self.paths
        for p in o.paths:
            if p in paths:
                continue
            if len(paths) < _PATH_CAP:
                paths.add(p)
            else:
                self.capped = True
        self.capped = self.capped or o.capped
        _offer(self.methods, o.methods, _NO_CEILING)
        self.attack += o.attack
        if o.first and (not self.first or o.first < self.first):
            self.first = o.first
        self.last = max(self.last, o.last)
        _offer(self.days, o.days, _NO_CEILING)
        self.samples += o.samples[:_SAMPLES - len(self.samples)]
        _offer(self.p404, o.p404, _IP_404_CAP)
        _offer(self.allm, o.allm, _NO_CEILING)
        _offer(self.tp, o.tp, _IP_PATHS)
        _offer(self.uas, o.uas, _IP_UAS)
        _offer(self.qs, o.qs, _IP_QUERIES)


# Every ceiling below keeps a key only if there was room the first time it was
# seen, and once kept a key counts every later request. So which keys a ceiling
# kept depends only on the ORDER in which distinct keys first appeared -- which
# is what makes slices mergeable exactly: each slice counts without ceilings, and
# `_Tally.merge`, taking the slices in file order, offers each slice's keys in
# their own first-seen order to the ceilings of the whole. The single pass and
# the merged slices keep the same keys with the same counts.
#
# One ceiling is not like that: an IP over `_MAX_IPS` drops the WHOLE request,
# from every other count too, and a slice cannot know it will be over. A merge
# that reaches that ceiling gives up (`_Over`) and the run counts in one pass.
_NO_CEILING = sys.maxsize


class _Over(Exception):
    """A merge reached `_MAX_IPS`: count in one pass instead."""


def _offer(mine: dict, theirs: dict, cap: int) -> None:
    """`theirs` counted into `mine` as the requests behind it would have been:
    known keys add up, a new key only while `mine` has room."""
    for k, n in theirs.items():
        if k in mine:
            mine[k] += n
        elif len(mine) < cap:
            mine[k] = n


def _union(mine: dict, theirs: dict, cap: int) -> None:
    """Per-key sets of distinct IPs, read only for their size, up to `cap`."""
    for k, ips in theirs.items():
        if k not in mine:
            continue                      # a key the ceiling did not keep
        have = mine[k]
        for ip in ips:
            if len(have) >= cap:
                break
            have.add(ip)


class _Tally:
    """Everything `web_metrics` counts over a run of requests."""

    def __init__(self):
        self.stats: dict[str, _IpStat] = {}
        self.p404: Counter = Counter()                  # 404 path -> hits
        self.p404_ips: dict[str, set[str]] = {}         # 404 path -> source IPs (capped)
        self.auth: dict[tuple[str, str], list] = {}     # (ip, path) -> [401s, 403s, first, last]
        self.methods_all: Counter = Counter()           # global GET/POST/... distribution
        self.paths_all: Counter = Counter()             # global top requested paths
        self.uas_all: Counter = Counter()               # global top user-agents
        self.uas_ips: dict[str, set[str]] = {}          # ua -> source IPs (capped)
        self.queries_all: Counter = Counter()           # global top query strings
        # What the ceilings cost, so it is reported instead of vanishing. Counted in
        # REQUESTS, not distinct IPs: an exact distinct count would need the very
        # unbounded set the ceiling exists to avoid.
        self.over_reqs = 0
        self.requests = 0

    def feed(self, records, bounded: bool = True) -> _Tally:
        """Count `records`. Unbounded (a slice of a larger run) every ceiling is
        lifted: what a slice holds is bounded by the slice itself."""
        cap = (lambda n: n) if bounded else (lambda n: _NO_CEILING)
        max_ips, path_cap, paths_cap = cap(_MAX_IPS), cap(_PATH_CAP), cap(_MAX_PATHS)
        tp_cap, max_uas, uips_cap = cap(_IP_PATHS), cap(_MAX_UAS), cap(_UA_IPS)
        uas_cap, queries_cap, qs_cap = cap(_IP_UAS), cap(_MAX_QUERIES), cap(_IP_QUERIES)
        max_404, p404_ips_cap = cap(_MAX_404_PATHS), cap(_404_IPS)
        ip_404_cap, max_auth = cap(_IP_404_CAP), cap(_MAX_AUTH_ROWS)
        stats, p404, p404_ips, auth = self.stats, self.p404, self.p404_ips, self.auth
        methods_all, paths_all = self.methods_all, self.paths_all
        uas_all, uas_ips, queries_all = self.uas_all, self.uas_ips, self.queries_all
        over_reqs = requests = 0

        for rec, _src in records:
            requests += 1
            st = stats.get(rec.ip)
            if st is None:
                if len(stats) >= max_ips:
                    # Beyond the ceiling: tallied, just not tracked individually.
                    # Known IPs keep accumulating normally.
                    over_reqs += 1
                    continue
                st = stats[rec.ip] = _IpStat()
            st.requests += 1
            s = rec.status
            if s.startswith("2"):
                st.s2xx += 1
            elif s.startswith("3"):
                st.s3xx += 1
            elif s == "401":
                st.s401 += 1
            elif s == "403":
                st.s403 += 1
            elif s == "404":
                st.s404 += 1
            elif s.startswith("4"):
                st.s4xx += 1
            elif s.startswith("5"):
                st.s5xx += 1
            if rec.size.isdigit():
                st.size += int(rec.size)
            if len(st.paths) < path_cap:
                st.paths.add(rec.path)
            elif rec.path not in st.paths:
                st.capped = True
            m = rec.method.upper() or "?"
            methods_all[m] += 1
            st.allm[m] += 1
            if m not in _NORMAL_METHODS:
                st.methods[rec.method] += 1
            if len(paths_all) < paths_cap or rec.path in paths_all:
                paths_all[rec.path] += 1
            if len(st.tp) < tp_cap or rec.path in st.tp:
                st.tp[rec.path] += 1
            # The UA is whatever the client sent: a scanner rotating it per request
            # would otherwise add an entry (and a set) for every single line.
            if rec.ua and rec.ua != "-":
                if len(uas_all) < max_uas or rec.ua in uas_all:
                    uas_all[rec.ua] += 1
                    uips = uas_ips.setdefault(rec.ua, set())
                    if len(uips) < uips_cap:
                        uips.add(rec.ip)
                if len(st.uas) < uas_cap or rec.ua in st.uas:
                    st.uas[rec.ua] += 1
            if rec.query and (len(queries_all) < queries_cap or rec.query in queries_all):
                queries_all[rec.query] += 1
            if rec.query and (len(st.qs) < qs_cap or rec.query in st.qs):
                st.qs[rec.query] += 1
            if rec.time:
                if not st.first or rec.time < st.first:
                    st.first = rec.time
                st.last = max(st.last, rec.time)
                day = rec.time[:10]
                if len(day) == 10 and day[4] == "-" and day[7] == "-":
                    st.days[day] += 1
            # payload signature hit on any status: a probe still ranks its IP
            # (huntweb keeps the served-only detail view). Pre-check scans only
            # path+query -- all the signatures look at (raw line would false-hit
            # on benign UAs like `curl/8` and pay decode+classify for nothing).
            if prefilter(rec.path + " " + rec.query):
                cat = classify(decode(rec.path) + " " + decode(rec.query))[0]
                if cat:
                    st.attack += 1
                    if len(st.samples) < _SAMPLES:
                        uri = rec.path + (f"?{rec.query}" if rec.query else "")
                        st.samples.append([cat, uri[:160]])
            if s == "404":
                # A wordlist scan invents a new path per request; track a bounded
                # set of them (the ranking below only ever shows the top anyway).
                if len(p404) < max_404 or rec.path in p404:
                    p404[rec.path] += 1
                    ips = p404_ips.setdefault(rec.path, set())
                    if len(ips) < p404_ips_cap:
                        ips.add(rec.ip)
                if len(st.p404) < ip_404_cap or rec.path in st.p404:
                    st.p404[rec.path] += 1
            elif s in ("401", "403"):
                a = auth.get((rec.ip, rec.path))
                if a is None:
                    # keyed by ip x path -- a distributed credential-stuffing run
                    # multiplies the two, so this needs a ceiling of its own
                    if len(auth) >= max_auth:
                        continue
                    auth[(rec.ip, rec.path)] = a = [0, 0, rec.time, rec.time]
                a[0 if s == "401" else 1] += 1
                a[2] = min(a[2], rec.time)
                a[3] = max(a[3], rec.time)

        self.over_reqs += over_reqs
        self.requests += requests
        return self

    def merge(self, o: _Tally) -> None:
        """Fold in an unbounded slice that comes right after what this holds."""
        self.requests += o.requests
        stats = self.stats
        for ip, theirs in o.stats.items():
            st = stats.get(ip)
            if st is None:
                if len(stats) >= _MAX_IPS:
                    raise _Over
                if theirs.within_ceilings():
                    stats[ip] = theirs            # what one pass would have built
                    continue
                st = stats[ip] = _IpStat()
            st.merge(theirs)
        _offer(self.p404, o.p404, _MAX_404_PATHS)
        self.p404_ips.update({k: set() for k in o.p404_ips
                              if k in self.p404 and k not in self.p404_ips})
        _union(self.p404_ips, o.p404_ips, _404_IPS)
        auth = self.auth
        for key, (n401, n403, first, last) in o.auth.items():
            a = auth.get(key)
            if a is None:
                if len(auth) >= _MAX_AUTH_ROWS:
                    continue
                auth[key] = [n401, n403, first, last]
            else:
                a[0] += n401
                a[1] += n403
                a[2] = min(a[2], first)
                a[3] = max(a[3], last)
        _offer(self.methods_all, o.methods_all, _NO_CEILING)
        _offer(self.paths_all, o.paths_all, _MAX_PATHS)
        _offer(self.uas_all, o.uas_all, _MAX_UAS)
        self.uas_ips.update({k: set() for k in o.uas_ips
                             if k in self.uas_all and k not in self.uas_ips})
        _union(self.uas_ips, o.uas_ips, _UA_IPS)
        _offer(self.queries_all, o.queries_all, _MAX_QUERIES)


def _slice(path, lo, hi) -> _Tally:
    """One slice of the timeline, counted without ceilings (in a pool worker)."""
    return _Tally().feed(_webshard.read(path, lo, hi), bounded=False)


def _count(ctx) -> _Tally:
    parts = _webshard.slices(ctx)
    if parts and len(parts) > 1:
        if ctx.log:
            ctx.log.debug(_webshard.describe(parts))
        whole = _Tally()
        try:
            for part in _webshard.in_order(_slice, parts):
                whole.merge(part)
            return whole
        except _Over:
            if ctx.log:
                ctx.log.debug(f"web_metrics: over {_MAX_IPS:,} client IPs, "
                              "counting again in one pass")
    return _Tally().feed(iter_records(ctx))


def run(ctx) -> None:
    t = _count(ctx)
    stats, p404, p404_ips, auth = t.stats, t.p404, t.p404_ips, t.auth
    methods_all, paths_all = t.methods_all, t.paths_all
    uas_all, uas_ips, queries_all = t.uas_all, t.uas_ips, t.queries_all
    over_reqs, requests = t.over_reqs, t.requests

    # Say what the ceilings cost. Silence here would be the same mistake the graph
    # made when it trimmed peers without a word: the analyst must know the ranking
    # is over a bounded set, not the whole log.
    if over_reqs and getattr(ctx, "log", None):
        ctx.log.warning(
            f"[!] web_metrics: more than {_MAX_IPS:,} distinct client IPs; "
            f"{over_reqs:,} request(s) from beyond that ceiling are not attributed "
            f"to an IP row (raise _MAX_IPS to track them all)")

    geo = Geo(ctx.assets)
    all_days = sorted({d for st in stats.values() for d in st.days})
    day_idx = {d: i for i, d in enumerate(all_days)}
    ip_rows: list[list] = []
    html_rows: list[list] = []
    for ip, st in stats.items():
        country, origin, asn = geo.lookup(ip)
        flags = []
        if st.attack:
            flags.append("attack")
        # ratio guards keep a busy legit proxy/NAT (high volume, low error
        # share) out of the flags; a dedicated brute/scanner is mostly errors.
        fails = st.s401 + st.s403
        if fails >= _AUTH_IP_CLUSTER and fails >= st.requests * _AUTH_RATIO:
            flags.append("auth-fail")
        if ((st.s404 >= _SCAN_404 and st.s404 >= st.requests * _SCAN_RATIO)
                or (st.requests >= 30 and st.s404 > st.requests * 0.5)):
            flags.append("scan")
        if st.methods:
            flags.append("odd-method")
        odd = " ".join(f"{m}:{c}" for m, c in
                       sorted(st.methods.items(), key=itemgetter(1), reverse=True))
        row = [ip, country, origin, asn, st.requests, st.s2xx, st.s3xx,
               st.s401, st.s403, st.s404, st.s4xx, st.s5xx,
               round(st.size / 1048576, 2),
               f"{_PATH_CAP}+" if st.capped else len(st.paths),
               odd, st.attack, st.first, st.last, "+".join(flags)]
        ip_rows.append(row)
        # HTML extras: daily series for every IP (cross-filtered timeline);
        # payload samples and own-404 ranking only for flagged IPs (size);
        # methods/top-paths/UAs/queries per IP feed the panels under a filter
        # and the detail view (truncated -- the CSVs keep full values).
        html_rows.append(row + [
            {day_idx[d]: n for d, n in st.days.items()},
            st.samples if flags else [],
            [list(t) for t in _top(st.p404, 8)] if flags else [],
            dict(st.allm),
            [[_t(p, 70), n] for p, n in _top(st.tp, 4)],
            [[_t(u, 70), n] for u, n in _top(st.uas, 2)],
            [[_t(q, 60), n] for q, n in _top(st.qs, 2)],
        ])
    order = sorted(range(len(ip_rows)), key=lambda i: ip_rows[i][4], reverse=True)
    ip_rows = [ip_rows[i] for i in order]
    html_rows = [html_rows[i] for i in order]
    write_csv(ctx.out, "web_ip_stats.csv", _IP_HEADER, ip_rows)

    rows404: list[list] = []
    for path, n in p404.most_common():
        sens = _SENSITIVE.search(decode(path)) is not None
        if n < _MIN_404 and not sens:
            continue
        rows404.append([path, n, len(p404_ips.get(path, ())),
                        "sensitive" if sens else ""])
    write_csv(ctx.out, "web_404_paths.csv", _404_HEADER, rows404)

    auth_rows: list[list] = []
    for (ip, path), (n401, n403, first, last) in auth.items():
        total = n401 + n403
        flags = []
        if total >= _AUTH_ROW_CLUSTER:
            flags.append("cluster")
        if _SENSITIVE.search(decode(path)):
            flags.append("sensitive")
        auth_rows.append([ip, path, n401, n403, total, first, last,
                          "+".join(flags)])
    auth_rows.sort(key=lambda r: r[4], reverse=True)
    write_csv(ctx.out, "web_auth_fail.csv", _AUTH_HEADER, auth_rows)

    # Interactive panel at the machine root, next to report.txt (see module doc).
    if ip_rows:
        globals_ = {
            "methods": [[m, n] for m, n in methods_all.most_common()],
            "paths": [[_t(p, 90), n] for p, n in paths_all.most_common(200)],
            "uas": [[_t(u, 90), n, len(uas_ips.get(u, ()))]
                    for u, n in uas_all.most_common(60)],
            "queries": [[_t(q, 90), n] for q, n in queries_all.most_common(60)],
        }
        _web_report.render(
            _machine_root(ctx.out) / "web_metrics.html", ctx.machine_name,
            time.strftime("%Y-%m-%d %H:%M"), all_days, html_rows, rows404,
            auth_rows, Path(ctx.assets), globals_)

    if ctx.log:
        ctx.log.debug(f"web_metrics: {len(ip_rows)} IP(s), {len(rows404)} 404 "
                      f"path(s), {len(auth_rows)} auth-fail row(s) "
                      f"over {requests} request(s)")


def _machine_root(out) -> Path:
    """The machine folder (where report.txt and the .db land): parent of the
    CSVs/ tree the handler writes into. Falls back to `out` itself."""
    out = Path(out)
    for p in (out, *out.parents):
        if p.name.lower() == "csvs":
            return p.parent
    return out
