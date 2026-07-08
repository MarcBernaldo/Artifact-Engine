"""Handler: web access-log security metrics. Outputs: web_ip_stats.csv,
web_404_paths.csv, web_auth_fail.csv

The ready-made audit queries an analyst would otherwise run by hand over the
access logs (`awk '{print $1}' | sort | uniq -c | sort -nr` and friends),
computed in ONE streaming pass over the same files as `web_access`:

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
see handlers/_web_report.py) built from the same single pass.

`web_access` stays the raw record and `huntweb` the payload-level detail; this
is the statistics layer that tells the analyst WHERE to pivot first.
"""

from __future__ import annotations

import re
import time
from collections import Counter
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _web_report
from artifact_engine.handlers._lincommon import iter_log_lines, write_csv
from artifact_engine.handlers._webcommon import Geo, decode, iter_access_files, parse
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


def _t(s: str, n: int) -> str:
    """Truncate for the HTML embed (full values stay in the CSVs)."""
    return s if len(s) <= n else s[: n - 1] + "…"


class _IpStat:
    __slots__ = ("requests", "s2xx", "s3xx", "s401", "s403", "s404", "s4xx",
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
        self.methods: Counter = Counter()   # odd methods only
        self.attack = 0
        self.first = ""
        self.last = ""
        self.days: Counter = Counter()      # 'YYYY-MM-DD' -> requests
        self.samples: list[list] = []       # [category, uri] of payload hits
        self.p404: Counter = Counter()      # own 404 paths (capped)
        self.allm: Counter = Counter()      # every method (GET/POST/...)
        self.tp: Counter = Counter()        # own paths (capped, for the HTML)
        self.uas: Counter = Counter()       # own user-agents (capped)
        self.qs: Counter = Counter()        # own query strings (capped)


def run(ctx) -> None:
    files = list(iter_access_files(ctx.evidence))
    if not files:
        raise HandlerSkip("no apache/nginx access logs")

    stats: dict[str, _IpStat] = {}
    p404: Counter = Counter()                    # 404 path -> hits
    p404_ips: dict[str, set[str]] = {}           # 404 path -> source IPs (capped)
    auth: dict[tuple[str, str], list] = {}       # (ip, path) -> [401s, 403s, first, last]
    methods_all: Counter = Counter()             # global GET/POST/... distribution
    paths_all: Counter = Counter()               # global top requested paths
    uas_all: Counter = Counter()                 # global top user-agents
    uas_ips: dict[str, set[str]] = {}            # ua -> source IPs (capped)
    queries_all: Counter = Counter()             # global top query strings

    for f in files:
        for line in iter_log_lines(f):
            rec = parse(line)
            if rec is None:
                continue
            st = stats.get(rec.ip)
            if st is None:
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
            if len(st.paths) < _PATH_CAP:
                st.paths.add(rec.path)
            elif rec.path not in st.paths:
                st.capped = True
            m = rec.method.upper() or "?"
            methods_all[m] += 1
            st.allm[m] += 1
            if m not in _NORMAL_METHODS:
                st.methods[rec.method] += 1
            if len(paths_all) < 200_000 or rec.path in paths_all:
                paths_all[rec.path] += 1
            if len(st.tp) < 400 or rec.path in st.tp:
                st.tp[rec.path] += 1
            if rec.ua and rec.ua != "-":
                uas_all[rec.ua] += 1
                uips = uas_ips.setdefault(rec.ua, set())
                if len(uips) < 2000:
                    uips.add(rec.ip)
                if len(st.uas) < 20 or rec.ua in st.uas:
                    st.uas[rec.ua] += 1
            if rec.query and (len(queries_all) < 100_000 or rec.query in queries_all):
                queries_all[rec.query] += 1
            if rec.query and (len(st.qs) < 30 or rec.query in st.qs):
                st.qs[rec.query] += 1
            if rec.time:
                if not st.first or rec.time < st.first:
                    st.first = rec.time
                if rec.time > st.last:
                    st.last = rec.time
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
                p404[rec.path] += 1
                ips = p404_ips.setdefault(rec.path, set())
                if len(ips) < 1000:
                    ips.add(rec.ip)
                if len(st.p404) < _IP_404_CAP or rec.path in st.p404:
                    st.p404[rec.path] += 1
            elif s in ("401", "403"):
                a = auth.get((rec.ip, rec.path))
                if a is None:
                    auth[(rec.ip, rec.path)] = a = [0, 0, rec.time, rec.time]
                a[0 if s == "401" else 1] += 1
                if rec.time < a[2]:
                    a[2] = rec.time
                if rec.time > a[3]:
                    a[3] = rec.time

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
        odd = " ".join(f"{m}:{c}" for m, c in st.methods.most_common())
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
            [list(t) for t in st.p404.most_common(8)] if flags else [],
            dict(st.allm),
            [[_t(p, 70), n] for p, n in st.tp.most_common(4)],
            [[_t(u, 70), n] for u, n in st.uas.most_common(2)],
            [[_t(q, 60), n] for q, n in st.qs.most_common(2)],
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
                      f"from {len(files)} file(s)")


def _machine_root(out) -> Path:
    """The machine folder (where report.txt and the .db land): parent of the
    CSVs/ tree the handler writes into. Falls back to `out` itself."""
    out = Path(out)
    for p in (out, *out.parents):
        if p.name.lower() == "csvs":
            return p.parent
    return out
