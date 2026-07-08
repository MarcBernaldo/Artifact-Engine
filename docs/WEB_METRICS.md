# web_metrics — access-log security metrics + interactive panel

`handlers/lin_web_metrics.py` (manifest `data/parsers/linux/web_metrics.yaml`,
os `linux`, category `web`). The classic security-audit queries an analyst
would otherwise run by hand over the access logs (`awk '{print $1}' | sort |
uniq -c | sort -nr` and friends), computed in **one streaming pass** — plus a
self-contained HTML panel built from the same pass. `web_access` stays the raw
per-request record and `huntweb` the payload-level detail; this is the
statistics layer that says *where to pivot first*.

| Output | Content |
|---|---|
| `CSVs/Web/web_ip_stats.csv` | One row per source IP: volume, status breakdown, distinct paths, odd HTTP methods, attack-payload hits, MB served, first/last seen, offline geo, flags. Sorted by volume. |
| `CSVs/Web/web_404_paths.csv` | 404 target ranking — what the recon was looking for. Kept when hit ≥ 3 times or the path is sensitive. |
| `CSVs/Web/web_auth_fail.csv` | 401/403 clusters per (ip, path): credential stuffing, brute force, permission probing. |
| `<machine>/web_metrics.html` | Interactive cross-filtered panel at the machine root, next to `report.txt`. |

## Where the data comes from

`_webcommon.iter_access_files(evidence)` — the same discovery `web_access` and
`huntweb` use:

- **UAC acquisition** (`[root]/` present): Apache/nginx/lighttpd access logs
  under `var/log/{apache2,httpd,nginx,lighttpd}` including per-vhost subdirs
  and rotated `.gz/.xz/.bz2` archives; `error` logs excluded.
- **Loose drop** (the `weblogs*` folder profile, §10 of ARCHITECTURE.md): no
  `[root]/`, so every file in the tree is offered — exports arrive named any
  which way. Each candidate must *prove* it is an access log: a binary sniff
  (NUL byte in the first 64 KB, decompressed) plus a probe that requires one of
  the first 20 lines to parse as Common/Combined Log Format. That keeps
  journald journals, mysql data and syslog out (a full `/var/log` export is
  mostly not access logs). The tool's own outputs (`CSVs/`, `run.json`,
  `traces.*`, …) are always excluded.

Lines parse as CLF/combined with tolerance for malformed request fields,
escaped quotes inside request/referer/UA (attack lines), and exporter-wrapped
lines (`"<whole line>"`). If nothing parses, the handler skips cleanly.

**X-Forwarded-For**: when the logs sit behind a reverse proxy / load balancer /
CDN, the connecting host is the frontend and the real client is in a trailing
`X-Forwarded-For="…"` field. `parse` recovers it — the leftmost XFF hop becomes
the source IP that every metric, flag and geo lookup keys on (the frontend is
kept as `edge_ip` in `web_access.csv`). This is what makes the per-source stats
meaningful behind a proxy; otherwise one frontend IP would carry ~all traffic.
XFF is client-settable, so it is read only from the tail after the combined
fields (a URL/UA can't forge it) — but a determined attacker can still set their
own XFF, the usual caveat.

## The single pass

Per source IP (`_IpStat`, `__slots__`, capped collections so wordlist scans
can't exhaust memory): request count, status buckets (2xx/3xx/401/403/404/
other-4xx/5xx), bytes served, distinct-path set (cap 5 000), full method
distribution + odd-method counter, first/last seen, per-day series, its own
404 paths, top paths / user-agents / query strings, and attack-payload hits
with up to 5 captured samples. Globally: 404-path ranking with distinct-IP
counts, (ip, path) auth-failure clusters, and method / path / UA / query
distributions for the HTML panels.

**Attack detection** reuses huntweb's signature set (`_webrules.classify`):
a cheap prefilter runs over `path + query` only (the signatures only ever match
there; scanning the raw line would false-hit benign UAs like `curl/8` and pay
decode+classify for nothing), then matching URIs are aggressively decoded
(`\xNN`, double URL-decode, lowercase) and classified. Hits count on **any**
status — a 404'd probe still ranks its IP.

## Flags (`suspicious` column)

Ratio guards keep a busy legitimate proxy/NAT (high volume, low error share)
out of the flags; a dedicated brute/scanner is mostly errors.

| Flag | Condition |
|---|---|
| `attack` | ≥ 1 payload-signature hit. |
| `auth-fail` | 401+403 ≥ 20 **and** ≥ 10 % of the IP's requests. |
| `scan` | 404 ≥ 50 **and** ≥ 25 % of requests, **or** ≥ 30 requests with > 50 % 404. |
| `odd-method` | Any method outside GET/HEAD/POST/OPTIONS (PUT, PROPFIND, TRACE, CONNECT, …). `?` (malformed request field) is not odd. |

`web_404_paths` / `web_auth_fail` rows are additionally marked `sensitive` when
the decoded path matches attacker-probed endpoints (`wp-login.php`, `/.env`,
`/.git`, `phpmyadmin`, `web.config`, backup/archive extensions, …).

## Offline geolocation

`_webcommon.Geo` resolves each IP to (country, origin, ASN) fully offline:
db-ip country/ASN mmdb + a Tor exit-node list (fetched by `aeng setup`,
gitignored). `origin` ∈ `private` / `local` / `foreign` / `tor` / `hosting`
(AS-org name matches a hosting/cloud/VPN keyword list) / `unknown`. Degrades
gracefully when the databases are absent (country `?`).

## The HTML panel (`handlers/_web_report.py`)

A single HTML file with the data embedded as JSON (`</` escaped — paths, UAs
and queries are attacker-controlled), no external requests, no libraries:
works from a file share on an air-gapped box.

Panels: KPI row, full-width daily timeline, world choropleth (Natural Earth
110 m from `data/assets/world_map.json`, volume/flags modes, top-country labels
+ clickable ranking), method / top-path / user-agent / query distributions, the
sortable IP table, and per-IP detail (daily sparkline, captured payload
samples, own 404s and auth failures).

Everything shares **one filter state** — text search (IP/ASN/country), a
path/query search (matches the IP's embedded top paths, queries and own-404s),
status-bucket chips (2xx/3xx/4xx/5xx — keep IPs that served ≥1 response in any
ticked class), method chips (GET/POST/… multi-select; also toggled from the
methods panel), flag and origin chips, country click, day click, UA click —
and every panel recomputes from the filtered set; a reset button clears it.
Per-IP strings embedded in the HTML are truncated; the CSVs keep full values.

The path/query filter is scoped to what is embedded per IP (top paths, top
queries, top 404s) rather than every request line — enough to find the IPs
whose main activity hit e.g. `wp-login`, without bloating the file with every
IP's full URL set.

## Relationship to siblings

- `web_access` — full request timeline (raw record, one row per request).
- `huntweb` — payload-level attack hunt + `web_suspicious.txt` indicators.
- `web_sigma` — SigmaHQ webserver ruleset over the same logs.
- `web_metrics` — this: aggregations that rank *sources* and *targets*.

## Extending

New flags belong next to the existing threshold constants (top of
`lin_web_metrics.py`) — keep the ratio-guard pattern. New panels: extend the
`html_rows` extras / `globals_` dict and the template in `_web_report.py`;
remember the fingerprint only hashes the handler module, so touch
`lin_web_metrics.py` (or run `--force`) after editing `_web_report.py`.
