# web_metrics — access-log security metrics + interactive panel

`handlers/lin_web_metrics.py` (manifest `data/parsers/linux/web_metrics.yaml`,
os `linux`, category `web`). The classic security-audit queries an analyst
would otherwise run by hand over the access logs (`awk '{print $1}' | sort |
uniq -c | sort -nr` and friends), computed in **one streaming pass** (or, for a
timeline over 256 MB, in slices merged to the same result) — plus a
self-contained HTML panel built from the same counts. `web_access` stays the raw
per-request record and `web_hunt` the payload-level detail; this is the
statistics layer that says *where to pivot first*.

![web_metrics.html over a synthetic access log](img/web_metrics.png)

*Three days of a synthetic shop (`docs/demo/make_images.py`): a directory scan,
a login brute force and a SQL injection among the customers. The country map is
cut from the picture -- documentation addresses have no country.*

| Output | Content |
|---|---|
| `CSVs/Web/web_ip_stats.csv` | One row per source IP: volume, status breakdown, distinct paths, odd HTTP methods, attack-payload hits, MB served, first/last seen, offline geo, flags. Sorted by volume. |
| `<machine>/web_metrics.html` | Interactive cross-filtered panel at the machine root, next to `report.txt`. Also ranks the 404 paths most asked for (kept when hit ≥ 3 times or the path is sensitive) -- in the panel only since v0.7.161: as a table, half its rows were flagged, and a path that was not served is an attempt that failed. |

## Where the data comes from

`_webcommon.iter_records(ctx)` — the same requests `web_access` and `web_hunt`
read. Since v0.7.87 the logs are parsed ONCE per volume: `web_access` is that
pass, this parser `depends_on` it and reads its `web_access.csv`, and the raw
logs are parsed here only when that file is absent. Either way the files are the
ones `_webcommon.iter_access_files(evidence)` discovers:

- **UAC acquisition** (`[root]/` present): Apache/nginx/lighttpd access logs
  under `var/log/{apache2,httpd,nginx,lighttpd}` including per-vhost subdirs
  and rotated `.gz/.xz/.bz2` archives; `error` logs excluded. Plus (v0.7.151)
  the files the server's own config (`etc/{apache2,httpd,nginx}`) names with
  `CustomLog`/`TransferLog` (Apache) or `access_log` (nginx) outside those dirs:
  a piped `rotatelogs`/`cronolog` included (its logfile argument), `${NAME}`
  filled from `Define`, the name matched up to its first `%` or `$`, a strftime
  directory (`/srv/logs/%Y/%m/`) walked from the fixed part above it, and since
  v0.7.159 any log dir two or more levels below `/` walked too, for the
  rotations a site archives into a subdirectory of it. Left out:
  files the `ErrorLog` names or with `error` in the name; names that start with a
  variable (nginx `$host.log`); a walk from fewer than two fixed directories;
  relative paths, left to the standard dirs (ServerRoot's `logs` is
  `/var/log/httpd`).
- **Loose drop** (the `weblogs*` folder profile, §10 of ARCHITECTURE.md): no
  `[root]/`, so every file in the tree is offered — exports arrive named any
  which way. Each candidate must *prove* it is an access log: a binary sniff
  (NUL byte in the first 64 KB, decompressed) plus a probe that requires one of
  the first 20 lines to parse as Common/Combined Log Format. That keeps
  journald journals, mysql data and syslog out (a full `/var/log` export is
  mostly not access logs). The tool's own outputs (`CSVs/`, `run.json`,
  `traces.*`, …) are always excluded.

A timeline over 256 MB is counted in slices by several processes and merged in
file order (v0.7.112, `handlers/_webshard.py`). The merge applies the ceilings
below, with the same result as one pass; see ARCHITECTURE.md, weblogs.

Lines parse as CLF/combined with tolerance for malformed request fields,
escaped quotes inside request/referer/UA (attack lines), and exporter-wrapped
lines (`"<whole line>"`). If nothing parses, the handler skips cleanly.

**X-Forwarded-For**: when the logs sit behind a reverse proxy / load balancer /
CDN, the connecting host is the frontend and the real client is in a trailing
`X-Forwarded-For="…"` field. `parse` recovers it — the leftmost XFF hop becomes
the source IP that every metric, flag and geo lookup keys on (the frontend is
kept as `edge_ip` in `web_access.csv`; that file also carries mod_ssl's
`ssl_request_log` rows since v0.7.156 -- `tls_cipher` filled -- which the
metrics skip, the access log holding the same requests). This is what makes the per-source stats
meaningful behind a proxy; otherwise one frontend IP would carry ~all traffic.
XFF is client-settable, so it is read only from the tail after the combined
fields (a URL/UA can't forge it) — but a determined attacker can still set their
own XFF, the usual caveat. A LogFormat that writes it unquoted right after the
proxy (`%h %{X-Forwarded-For}i %l %u …`) is read from the fields before `%l %u`
instead (the leftmost address there is the client; a URL/UA cannot reach that
position either), and Debian's vhost_combined (`%v:%p %h …`) parses with the
vhost dropped (v0.7.141).

## The single pass

Per source IP (`_IpStat`, `__slots__`, capped collections so wordlist scans
can't exhaust memory): request count, status buckets (2xx/3xx/401/403/404/
other-4xx/5xx), bytes served, distinct-path set (cap 5 000), full method
distribution + odd-method counter, first/last seen, per-day series, its own
404 paths, top paths / user-agents / query strings, and attack-payload hits
with up to 5 captured samples. Globally: 404-path ranking with distinct-IP
counts, (ip, path) auth-failure clusters, and method / path / UA / query
distributions for the HTML panels.

**Attack detection** reuses web_hunt's signature set (`_webrules.classify`):
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

The panel's 401/403 clusters per (ip, path) and its 404 list are additionally marked `sensitive` when
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
methods panel), flag and origin chips, country click, a **day range**, UA click —
and every panel recomputes from the filtered set; a reset button clears it.
Per-IP strings embedded in the HTML are truncated; the CSVs keep full values.

**The date window and playback.** A calendar picks the days (v0.7.75, the same
control the lateral graph got in v0.7.74): click one, drag or shift-click for a
range, ctrl/cmd-click to add a separate day — so "the 24th and the 2nd" no longer
means dragging in the nine days between them. Each day carries a bar for the
requests it holds and a day the logs never covered is dimmed and inert, so a hole
in the coverage is visible before it is mistaken for a quiet day. A single day was
never enough to read an intrusion — scan → exploitation → webshell spans several —
and the play button walks the days picked (all of them when none are), handing the
selection back when it stops: what is filtered is what `copiar IPs` and the CSV
export, so a window left behind by playback would ship in the evidence. Clicking a
bar on the daily timeline still selects that day, shift-clicking extends from the
first day picked, and the active days stay outlined on the bars and named in the
filter summary.

These rows are aggregated **per day** and carry no time of day, so the calendar
here stops at days; the graph's half-hour ends have nothing to bite on. Giving
this panel half-hour buckets would mean carrying 48 of them per IP per day in the
page.

URLs, user-agents and query strings come straight off the wire, i.e. they are
attacker-controlled: every one of them is HTML-escaped before it reaches the page,
and the embedded JSON is `</`-escaped so a crafted path cannot break out of the
`<script>` block.

**Bounded memory.** The per-IP structures were always capped (distinct paths,
own-404s, samples, UAs, queries); the top-level accumulators now are too, because
their keys come from whoever hit the server — one `_IpStat` (eight Counters) per
distinct client IP, one entry per 404 path, per user-agent, per `(ip, path)` auth
pair. A months-long log from a public site, or a scanner rotating its UA on every
request, grew those without limit. The ceilings are measured, not guessed: a
one-request source costs ~1.8 KB including its dict key, so the 1M `_MAX_IPS`
default is ~1.8 GB in the worst case — sized so a real public-site drop seen here
(619k distinct sources) stays whole. Past `_MAX_IPS` / `_MAX_404_PATHS` / `_MAX_UAS` /
`_MAX_AUTH_ROWS` a *new* key stops being tracked while known keys keep counting, so
the ceiling only ever costs the long tail — and the requests it could not attribute
are reported as a warning, never swallowed. Raise the constants to trade RAM for
completeness.

The path/query filter is scoped to what is embedded per IP (top paths, top
queries, top 404s) rather than every request line — enough to find the IPs
whose main activity hit e.g. `wp-login`, without bloating the file with every
IP's full URL set.

## Relationship to siblings

- `web_access` — full request timeline (raw record, one row per request).
- `web_hunt` — payload-level attack hunt + `web_suspicious.txt` indicators.
- `web_sigma` — SigmaHQ webserver ruleset over the same logs.
- `web_metrics` — this: aggregations that rank *sources* and *targets*.

## Extending

New flags belong next to the existing threshold constants (top of
`lin_web_metrics.py`) — keep the ratio-guard pattern. New panels: extend the
`html_rows` extras / `globals_` dict and the template in `_web_report.py`.

Editing `_web_report.py` re-runs `web_metrics` on its own — since v0.7.0 the `.done`
fingerprint hashes the handler's whole first-party import closure, and that reaches
the report module. No `--force`, and nothing else re-parses: the closure is 24
modules and none of the other parsers are in it. (This page said the opposite until
v0.7.13, which cost a full re-parse to pick up a one-parser change.)
