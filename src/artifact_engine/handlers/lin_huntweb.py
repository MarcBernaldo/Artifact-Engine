"""Handler: web-attack hunt. Output: huntweb.csv

Attack-only view over the same access logs as `web_access`. For each request it
decodes the path+query (URL %XX + double-encoding + \\xNN) and matches:

  - the built-in payload signatures (log4shell/cmdi/webshell/sqli/lfi/traversal/
    xss), which fire only on a SERVED request (HTTP 200) -- a payload the server
    actually returned landed, a 404/301/403 was just a probe (still in
    `web_access`);
  - the analyst-editable indicators in `assets/web_suspicious.txt` (scanner
    User-Agents, web-shell/secret paths, miners, ...), matched over path+query+UA
    on ANY status -- odd things to see at all, whether served or not. Add lines
    to that file to hunt your own IOCs without touching code.

The matched category is the FIRST column, then the full flag list, then the
parsed request, then the offline IP origin: country (db-ip country-lite), an
origin tag (private/local/tor/hosting/foreign/unknown -- Tor exit list + db-ip
asn-lite), and the raw AS number+org.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._indicators import combined, load_indicators, match_labels
from artifact_engine.handlers._lincommon import iter_log_lines, write_csv
from artifact_engine.handlers._webcommon import Geo, decode, iter_access_files, parse
from artifact_engine.handlers._webrules import classify, prefilter

_HEADER = ["category", "flag", "time", "ip", "country", "origin", "asn",
           "method", "status", "path", "query", "ua", "source"]


def run(ctx) -> None:
    files = list(iter_access_files(ctx.evidence))
    if not files:
        raise HandlerSkip("no apache/nginx access logs")

    geo = Geo(ctx.assets)
    geo_cache: dict[str, tuple[str, str, str]] = {}
    user_rules = load_indicators(Path(ctx.assets) / "web_suspicious.txt")
    user_pre = combined(user_rules)      # cheap raw-line pre-check for the IOC list
    rows: list[list] = []
    for f in files:
        try:
            src = str(f.relative_to(ctx.evidence))
        except ValueError:
            src = f.name
        for line in iter_log_lines(f):
            rec = parse(line)
            if rec is None:
                continue
            # Pre-checks scan only what the rules actually look at: path+query
            # for the built-in signatures, +UA for the user IOCs. Scanning the
            # whole raw line burned ~10x the bytes and false-hit on benign UAs
            # (`curl/8`, `wget`) and referers, decoding+classifying for nothing.
            pq = rec.path + " " + rec.query
            hit_builtin = prefilter(pq)
            hit_user = user_pre is not None and user_pre.search(
                pq + " " + (rec.ua or "")) is not None
            if not (hit_builtin or hit_user):    # cheap skip of benign traffic
                continue
            hay = decode(rec.path) + " " + decode(rec.query)
            # built-in payload rules: served requests only
            category = flags = ""
            if hit_builtin and rec.status == "200":
                category, flags = classify(hay)
            # user IOCs: any status, over path+query+UA
            labels = match_labels(user_rules, hay + " " + (rec.ua or "").lower()) if hit_user else []
            if not category and not labels:
                continue
            category = category or labels[0]
            flag = "+".join(x for x in ([flags] if flags else []) + labels if x)
            geo_info = geo_cache.get(rec.ip)
            if geo_info is None:
                geo_info = geo.lookup(rec.ip)
                geo_cache[rec.ip] = geo_info
            country, tag, asn = geo_info
            rows.append([category, flag, rec.time, rec.ip, country, tag, asn,
                         rec.method, rec.status, rec.path, rec.query, rec.ua, src])

    # newest first within the hunt view; foreign/tor float up via stable sort
    rows.sort(key=lambda r: r[2], reverse=True)
    write_csv(ctx.out, "huntweb.csv", _HEADER, rows)
