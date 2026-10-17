"""Handler: full web access-log timeline. Output: web_access.csv

Parses EVERY Apache/nginx access log on the host (current + rotated .gz + per
-vhost) into one clean, sortable timeline. Since v0.7.156 mod_ssl's
`ssl_request_log` too, after them, with the TLS protocol and cipher it adds and
no status/referer/UA (it logs none); a row with `tls_cipher` is one of those, and
the web detections skip them -- the access log holds the same requests. No filtering, no flags -- this is the
raw record the analyst pivots through; `web_hunt` is the attack-only view over the
same data. Streams to CSV so a multi-hundred-MB log set never loads whole.
"""

from __future__ import annotations

import csv

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import iter_log_lines
from artifact_engine.handlers._webcommon import (
    iter_access_files,
    iter_ssl_request_files,
    parse,
    parse_ssl_request,
)

_HEADER = ["time", "ip", "edge_ip", "method", "status", "size", "path", "query",
           "referer", "ua", "source", "tls_protocol", "tls_cipher"]


def run(ctx) -> None:
    files = list(iter_access_files(ctx.evidence))
    ssl_files = list(iter_ssl_request_files(ctx.evidence))
    if not files and not ssl_files:
        raise HandlerSkip("no apache/nginx access logs")

    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "web_access.csv"
    rows = 0
    try:
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(_HEADER)
            for f in files:
                try:
                    src = str(f.relative_to(ctx.evidence))  # for traceability
                except ValueError:
                    src = f.name
                for line in iter_log_lines(f):
                    rec = parse(line)
                    if rec is None:
                        continue
                    w.writerow([rec.time, rec.ip, rec.edge_ip, rec.method,
                                rec.status, rec.size, rec.path, rec.query,
                                rec.referer, rec.ua, src, "", ""])
                    rows += 1
            for f in ssl_files:
                src = str(f.relative_to(ctx.evidence))
                for line in iter_log_lines(f):
                    s = parse_ssl_request(line)
                    if s is None:
                        continue
                    t, ip, method, path, query, size, proto, cipher = s
                    w.writerow([t, ip, "", method, "", size, path, query, "", "", src, proto, cipher])
                    rows += 1
    except BaseException:
        # A HALF-WRITTEN timeline is not a shorter timeline. Since v0.7.87 three
        # detection parsers read this file, and the engine merges a failed
        # parser's output into the shared folder anyway (`runner._merge_into`
        # runs outside the try that records the error), so a prefix left here
        # becomes "ok, 3 of 9 detections" with a marker written over it -- the
        # six that are gone do not come back without --force. The disk filling up
        # mid-write is the documented case for a file this size.
        out.unlink(missing_ok=True)
        raise
    if rows == 0:
        out.unlink(missing_ok=True)  # access_log present but empty -> no CSV
    if ctx.log:
        ctx.log.debug(f"web_access: {rows} request(s) from {len(files) + len(ssl_files)} file(s)")
