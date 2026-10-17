"""Handler: mod_ssl's request log. Output: web_ssl_requests.csv

RHEL's default ssl.conf writes every HTTPS request a second time, to
`ssl_request_log`, in its own format:

  [11/Oct/2026:14:32:52 +0200] 10.0.0.5 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 "GET /x?a=1 HTTP/1.1" 5120

The same requests are normally in the vhost's access log too, which is why this
is a table of its own and not part of web_access: there they would be counted
twice by every web parser. What it adds is the TLS protocol and cipher each
client negotiated. No filtering, no flags.

`time` keeps the offset it was logged with, like web_access.
"""

from __future__ import annotations

import csv
import re

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import iter_log_lines, root
from artifact_engine.handlers._webcommon import _LOG_BASES, _iso_time

_HEADER = ["time", "ip", "protocol", "cipher", "method", "path", "query", "http_version",
           "size", "source"]
_LINE = re.compile(r'^\[([^\]]+)\] (\S+) (\S+) (\S+) "((?:[^"\\]|\\.)*)" (\S+)\s*$')


def _files(evidence):
    r = root(evidence)
    for base in _LOG_BASES:
        d = r / base
        if d.is_dir():
            yield from (f for f in sorted(d.rglob("*")) if f.is_file() and "ssl_request" in f.name.lower())


def _request(raw: str) -> tuple[str, str, str, str]:
    """`GET /x?a=1 HTTP/1.1` -> (method, path, query, version); a malformed
    request stays whole in `path`."""
    parts = raw.split(" ")
    if len(parts) != 3:
        return "", raw, "", ""
    method, target, version = parts
    path, _, query = target.partition("?")
    return method, path, query, version


def run(ctx) -> None:
    files = list(_files(ctx.evidence))
    if not files:
        raise HandlerSkip("no mod_ssl ssl_request_log")
    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "web_ssl_requests.csv"
    rows = 0
    try:
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(_HEADER)
            for f in files:
                src = str(f.relative_to(ctx.evidence))
                for line in iter_log_lines(f):
                    m = _LINE.match(line.rstrip("\r"))
                    if not m:
                        continue
                    ts, ip, proto, cipher, req, size = m.groups()
                    w.writerow([_iso_time(ts), ip, proto, cipher, *_request(req), size, src])
                    rows += 1
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    if rows == 0:
        out.unlink(missing_ok=True)
    if ctx.log:
        ctx.log.debug(f"web_ssl_requests: {rows} request(s) from {len(files)} file(s)")
