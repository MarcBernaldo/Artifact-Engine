"""Handler: web server error logs. Output: web_errors.csv

Every Apache/nginx error log on the host (current + rotated .gz + per-vhost),
one row per line, in file order. No filtering, no flags: this is the record the
analyst reads next to `web_access` -- PHP warnings that name the script and line
a request reached, ModSecurity denials, upstream failures, and the output of
child processes, which Apache writes to the error log without a prefix.

Line formats:

  Apache 2.4  [Wed Oct 11 14:32:52.123456 2026] [php:warn] [pid 123:tid 4]
              [client 10.0.0.5:51234] AH01071: msg, referer: http://example.local/
  Apache 2.2  [Wed Oct 11 14:32:52 2026] [error] [client 10.0.0.5] msg
  nginx       2026/10/11 14:32:52 [error] 123#0: *45 msg, client: 10.0.0.5,
              server: example.local, request: "GET / HTTP/1.1", host: "example.local"

(each on one line).

Both write host-local time with the year and no offset: `time_local` keeps it,
`time_utc` converts it with the host's zone (empty when the acquisition does not
name one). A line in neither format keeps only `message`.
"""

from __future__ import annotations

import csv
import re

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import iter_log_lines, root
from artifact_engine.handlers._syslogtime import Clock

_LOG_BASES = ("var/log/apache2", "var/log/httpd", "var/log/nginx", "var/log/lighttpd")

_HEADER = ["time_local", "time_utc", "level", "module", "pid", "client", "message",
           "request", "server", "host", "referer", "source"]

_MONTHS = {m: f"{i:02d}" for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

# [Wed Oct 11 14:32:52.123456 2026]
_APACHE_TS = re.compile(r"^\[\w{3} (\w{3}) +(\d{1,2}) (\d\d:\d\d:\d\d)(\.\d+)? (\d{4})\] ")
_BRACKET = re.compile(r"\[([^\]]*)\] ?")
_NGINX = re.compile(r"^(\d{4})/(\d\d)/(\d\d) (\d\d:\d\d:\d\d) \[(\w+)\] (\d+)#\d+: (?:\*\d+ )?")
# nginx's trailing context, in the order it writes it
_NGINX_CTX = re.compile(r', (client|server|request|upstream|host|referrer): ("(?:[^"\\]|\\.)*"|[^,]*)')


def _files(evidence):
    r = root(evidence)
    for base in _LOG_BASES:
        d = r / base
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*")):
            if f.is_file() and "error" in f.name.lower() and f.suffix.lower() not in (".json", ".conf"):
                yield f


def _client(v: str) -> str:
    """`10.0.0.5:51234` -> `10.0.0.5`. An IPv6 address keeps what Apache wrote:
    its port cannot be told from the address."""
    return v.rpartition(":")[0] if v.count(":") == 1 else v


def _apache(line: str, m) -> list[str]:
    month = _MONTHS.get(m.group(1), "00")
    local = f"{m.group(5)}-{month}-{int(m.group(2)):02d} {m.group(3)}{m.group(4) or ''}"
    level = module = pid = client = ""
    rest = line[m.end():]
    while rest.startswith("["):
        b = _BRACKET.match(rest)
        if not b:
            break
        tag = b.group(1)
        if tag.startswith("pid "):
            pid = tag[4:]
        elif tag.startswith(("client ", "remote ")):
            client = _client(tag.split(" ", 1)[1])
        elif not level and " " not in tag:
            module, _, level = tag.rpartition(":")
        else:
            break
        rest = rest[b.end():]
    msg, sep, referer = rest.rpartition(", referer: ")
    if not sep:
        msg, referer = rest, ""
    return [local, level, module, pid, client, msg, "", "", "", referer]


def _nginx(line: str, m) -> list[str]:
    local = f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}"
    rest = line[m.end():]
    ctx = {}
    i = rest.find(", client: ")
    if i >= 0:
        for c in _NGINX_CTX.finditer(rest, i):
            v = c.group(2)
            ctx[c.group(1)] = v[1:-1] if v.startswith('"') and v.endswith('"') else v
        rest = rest[:i]
    return [local, m.group(5), "", m.group(6), ctx.get("client", ""), rest,
            ctx.get("request", ""), ctx.get("server", ""), ctx.get("host", ""),
            ctx.get("referrer", "")]


def parse(line: str) -> list[str]:
    """[time_local, level, module, pid, client, message, request, server, host, referer]"""
    m = _APACHE_TS.match(line)
    if m:
        return _apache(line, m)
    m = _NGINX.match(line)
    if m:
        return _nginx(line, m)
    return ["", "", "", "", "", line, "", "", "", ""]


def run(ctx) -> None:
    files = list(_files(ctx.evidence))
    if not files:
        raise HandlerSkip("no apache/nginx error logs")

    clock = Clock(ctx.evidence)
    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "web_errors.csv"
    rows = 0
    try:
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(_HEADER)
            for f in files:
                src = str(f.relative_to(ctx.evidence))
                for line in iter_log_lines(f):
                    if not line.strip():
                        continue
                    rec = parse(line.rstrip("\r"))
                    utc = clock.utc(rec[0][:19], None) if rec[0] else ""
                    w.writerow([rec[0], utc, *rec[1:], src])
                    rows += 1
    except BaseException:
        out.unlink(missing_ok=True)          # a prefix is not a shorter table
        raise
    if rows == 0:
        out.unlink(missing_ok=True)
    if ctx.log:
        ctx.log.debug(f"web_errors: {rows} line(s) from {len(files)} file(s)")
