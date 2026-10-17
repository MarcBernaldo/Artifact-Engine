"""Shared web-log helpers for the four web parsers.

`iter_records` is where they take their requests from (web_hunt and web_metrics
read a large timeline in slices instead, `_webshard`), so the access logs are
read and CLF-parsed ONCE per volume instead of once per parser (v0.7.87).

Covers Apache (Debian `access.log*`, RHEL/SUSE `access_log*`, per-vhost
subdirs) and nginx, including rotated `.gz/.xz/.bz2` archives, plus (v0.7.151)
every log the server's own config names elsewhere (`configured_logs`). Lines are the
Common/Combined Log Format, also with extra fields before `%l %u` (an
X-Forwarded-For after the proxy, vhost_combined's `%v:%p`); parsing is tolerant
of malformed request fields.
"""

from __future__ import annotations

import bz2
import csv
import gzip
import ipaddress
import lzma
import posixpath
import re
from pathlib import Path
from urllib.parse import unquote

from artifact_engine.core.sigma_prefilter import trie_pattern
from artifact_engine.handlers._lincommon import iter_log_lines, read_lines, root

WEB_CATEGORY = "web"

# Where web servers keep access logs (relative to [root]).
_LOG_BASES = ("var/log/apache2", "var/log/httpd", "var/log/nginx", "var/log/lighttpd")

# Loose-drop fallback exclusions: the tool's own outputs living inside the
# machine folder, plus files that are never access logs. Containers are skipped
# because `extract_drops` already unpacked them next to themselves; standalone
# .gz stays (rotated logs, streamed by iter_log_lines).
_DROP_SKIP_DIRS = {"csvs", "jsons"}
_DROP_SKIP_EXT = (".json", ".conf", ".csv", ".db", ".xlsx", ".zip", ".7z",
                  ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")

_SNIFF_OPENERS = {".gz": gzip.open, ".xz": lzma.open, ".bz2": bz2.open}

# How many leading lines a fallback candidate gets to prove it is an access log.
_PROBE_LINES = 20


def _looks_access_log(f: Path, clf_only: bool = True) -> bool:
    """Sniff for the loose-drop fallback: keep a file only if one of its first
    lines parses as CLF/combined. A full /var/log export carries journald
    journals, lastlog, mysql data (binary, often HUGE -- real case: 953 MB of
    journal vs 15 MB of access logs) plus syslog/installer/cloud-init (text but
    never CLF), and running the per-line hunt regexes over them burns minutes
    for zero rows. Probing ~20 decompressed lines costs microseconds.

    `clf_only=False` keeps every TEXT file (binary still sniffed out) -- for
    callers that enumerate drop files with their own format probe (fortigate)."""
    opener = _SNIFF_OPENERS.get(f.suffix.lower())
    try:
        with (opener or open)(f, "rb") as fh:
            head = fh.read(65536)
    except (OSError, EOFError, ValueError, lzma.LZMAError):
        return False
    if b"\x00" in head:
        return False                             # binary, never an access log
    if not clf_only:
        return True
    lines = head.decode("utf-8", "replace").splitlines()
    return any(parse(ln) for ln in lines[:_PROBE_LINES] if ln.strip())


# Log directives in the web server's own config: where a site writes its logs
# when that is not /var/log -- a disk of its own, often through a piped
# rotatelogs/cronolog that stamps the date into the name or the directories.
_CONF_DIRS = ("etc/apache2", "etc/httpd", "etc/nginx")
_LOG_DIRECTIVE = re.compile(
    r"""^\s*(CustomLog|TransferLog|ErrorLog|access_log|error_log)\s+("[^"]*"|'[^']*'|\S+)""",
    re.IGNORECASE)
_DEFINE = re.compile(r"""^\s*Define\s+(\w+)\s+("[^"]*"|\S+)""", re.IGNORECASE)
_DEFINED = re.compile(r"\$\{(\w+)\}")
# Piped-logger options that take a value; the same letter differs between the
# two (rotatelogs -l is local time, cronolog -l a link name).
_PIPE_OPTS_WITH_ARG = {"rotatelogs": {"-L", "-p", "-n"},
                       "cronolog": {"-H", "-S", "-l", "-P", "-p", "-d", "-z"}}
_CONF_MAX = 1 << 20                              # bigger is not a config file
_NAME_VARIABLE = re.compile(r"[%$]")


def _log_target(value: str, defines: dict[str, str]) -> str:
    """The absolute file a log directive writes: the value itself, or the logfile
    argument of a piped logger (`"| /usr/sbin/rotatelogs -l /srv/logs/access.%Y%m%d
    86400"`: the first argument that is not an option or an option's value).
    `${NAME}` is filled from Apache's `Define`s. '' for syslog, off, stderr,
    /dev/* and relative paths (under ServerRoot, whose `logs` is /var/log/httpd)."""
    v = value.strip().strip("\"'").strip().rstrip(";")
    if v.startswith("|"):
        prog, *args = v[1:].split() or [""]
        with_arg = _PIPE_OPTS_WITH_ARG.get(prog.rsplit("/", 1)[-1], set())
        v, skip = "", False
        for a in args:
            if skip:
                skip = False
            elif a.startswith("-"):
                skip = a in with_arg
            else:
                v = a
                break
    v = _DEFINED.sub(lambda m: defines.get(m.group(1), m.group(0)), v)
    if not v.startswith("/") or v.startswith("/dev/"):
        return ""
    return posixpath.normpath(v)


def _log_entry(r: Path, path: str) -> tuple[Path, str, bool] | None:
    """(directory, file-name prefix, walk below it) for a configured log path. The
    prefix is the name up to its first strftime field or variable, so rotations
    and dated names match; a field in a DIRECTORY (`/srv/logs/%Y/%m/access.log`)
    makes the fixed part above it a tree to walk. A directory two or more levels
    below `/` is walked too (v0.7.159), for the rotations a site archives into a
    subdirectory of its log dir. None when the name starts with a variable (nginx
    `$host.log`) or a dated directory sits right under `/`."""
    *dirs, name = [p for p in path.split("/") if p] or [""]
    fixed = []
    for d in dirs:
        if _NAME_VARIABLE.search(d):
            break
        fixed.append(d)
    prefix = _NAME_VARIABLE.split(name, maxsplit=1)[0]
    if not prefix or (len(fixed) < len(dirs) and len(fixed) < 2):
        return None
    return r.joinpath(*fixed), prefix, len(fixed) >= 2


def configured_logs(evidence: Path) -> dict[str, list[tuple[Path, str, bool]]]:
    """{"access": [(dir, name prefix, walk), ...], "error": [...]} from the log
    directives in every apache/nginx config file of a UAC acquisition."""
    out: dict[str, list[tuple[Path, str, bool]]] = {"access": [], "error": []}
    r = evidence / "[root]"
    if not r.is_dir():
        return out                               # a loose drop has no config
    texts = []
    for base in _CONF_DIRS:
        d = r / base
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*")):
            try:
                if f.is_file() and f.stat().st_size <= _CONF_MAX:
                    texts.append(read_lines(f))
            except OSError:
                continue
    defines = {"APACHE_LOG_DIR": "/var/log/apache2"}     # Debian's envvars default
    for lines in texts:
        for ln in lines:
            m = _DEFINE.match(ln)
            if m:
                defines[m.group(1)] = m.group(2).strip('"')
    for lines in texts:
        for ln in lines:
            m = _LOG_DIRECTIVE.match(ln)
            path = _log_target(m.group(2), defines) if m else ""
            entry = _log_entry(r, path) if path else None
            if entry is None:
                continue
            kind = "error" if m.group(1).lower() in ("errorlog", "error_log") else "access"
            if entry not in out[kind]:
                out[kind].append(entry)
    return out


def _resolved(f: Path) -> Path:
    try:
        return f.resolve()
    except OSError:
        return f


def _configured_files(entries, seen: set):
    """The files of configured log entries, each once: `seen` holds RESOLVED
    paths, so a config path through a symlink (RHEL's /etc/httpd/logs) does not
    read a standard-dir file a second time."""
    for d, prefix, walk in entries:
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*") if walk else d.iterdir()):
            if (not f.is_file() or not f.name.startswith(prefix)
                    or f.suffix.lower() in (".json", ".conf")):
                continue
            key = _resolved(f)
            if key not in seen:
                seen.add(key)
                yield f


def iter_error_files(evidence: Path):
    """Every web server error log: the standard log dirs (any file with `error`
    in its name) and the ErrorLog/error_log files the config names elsewhere."""
    r = root(evidence)
    seen: set = set()
    for base in _LOG_BASES:
        d = r / base
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*")):
            if f.is_file() and "error" in f.name.lower() and f.suffix.lower() not in (".json", ".conf"):
                seen.add(_resolved(f))
                yield f
    yield from _configured_files(configured_logs(evidence)["error"], seen)


def iter_ssl_request_files(evidence: Path):
    """mod_ssl's `ssl_request_log` files (RHEL's default ssl.conf) in the standard
    log dirs: a second record of HTTPS requests, in a format of its own."""
    r = root(evidence)
    for base in _LOG_BASES:
        d = r / base
        if d.is_dir():
            yield from (f for f in sorted(d.rglob("*")) if f.is_file() and "ssl_request" in f.name.lower())


# [11/Oct/2026:14:32:52 +0200] 10.0.0.5 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 "GET /x?a=1 HTTP/1.1" 5120
_SSL_REQUEST = re.compile(r'^\[([^\]]+)\] (\S+) (\S+) (\S+) "((?:[^"\\]|\\.)*)" (\S+)\s*$')


def parse_ssl_request(line: str) -> tuple[str, str, str, str, str, str, str, str] | None:
    """(time, ip, method, path, query, size, tls_protocol, tls_cipher) of an
    ssl_request_log line, None when it is not one. A malformed request stays
    whole in `path`."""
    m = _SSL_REQUEST.match(line.rstrip("\r"))
    if not m:
        return None
    ts, ip, proto, cipher, req, size = m.groups()
    parts = req.split(" ")
    if len(parts) == 3:
        method, target = parts[0], parts[1]
        path, _, query = target.partition("?")
    else:
        method, path, query = "", req, ""
    return _iso_time(ts), ip, method, path, query, size, proto, cipher


def iter_access_files(evidence: Path, clf_only: bool = True, csv_ok: bool = False):
    """Yield every access-log file (current + rotated + per-vhost), newest dirs
    first. Excludes error logs and non-log files. Then (v0.7.151) the files the
    server's config names with CustomLog/TransferLog/access_log, wherever they are
    (v0.7.159: also the rotations archived into a subdirectory of a log dir).

    `csv_ok=True` keeps `.csv/.tsv` files in the loose-drop fallback (FortiGate/
    FortiAnalyzer exports arrive as CSV); our own outputs stay excluded because
    they live under the skipped `CSVs/` tree.

    Fallback for a LOOSE drop (the `weblogs[-label]` folder profile): when the
    evidence has no `[root]/` (so it is not a UAC acquisition), every file in the
    tree is offered instead -- exports arrive named any which way
    (`www_client_com.log`, `ssl_log-20260101.gz`), and the analyst put them there
    on purpose. Error logs, configs and the tool's own outputs are skipped; a
    non-CLF file simply parses to 0 rows."""
    r = root(evidence)
    found = False
    seen: set = set()
    for base in _LOG_BASES:
        d = r / base
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            n = f.name.lower()
            if "access" not in n or "error" in n:
                continue
            if f.suffix.lower() in (".json", ".conf"):
                continue
            found = True
            seen.add(_resolved(f))
            yield f
    conf = configured_logs(evidence)
    # A CustomLog prefix can also match its vhost's error log (`site` and
    # `site.err`): those the config names are left out, and so is any file named
    # `error`, as in the standard dirs -- an ErrorLog given relative is not named.
    errors = {_resolved(f) for f in _configured_files(conf["error"], set())}
    for f in _configured_files(conf["access"], seen):
        if _resolved(f) not in errors and "error" not in f.name.lower():
            found = True
            yield f
    if found or (evidence / "[root]").is_dir():
        return           # real acquisition (or the drop mirrors var/log): no fallback
    for f in sorted(evidence.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(evidence)
        if any(p.lower() in _DROP_SKIP_DIRS for p in rel.parts[:-1]):
            continue                             # our CSVs/JSONs output tree
        n = f.name.lower()
        if n.startswith(".") or "error" in n:
            continue                             # markers / error logs
        skip_ext = _DROP_SKIP_EXT
        if csv_ok:
            skip_ext = tuple(e for e in skip_ext if e not in (".csv", ".tsv"))
        if n.endswith(skip_ext) or n in (
                "run.json", "report.txt", "aeng-run.log", "traces.txt",
                "traces.csv", "run-summary.txt", "run-summary.json"):
            continue                             # the tool's own root outputs
        if not _looks_access_log(f, clf_only):
            continue                             # binary or non-CLF (journald, syslog, ...)
        yield f


# Combined Log Format. Request/referer/UA allow escaped quotes (\" \xNN) so an
# attack line with embedded quotes still parses. Referer+UA are optional (plain
# Common Log Format has neither). Between the size and the "referer"/"ua" pair we
# tolerate extra unquoted fields (`[^"]*?`): SSL vhosts commonly log
# `%{SSL_PROTOCOL}x %{SSL_CIPHER}x` there, and others add `%D %T` -- without this
# the referer/UA (and thus every UA-based detection) are lost on HTTPS logs.
# A quoted field with backslash escapes, written as an "unrolled loop" rather
# than the obvious `(?:[^"\\]|\\.)*`. Both accept exactly the same language, but
# the alternation form makes the engine try two branches at EVERY character,
# while this one consumes runs of ordinary characters in a single step and only
# stops for a real escape. Measured on 300,000 real access-log lines (340 chars
# average): 65k lines/s before, 390k after -- a 6x speed-up of the match, with
# byte-identical capture groups on every one of those lines. It matters because
# the regex was 68% of `parse`, `parse` is 94% of the read loop, and four
# separate web parsers each run that loop over the whole log set.
#
# Up to four extra unquoted fields may sit between the first field and `%l %u
# [time]` (`pre`): a LogFormat that logs `%h %{X-Forwarded-For}i %l %u ...`
# (the proxy, then the client), Debian's vhost_combined `%v:%p %h %l %u ...`
# (the vhost, then the client). Without them every line of such a log failed to
# parse -- on one real web server, 97% of its access lines. `_extra_client` says
# which field is the client.
_Q = r'[^"\\]*(?:\\.[^"\\]*)*'
_LINE = re.compile(
    r'^(?P<ip>\S+)(?P<pre>(?:\s+[^\s\[]+){0,4}?)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>' + _Q + r')"\s+(?P<status>\d{3}|-)\s+(?P<size>\S+)'
    r'(?:\s+[^"\r\n]*?"(?P<referer>' + _Q + r')"\s+"(?P<ua>' + _Q + r')")?'
)

# Reverse-proxy real-client IP. Behind a load balancer / CDN the connecting %h is
# the frontend and the true client is in X-Forwarded-For -- here logged as a
# trailing `X-Forwarded-For="1.2.3.4"` field (a custom LogFormat). XFF is a comma
# list "client, proxy1, proxy2" whose LEFTMOST hop is the originating client. It
# is client-settable (spoofable), but the connecting IP is only ever the proxy,
# so for attribution the client wins and the frontend is kept as `edge_ip`.
_XFF = re.compile(r'x-forwarded-for\s*[=:]\s*"?\s*([0-9a-fA-F.:, ]+)', re.IGNORECASE)


def _xff_client(tail: str) -> str:
    """Leftmost valid IP of a trailing X-Forwarded-For field, or '' if absent /
    unusable (`-`, `unknown`). Scans left-to-right so the first real IP wins even
    if the header opens with a junk token."""
    m = _XFF.search(tail)
    if not m:
        return ""
    for tok in m.group(1).split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            ipaddress.ip_address(tok)
            return tok
        except ValueError:
            continue
    return ""

def _ip(tok: str) -> str:
    tok = tok.strip(",")
    try:
        ipaddress.ip_address(tok)
    except ValueError:
        return ""
    return tok


def _extra_client(first: str, pre: str) -> tuple[str, str]:
    """(client, edge) from the extra fields before `%l %u`, or ('', '').

    The leftmost address among them is the client. When the first field is an
    address too, it is the proxy that connected (`%h %{X-Forwarded-For}i`) and
    becomes `edge_ip`; when it is not (`%v:%p %h`, a vhost), there is no proxy.
    An extra field of `-` (no X-Forwarded-For on that request) names nobody."""
    for tok in pre.split():
        client = _ip(tok)
        if client:
            return (client, first) if _ip(first) else (client, "")
    return "", ""


_MONTHS = {m: f"{i:02d}" for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
# 19/May/2026:09:11:17 +0000
_TS = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})\s*([+-]\d{4})?")


def _iso_time(raw: str) -> str:
    """CLF timestamp -> '2026-05-19 09:11:17 +0000' (sortable), or raw on miss."""
    m = _TS.match(raw)
    if not m:
        return raw
    day, mon, year, hms, tz = m.groups()
    mm = _MONTHS.get(mon, "00")
    return f"{year}-{mm}-{day} {hms} {tz or ''}".rstrip()


class Record:
    # Field order mirrors the log line, not the alphabet: this is the shape of a
    # request as it was written.
    __slots__ = ("ip", "edge_ip", "time", "method", "path", "query", "status",  # noqa: RUF023
                 "size", "referer", "ua")

    def __init__(self, ip, time, method, path, query, status, size, referer, ua,
                 edge_ip=""):
        # `ip` is the effective CLIENT (X-Forwarded-For when present, else the
        # connecting host); `edge_ip` is the connecting frontend/proxy when a
        # different client was recovered from XFF or from an extra field before
        # `%l %u`, else "" (direct request, or a vhost first field).
        self.ip, self.edge_ip, self.time, self.method = ip, edge_ip, time, method
        self.path, self.query, self.status = path, query, status
        self.size, self.referer, self.ua = size, referer, ua


def parse(line: str):
    """Parse one access-log line into a Record, or None if it isn't one."""
    # Some exporters wrap the WHOLE CLF line in double quotes with the inner quotes
    # left unescaped, e.g. `"1.2.3.4 - - [..] "GET / HTTP/1.1" 200 5 "-" "UA""`. A
    # real CLF line never starts with a quote, so a leading " marks this wrapping;
    # peel it (and its matching trailing ") so the IP/UA aren't captured with a
    # stray quote.
    if line.startswith('"'):
        line = line[1:]
        line = line.removesuffix('"')
    m = _LINE.match(line)
    if not m:
        return None
    req = m.group("request")
    method = path = query = ""
    proto_split = req.rsplit(" ", 1)
    # request = "METHOD URI PROTO"; tolerate missing pieces / spaces in URI.
    head = proto_split[0]
    if " " in head:
        method, _, uri = head.partition(" ")
    else:
        method, uri = "", head
    if "?" in uri:
        path, _, query = uri.partition("?")
    else:
        path = uri
    # Recover the real client from a trailing X-Forwarded-For, if any. Only the
    # short tail AFTER the matched combined fields is searched, so an XFF-looking
    # string injected into the URL/UA can't hijack attribution.
    connecting = m.group("ip")
    client = _xff_client(line[m.end():])
    edge = connecting if client else ""
    if not client and m.group("pre"):
        client, edge = _extra_client(connecting, m.group("pre"))
    return Record(
        ip=client or connecting,
        edge_ip=edge,
        time=_iso_time(m.group("time")),
        method=method,
        path=path,
        query=query,
        status=m.group("status"),
        size=m.group("size"),
        referer=(m.group("referer") or ""),
        ua=(m.group("ua") or ""),
    )


_HEX_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")


# --------------------------------------------------------------------------- #
# One parse pass, several readers
# --------------------------------------------------------------------------- #
# MEASURED on a public web server's logs: 90 access files, 2.23 GB on disk (6.8 GB
# of text -- one rotated file is gzipped), 52,493,215 requests. Four web parsers
# each read and CLF-parsed all of it, and one such pass costs 6.0 minutes at
# 145,700 req/s. `web_access` already writes exactly what the other three then
# re-derive, and reading that back is 334,800 req/s -- 2.6 minutes -- because
# `csv.reader` is C where `parse()` is a regex, and only the `Record` is built on
# both sides. So three of the four passes are replaced by a read of the first
# one's output: 3.4 minutes saved per consumer, about 10 of CPU on that volume.
# (Both sides timed the same way -- streaming, discarding, over all 90 files.
# Timed differently they disagree by 3x in either direction, which is how the
# first pair of figures for this commit came out wrong twice.)
#
# NOT a wall-clock fix for a long tail, and it COSTS wall clock on the host that
# has one. The four passes ran in parallel, so what this buys is CPU -- the
# machine's time back for the other units. What it costs is the dependency: the
# three readers are level 1 now, and `scheduler.run_all` runs one level at a time
# and waits for all of it ACROSS EVERY MACHINE in the case, so they cannot start
# until the last level-0 task of the last unit has finished. On a case whose other
# units are quick that is roughly `web_access`'s own 6 min; on a case where they
# are not, it is however long they take. Chosen deliberately: on a five-host run
# the duplicated passes compete for the same cores as everything else. The parser
# that sets the tail there is `web_sigma`, and profiled over 52.5 M requests its
# cost is `_scan` -- the per-batch insert plus the 16 rules, 8.6 min -- against
# 2.6 min of reading. The reading was never the thing to fix.
#
# `web_access.csv` is a lossless round-trip of a `Record`: on an access-log row the
# first eleven columns are the ten slots plus the source file (the two TLS columns
# after them are filled only on mod_ssl rows, which `request_row` skips). That is
# what makes this safe, and the header
# is CHECKED rather than assumed -- a column added or moved there without this
# list falls back to the raw logs instead of mapping the wrong field onto a
# detection.
_PREPARSED = Path("CSVs") / "Web" / "web_access.csv"

# A request line no web server accepts (Apache caps at 8 KB, nginx at 8 KB by
# default), with room for a proxy export that caps nothing. `csv`'s own default
# is 128 KB, and one longer field -- an attacker-controlled URI, which `parse()`
# itself reads without complaint -- aborted the whole iteration and cost all
# three readers their entire output for that volume (found by review).
_MAX_FIELD = 4 * 1024 * 1024

# Exactly `lin_web_access._HEADER`. Stated here as well, because the two files are
# the two ends of this contract and a silent disagreement is the failure mode.
# Rows with a `tls_cipher` come from mod_ssl's ssl_request_log (v0.7.156): the
# same requests the access logs hold, so the detections never read them --
# `request_row` is the one test both readers apply.
_PREPARSED_HEADER = ["time", "ip", "edge_ip", "method", "status", "size", "path",
                     "query", "referer", "ua", "source", "tls_protocol", "tls_cipher"]


def request_row(r: list[str]) -> bool:
    """True for a full web_access.csv row of an ACCESS log (not ssl_request_log)."""
    return len(r) == len(_PREPARSED_HEADER) and not r[12]


def _preparsed_ok(path: Path) -> bool:
    """True when `path` is a web_access.csv this reader can map field for field."""
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            head = next(csv.reader(fh), None)
    except (OSError, csv.Error):
        return False
    return head == _PREPARSED_HEADER


def _from_csv(path: Path):
    """(Record, source) per row of a pre-parsed timeline.

    `csv.reader` and fixed indices, not `DictReader`: on 52 M rows the dict per
    row is most of the cost this exists to avoid."""
    if csv.field_size_limit() < _MAX_FIELD:
        csv.field_size_limit(_MAX_FIELD)
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        rows = csv.reader(fh)
        next(rows, None)        # the header, already checked
        for r in rows:
            if not request_row(r):
                continue        # cut short by a full disk, or mod_ssl's second record
            yield Record(r[1], r[0], r[3], r[6], r[7], r[4], r[5], r[8], r[9],
                         edge_ip=r[2]), r[10]


def _from_raw(evidence: Path, files):
    """(Record, source) per request, parsed out of the raw access logs."""
    for f in files:
        try:
            src = str(f.relative_to(evidence))
        except ValueError:
            src = f.name
        for line in iter_log_lines(f):
            rec = parse(line)
            if rec is not None:
                yield rec, src


def _source(ctx) -> tuple[list[Path], Path | None]:
    """(access logs, the timeline `iter_records` reads -- or None for the raw
    logs). Raises `HandlerSkip` when there are no access logs; see below."""
    from artifact_engine.core.runner import HandlerSkip, marker_path

    files = list(iter_access_files(ctx.evidence))
    if not files:
        raise HandlerSkip("no apache/nginx access logs")
    pre = Path(ctx.evidence) / _PREPARSED
    done = marker_path(pre.parent, "web_access")
    if pre.is_file() and done.is_file() and _preparsed_ok(pre):
        return files, pre
    return files, None


def iter_records(ctx):
    """(Record, source) for every request on this volume, parsed ONCE.

    Reads the pre-parsed timeline when `web_access` has written one, and the raw
    logs when it has not. The fallback is the point of the function, not a
    leftover: `web_access` can be absent from a tree's parser set, or skip, or be
    the one parser an analyst removed to avoid its output on a 50-million-request
    host -- and a web ATTACK view that silently reported nothing in that case
    would be the worst of the three outcomes. Which path was taken is logged,
    because "no detections" and "no input" must not read alike.

    Raises `HandlerSkip` when the volume has no access logs at all. NOT a
    generator function: the skip has to raise where it is called, not on the
    first line a caller pulls.

    The LOGS decide whether there is anything to read, and the timeline only
    where the records come from. Asking the CSV first let a leftover one -- a case
    parsed by an earlier version whose bulky logs were then pruned to reclaim the
    space -- report detections on a volume where `web_access` itself answers "no
    apache/nginx access logs", with nothing anywhere saying the requests came from
    evidence that is no longer there (found by review).

    And the timeline is read only once `web_access` has SAID it finished: its
    marker is written by `runner.run_parser` on `status == "ok"` and on nothing
    else. Without that check a pass that died mid-write handed these three a
    prefix of its own output -- see the comment in `lin_web_access.run`, which is
    where that is really fixed; this is the second line of defence, because the
    merge is the engine's bookkeeping and not that parser's."""
    files, pre = _source(ctx)
    if pre is not None:
        if ctx.log:
            ctx.log.debug(f"web: reading the pre-parsed timeline ({_PREPARSED.name})")
        return _from_csv(pre)
    if ctx.log:
        ctx.log.debug(f"web: parsing {len(files)} raw access log file(s) "
                      f"(no usable {_PREPARSED.name})")
    return _from_raw(Path(ctx.evidence), files)


def decode(s: str) -> str:
    """Aggressively normalise an attacker-controlled string for matching:
    resolve `\\xNN` escapes, URL-decode twice (defeats single double-encoding),
    turn '+' into space, lowercase."""
    if not s:
        return ""
    s = _HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), s)
    s = unquote(unquote(s.replace("+", " ")))
    return s.lower()


# --------------------------------------------------------------------------- #
# Offline IP origin: db-ip country-lite mmdb + Tor exit list (via `aeng setup`)
# --------------------------------------------------------------------------- #
HOME_COUNTRY = "ES"
COUNTRY_DB = "dbip-country-lite.mmdb"
ASN_DB = "dbip-asn-lite.mmdb"
TOR_LIST = "tor-exit-nodes.txt"

# Substrings (lowercase) in an AS-org name that mark a hosting/cloud/VPN/proxy
# network rather than a residential/corporate ISP -- attacker traffic almost
# always originates from these. Best-effort: the `asn` column always carries the
# raw org so the analyst can judge anything this list misses. Includes the major
# clouds, generic infra terms, and a few well-documented bulletproof providers.
_HOSTING = (
    "hosting", "datacenter", "data center", "dedicated", "colocation", "colo ",
    "vps", "server", "cloud", "virtual", "vpn", "proxy", "seedbox", "datacamp",
    "amazon", "aws", "google", "microsoft", "azure", "ovh", "digitalocean",
    "digital ocean", "hetzner", "linode", "akamai", "cloudflare", "vultr",
    "leaseweb", "contabo", "scaleway", "alibaba", "tencent", "huawei", "oracle",
    "m247", "choopa", "fastly", "ionos", "godaddy", "namecheap", "rackspace",
    "softlayer", "gcore", "g-core", "limestone", "psychz", "quadranet",
    "hostinger", "dreamhost", "kamatera", "netcup", "worldstream", "serverius",
    "hostwinds", "frantech", "buyvm", "colocrossing", "hostkey", "ipxo",
    "nordvpn", "mullvad", "expressvpn", "cyberghost", "surfshark", "proton",
    "windscribe", "ipvanish", "private internet",
    # documented bulletproof / abuse-friendly
    "aeza", "stark industries", "chang way", "flokinet", "njalla", "pq hosting",
    "mivocloud", "bucklog", "spectre operations", "railnet", "green floid",
)


_HOSTING_RX = re.compile(trie_pattern(_HOSTING))


def is_hosting(org: str) -> bool:
    return _HOSTING_RX.search(org.lower()) is not None


class Geo:
    """Resolve an IP to (country, origin, asn) fully offline. Degrades
    gracefully: missing db/lib -> country '?'/asn '', origin from private/Tor."""

    def __init__(self, assets: Path):
        self._country_db = self._open(assets / COUNTRY_DB)
        self._asn_db = self._open(assets / ASN_DB)
        self._tor: set[str] = set()
        tor = assets / TOR_LIST
        if tor.is_file():
            try:
                self._tor = {ln.strip() for ln in tor.read_text(
                    encoding="utf-8", errors="replace").splitlines()
                    if ln.strip() and not ln.startswith("#")}
            except OSError:
                self._tor = set()

    @staticmethod
    def _open(db: Path):
        try:
            import maxminddb  # local: optional, only needed for geo
            if db.is_file():
                return maxminddb.open_database(str(db))
        except Exception:  # noqa: BLE001 - lib absent or db unreadable
            return None
        return None

    def _country(self, ip: str) -> str:
        if not self._country_db:
            return "?"
        try:
            rec = self._country_db.get(ip)
        except (ValueError, KeyError):
            return "?"
        if isinstance(rec, dict):
            return (rec.get("country") or {}).get("iso_code") or "?"
        return "?"

    def _asn(self, ip: str) -> tuple[int, str]:
        if not self._asn_db:
            return 0, ""
        try:
            rec = self._asn_db.get(ip)
        except (ValueError, KeyError):
            return 0, ""
        if isinstance(rec, dict):
            return (rec.get("autonomous_system_number") or 0,
                    rec.get("autonomous_system_organization") or "")
        return 0, ""

    def lookup(self, ip: str) -> tuple[str, str, str]:
        """(country, origin, asn). origin in: private, local, tor, hosting,
        foreign, unknown. asn = 'AS<n> <org>' (context) or ''."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "?", "unknown", ""
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "LAN", "private", ""
        num, org = self._asn(ip)
        asn = f"AS{num} {org}".strip() if num else ""
        country = self._country(ip)
        if ip in self._tor:
            origin = "tor"
        elif is_hosting(org):
            origin = "hosting"
        elif country == HOME_COUNTRY:
            origin = "local"
        elif country == "?":
            origin = "unknown"
        else:
            origin = "foreign"
        return country, origin, asn
