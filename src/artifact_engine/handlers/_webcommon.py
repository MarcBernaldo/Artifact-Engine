"""Shared web-log helpers for lin_web_access / lin_huntweb.

Covers Apache (Debian `access.log*`, RHEL/SUSE `access_log*`, per-vhost
subdirs) and nginx, including rotated `.gz/.xz/.bz2` archives. Lines are the
Common/Combined Log Format; parsing is tolerant of malformed request fields.
"""

from __future__ import annotations

import bz2
import gzip
import ipaddress
import lzma
import re
from pathlib import Path
from urllib.parse import unquote

from artifact_engine.handlers._lincommon import root

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


def iter_access_files(evidence: Path, clf_only: bool = True, csv_ok: bool = False):
    """Yield every access-log file (current + rotated + per-vhost), newest dirs
    first. Excludes error logs and non-log files.

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
_LINE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3}|-)\s+(?P<size>\S+)'
    r'(?:\s+[^"\r\n]*?"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<ua>(?:[^"\\]|\\.)*)")?'
)

# Reverse-proxy real-client IP. Behind a load balancer / CDN the connecting %h is
# the frontend and the true client is in X-Forwarded-For -- here logged as a
# trailing `X-Forwarded-For="1.2.3.4"` field (a custom LogFormat). XFF is a comma
# list "client, proxy1, proxy2" whose LEFTMOST hop is the originating client. It
# is client-settable (spoofable), but the connecting IP is only ever the proxy,
# so for attribution the client wins and the frontend is kept as `edge_ip`.
_XFF = re.compile(r'x-forwarded-for\s*[=:]\s*"?\s*([0-9a-fA-F.:, ]+)', re.I)


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
    __slots__ = ("ip", "edge_ip", "time", "method", "path", "query", "status",
                 "size", "referer", "ua")

    def __init__(self, ip, time, method, path, query, status, size, referer, ua,
                 edge_ip=""):
        # `ip` is the effective CLIENT (X-Forwarded-For when present, else the
        # connecting host); `edge_ip` is the connecting frontend/proxy when a
        # different client was recovered from XFF, else "" (direct request).
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
        if line.endswith('"'):
            line = line[:-1]
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
    return Record(
        ip=client or connecting,
        edge_ip=connecting if client else "",
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


def is_hosting(org: str) -> bool:
    o = org.lower()
    return any(k in o for k in _HOSTING)


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
            import maxminddb  # noqa: PLC0415 - optional, only needed for geo
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
