r"""Cross-machine lateral-movement graph from Windows logon events.

Correlates authentication across every parsed machine into a unified edge list
(lateral_movement.csv) and a self-contained interactive graph (lateral_movement.html,
a vanilla-JS force-directed SVG -- no external libraries, works offline).

Destination-side (EvtxECmd Security channel, already parsed per machine):
  4624 successful logon  (types 3 network / 9 runas / 10 RDP only -- local/service
                          types 2/4/5/7/11 are not lateral movement)
  4625 failed logon      (potential password spraying / brute force)
  4648 explicit creds    (runas / outbound lateral -- this host -> TargetServerName)
  4768 Kerberos TGT      (DC only: which account got a ticket from which IP)
  4769 Kerberos TGS      (DC only: service ticket requests)

Destination-side RDP from the TerminalServices *operational* logs (parsed per
machine), which survive after the Security log has rolled over -- often the only
place a workstation's inbound RDP is still recorded:
  evtx_rdpSessions  LocalSessionManager 21 (logon) / 25 (RECONNECT) -- source in
                    RemoteHost, account in UserName; a LOCAL/link-local session
                    is a console logon, not lateral, and is dropped
  evtx_rdpAuth      RemoteConnectionManager 1149 (RDP authentication succeeded)

Source-side (this host -> where it reached OUT, which the destination's Security
log may never have held or has since rolled over):
  evtx_rdpOut       TerminalServices-RDPClient 1024/1102 -- RDP dial-outs with the
                    real per-connection time. The acting account arrives only as
                    a SID (UserId column); it is resolved to a name through the
                    machine's own ProfileList (reg_profList.csv)
  rdp_outbound.csv  Terminal Server Client MRU -- every RDP target + the account
                    used against it (survives for years)
  explorer_input    TypedPaths that are UNC (\\host\share) -- SMB reached by hand

Hosts acquired in the case are matched by IP (machine_info.json) and name; a peer
outside the case is kept as an EXTERNAL node and highlighted. An edge carries a
reason (-> suspicious=yes, and shown in the graph) for RDP in/out, explicit creds,
failed logons, hand-typed UNC, movement between acquired hosts (case_to_case),
Kerberos service tickets and any corroborating chainsaw verdict; routine inbound
network auth and outside-the-case Kerberos stay in the CSV only.

Pivot chains (X -> B -> Y): a successful inbound logon onto an acquired host is
paired with outbound activity FROM that host by the same account within a time
window -- the defining lateral-movement pattern. Both edges get reason `chain`
and the graph lists each chain in an "Attack paths" panel (click to highlight).

Linux/UAC hosts join the SAME graph (their identity is in machine_info.json, so
IPs/names resolve against the shared index and cross-OS pivots show up):
  wtmp.csv         USER_PROCESS records with a remote `host` -- inbound login with
                   a real (epoch) timestamp: the Linux timeline/chain source
  auth.csv         sshd Accepted / Failed / Invalid user -- inbound SSH with the
                   auth method and the brute-force failures. NOTE: classic syslog
                   lines carry no year, so these often have no parseable time;
                   wtmp/btmp carry the timeline, auth carries method + failures.
  btmp.csv         failed logins (binary, always timestamped) -- brute force/spray
  known_hosts.csv  per-account outbound SSH targets (reference, like RDP-MRU): a
                   graph edge only when it lands on another acquired host
Same low-FP rule as Windows: a routine successful inbound SSH stays in the .csv;
the graph keeps failures, inter-host movement, chains, and `brute_success` (>= 5
failures then a success from the same source).
"""

from __future__ import annotations

import csv
import html
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.core.detector import Machine
from artifact_engine.logging_setup import get_logger

log = get_logger()

# Logon types worth graphing (lateral); the rest are local console / service.
_LATERAL_TYPES = {3, 9, 10}
_TYPE_NAME = {3: "network", 9: "runas", 10: "rdp", 2: "interactive", 11: "cached"}
_EVENTS = {"4624", "4625", "4648", "4768", "4769"}

_RE_LOGON_TYPE = re.compile(r"LogonType\s+(\d+)")
# Stop at the field separator ("|", after PayloadData join) or a comma, so the
# username doesn't swallow the rest of the payload (ServiceName, Status, ...).
_RE_TARGET = re.compile(r"Target:\s*([^|,]+)")
_RE_TARGET_SERVER = re.compile(r"TargetServerName:\s*([^\s|,]+)")
_RE_SERVICE = re.compile(r"ServiceName:\s*([^\s|,]+)")
# RDPClient 1024 records the target as "Dest: <host>", 1102 as "Address: <ip>".
_RE_RDP_DEST = re.compile(r"Dest:\s*([^\s|,]+)")
_RE_RDP_ADDR = re.compile(r"Address:\s*([^\s|,]+)")
_RE_WS_IP = re.compile(r"^(?P<ws>.*?)\s*\((?P<ip>.*)\)\s*$")
_LOCAL = {"", "-", "::1", "127.0.0.1", "localhost", "::ffff:127.0.0.1"}
_MAX_EXTERNAL = 40   # graph keeps only the most active external nodes (readable)
# ...but an external touching one of these NEVER gets culled by the volume cap:
# a one-shot brute-force / anonymous / pivot source matters even at low count.
_HIGH_SIGNAL = {"anonymous_logon", "failed_logon", "chain", "chainsaw",
                "explicit_creds", "untrusted_cert"}

# --- pivot chains (X -> B -> Y) -------------------------------------------- #
# An attacker session on a pivot rarely needs more than a working half-day; a
# wider window starts chaining unrelated routine logons of the same admin.
_CHAIN_WINDOW = 12 * 3600
# An rdpOut 1024/1102 whose UserId SID did not resolve (no ProfileList row) has
# no account: only chain it when the dial-out follows the inbound logon closely
# enough to plausibly be the same hands-on session.
_CHAIN_WINDOW_NOUSER = 3600
_CHAIN_TS_CAP = 400          # per-edge event-timestamp sample kept for pairing
_MAX_CHAINS = 200
# Inbound evidence of a REAL session on the pivot: a successful 4624 (its lateral
# types are already the only ones collected), an inbound RDP session from the
# TerminalServices operational logs, or a Linux inbound SSH login.
_CHAIN_IN_EIDS = {"4624", "LSM-21", "LSM-25", "RCM-1149", "ssh", "wtmp"}
# Outbound evidence FROM the pivot: anything this tool treats as reach-out. The
# inbound RDP/SSH ids double as outbound (an X->B->Y chain's second leg is the
# rdp/ssh login onto Y whose SOURCE is the pivot B).
_CHAIN_OUT_EIDS = {"4624", "4648", "4769", "1024", "1102", "TSC-MRU", "TypedPath",
                   "LSM-21", "LSM-25", "RCM-1149", "ssh", "wtmp"}
# brute_success: a source that failed against a host at least this many times and
# then logged in successfully (password spray / brute force that worked).
_BRUTE_MIN_FAILS = 5

_RE_TS = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)")


def _parse_ts(s: str) -> float | None:
    """Epoch seconds from 'YYYY-MM-DD HH:MM:SS[.frac...]' (EvtxECmd / registry
    key-write timestamps), or None. Sub-second precision is irrelevant here."""
    m = _RE_TS.match((s or "").strip())
    if not m:
        return None
    try:
        return datetime(*map(int, m.groups()), tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _fmt_ts(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


def _norm_ip(token: str) -> str:
    """Normalise a RemoteHost token to a bare IP/name: drop ::ffff: and a :port."""
    t = token.strip()
    if t.lower().startswith("::ffff:"):
        t = t[7:]
    # v4 "ip:port" -> strip the port (a trailing all-digit segment after ':')
    if t.count(":") == 1:
        host, _, port = t.rpartition(":")
        if port.isdigit() and host.count(".") == 3:
            t = host
    return t


def _extract_src(remotehost: str) -> str | None:
    """Source IP or workstation name from EvtxECmd's RemoteHost, or None if local.
    Handles "ws (ip)" (4624/4625/4648) and a bare "ip:port" (Kerberos 4768/4769)."""
    raw = (remotehost or "").strip()
    if not raw or raw in ("-:-",):
        return None
    m = _RE_WS_IP.match(raw)
    if m:
        ip = _norm_ip(m.group("ip"))
        ws = m.group("ws").strip()
        if ip and ip not in _LOCAL:
            return ip
        if ws and ws not in _LOCAL:
            return ws
        return None
    src = _norm_ip(raw)
    return None if src in _LOCAL else src


def _payload_join(row: dict) -> str:
    return " | ".join(row.get(f"PayloadData{i}", "") or "" for i in range(1, 7))


def _logon_type(payload: str) -> int | None:
    m = _RE_LOGON_TYPE.search(payload)
    return int(m.group(1)) if m else None


def _first(rx: re.Pattern, payload: str) -> str:
    m = rx.search(payload)
    return m.group(1).strip() if m else ""


def _clean_user(user: str) -> str:
    """Canonical account label so the SAME principal merges into one edge/node.

    Windows accounts are case-insensitive and the KDC/EvtxECmd emit the same
    account many ways -- `CORP\\administrator`, `CORP\\Administrator`,
    `corp\\administrator`, `CORP.LOCAL\\Administrator`. Canonicalise to
    `<NETBIOS_UPPER>\\<user_lower>` (domain reduced to its first DNS label, so
    CORP.LOCAL == CORP); a genuinely different domain (OTHERDOM\\, WORKGROUP\\)
    still stays distinct. Bare/UPN names keep their form (domain unknown)."""
    u = (user or "").strip().strip("\\")
    if u in ("-", "-\\-", ""):
        return ""
    if "\\" in u:
        dom, _, name = u.partition("\\")
        dom = dom.split(".")[0].upper()
        return f"{dom}\\{name.lower()}" if dom else name.lower()
    return u


def _short_user(user: str) -> str:
    """Bare account without the domain prefix, lower-cased (for cross-source match)."""
    return (user or "").split("\\")[-1].strip().lower()


_KRB_NONHOST = {"krbtgt"}


def _spn_host(spn: str) -> str:
    """Host part of a Kerberos SPN / ServiceName, or "" if it is not a host principal.
    Handles "HOST$", "host$@REALM", "MSSQLSvc/host.fqdn:1433", "cifs/host"."""
    s = (spn or "").strip()
    if "/" in s:                       # service class / instance -> keep the instance
        s = s.split("/", 1)[1]
    s = s.split("/")[0].split(":")[0].split("@")[0].strip()   # drop port / extra / realm
    if not s or s.lower() in _KRB_NONHOST:
        return ""
    return s                           # _resolve strips a trailing "$" and canonicalises


def _load_host_index(machines: list[Machine]) -> dict[str, str]:
    """Map every known IP / name / fqdn (lower-cased) -> canonical machine name.

    Also indexes the short (first-label) form of a dotted name so a Linux host
    whose hostname is an FQDN (`web01.example.local`) still resolves when a peer
    refers to it by its short name (`web01`). Short forms never overwrite a full
    match, so an exact IP/FQDN key always wins over a short-name collision."""
    index: dict[str, str] = {}
    shorts: dict[str, str] = {}
    for m in machines:
        info_path = m.path / "CSVs" / "SystemInfo" / "machine_info.json"
        name = m.name
        keys = {name}
        try:
            info = json.loads(info_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            info = {}
        if info.get("machine_name"):
            name = info["machine_name"]
            keys.add(name)
        if info.get("fqdn"):
            keys.add(info["fqdn"])
        for ip in info.get("IPs", []) or []:
            keys.add(ip)
        for k in keys:
            if not k:
                continue
            kl = str(k).lower()
            index[kl] = name
            short = kl.split(".")[0]
            if short and short != kl and not _RE_IPV4.match(kl):
                shorts.setdefault(short, name)   # weakest priority (filled below)
    for short, name in shorts.items():
        index.setdefault(short, name)            # only if no exact key claimed it
    return index


_RE_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _resolve(token: str, index: dict[str, str]) -> tuple[str, bool]:
    """(label, is_case_host). Matches by full token then short hostname; a trailing
    "$" (machine account HOST$) is stripped for matching, so HOST$ resolves to HOST
    (and a host referring to its own machine account is treated as self). Unresolved
    host names are canonicalised to their short lower-case form so FQDN/short/case
    variants of the same external host merge into one node; IPs are kept verbatim."""
    if not token:
        return "", False
    key = token.lower().rstrip("$")
    if key in index:
        return index[key], True
    short = key.split(".")[0]
    if short in index:
        return index[short], True
    if ":" in token or _RE_IPV4.match(token):
        return token, False
    return short, False


@dataclass
class _Edge:
    src: str
    dst: str
    user: str
    logon_type: int | None
    event_id: str
    status: str                 # "ok" | "failed"
    src_case: bool
    dst_case: bool
    count: int = 0
    first: str = ""
    last: str = ""
    reasons: set[str] = field(default_factory=set)
    chainsaw: set[str] = field(default_factory=set)   # chainsaw rule verdicts, if any
    ts: list[float] = field(default_factory=list)     # event-time sample (chain pairing)


def _edge_key(src: str, dst: str, user: str, lt: int | None, eid: str) -> tuple:
    return (src, dst, user, lt, eid)


def _add_edge(edges: dict[tuple, _Edge], edge: _Edge, ts: str = "") -> _Edge:
    """Merge `edge` into the aggregate for its key (bumping count, widening the
    first/last window with `ts` when given). Returns the surviving aggregate."""
    key = _edge_key(edge.src, edge.dst, edge.user, edge.logon_type, edge.event_id)
    agg = edges.get(key)
    if agg is None:
        edges[key] = edge
        agg = edge
    agg.count += 1
    if ts:
        if not agg.first or ts < agg.first:
            agg.first = ts
        if ts > agg.last:
            agg.last = ts
        if len(agg.ts) < _CHAIN_TS_CAP:
            t = _parse_ts(ts)
            if t is not None:
                agg.ts.append(t)
    return agg


# Loose-drop machines (a folder of web/firewall logs) are os=linux but are not
# hosts with a logon identity: they carry no auth/wtmp/known_hosts and no
# machine_info, so they must not become graph nodes.
_NON_HOST_COLLECTORS = {"weblogs", "fortigate"}


def _machine_hosts_live(machines: list[Machine]) -> list[Machine]:
    """Correlatable hosts: Windows + Linux/UAC, excluding VSS snapshots (their
    logon logs are a point-in-time copy of the live host -- would duplicate every
    edge) and loose-drop log folders (see _NON_HOST_COLLECTORS)."""
    out = []
    for m in machines:
        if m.os not in ("windows", "linux") or m.collector in _NON_HOST_COLLECTORS:
            continue
        if m.volumes and m.volumes[0].name.upper().startswith("VSS"):
            continue
        out.append(m)
    return out


def _collect(machine: Machine, index: dict[str, str], edges: dict[tuple, _Edge]) -> bool:
    """Read one machine's evtx_security.csv, accumulate logon edges. Returns True if
    the machine logged Kerberos 4768/4769 (i.e. it is a domain controller)."""
    csv_path = machine.path / "CSVs" / "EventLogs" / "evtx_security.csv"
    if not csv_path.is_file():
        return False
    dst_label, dst_case = machine.name, True
    is_dc = False
    try:
        with csv_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                eid = (row.get("EventId") or "").strip()
                if eid not in _EVENTS:
                    continue
                if eid in ("4768", "4769"):
                    is_dc = True          # only DCs log Kerberos KDC events
                ts = (row.get("TimeCreated") or "").strip()
                payload = _payload_join(row)
                lt = _logon_type(payload)
                edge = _row_to_edge(machine, eid, row, payload, lt, index, dst_label, dst_case)
                if edge is not None:
                    _add_edge(edges, edge, ts)
    except OSError as e:
        log.debug(f"lateral: {csv_path.name}: {e}")
    return is_dc


def _open_csv(path: Path):
    """Yield DictReader rows from a per-machine CSV, or nothing if absent/unreadable."""
    if not path.is_file():
        return
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            yield from csv.DictReader(fh)
    except OSError as e:
        log.debug(f"lateral: {path.name}: {e}")


_RE_SID_KEY = re.compile(r"^KeyName:\s*(S-1-5-21-[\d-]+)$")


def _load_sid_users(machine: Machine) -> dict[str, str]:
    """SID -> profile name from reg_profList.csv (the RECmd ProfileList batch).

    The RDPClient operational channel logs 1024/1102 in the USER's session, so the
    account is there -- but only as a SID (UserId column, UserName stays empty).
    ProfileList maps every real user SID (S-1-5-21-*) that ever logged on to its
    profile path; the folder name is the standard forensic approximation of the
    account name (a renamed account or a collision-suffixed profile may differ)."""
    out: dict[str, str] = {}
    for row in _open_csv(machine.path / "CSVs" / "Registry" / "reg_profList.csv"):
        m = _RE_SID_KEY.match((row.get("ValueData") or "").strip())
        v3 = row.get("ValueData3") or ""
        if m and "ProfileImagePath:" in v3:
            name = v3.split("ProfileImagePath:", 1)[1].strip().rstrip("\\").rsplit("\\", 1)[-1]
            if name:
                out[m.group(1)] = name
    return out


def _collect_rdp_out(machine: Machine, index: dict[str, str],
                     edges: dict[tuple, _Edge], sid_users: dict[str, str]) -> None:
    """evtx_rdpOut.csv (TerminalServices-RDPClient 1024/1102): this host -> the RDP
    target it dialed, with the real per-connection time. Source-side, so it holds
    even when the destination is not acquired or its Security log rolled over.
    The dialing account is attributed via its UserId SID (see _load_sid_users);
    an unresolvable SID leaves the edge account-less, as before."""
    for row in _open_csv(machine.path / "CSVs" / "EventLogs" / "evtx_rdpOut.csv"):
        eid = (row.get("EventId") or "").strip()
        if eid not in ("1024", "1102"):
            continue
        payload = _payload_join(row)
        m = _RE_RDP_DEST.search(payload) or _RE_RDP_ADDR.search(payload)
        target = _norm_ip(m.group(1)) if m else _extract_src(row.get("RemoteHost") or "")
        if not target or len(target) < 3 or target.lower() in _LOCAL:
            continue
        dl, dcase = _resolve(target, index)
        if not dl or dl == machine.name:
            continue
        user = _clean_user(sid_users.get((row.get("UserId") or "").strip(), ""))
        reasons = {"rdp_outbound"} | ({"case_to_case"} if dcase else set())
        _add_edge(edges, _Edge(machine.name, dl, user, 10, eid, "ok", True, dcase,
                               reasons=reasons), (row.get("TimeCreated") or "").strip())


def _collect_rdp_mru(machine: Machine, index: dict[str, str], edges: dict[tuple, _Edge]) -> None:
    """rdp_outbound.csv (Terminal Server Client MRU): every host this box RDP'd to and
    the account used against it - the years-deep client-side lateral map."""
    for row in _open_csv(machine.path / "CSVs" / "Registry" / "rdp_outbound.csv"):
        target = (row.get("target") or "").strip()
        if not target:
            continue
        dl, dcase = _resolve(target, index)
        if not dl or dl == machine.name:
            continue
        user = _clean_user(row.get("username_hint")) or _clean_user(row.get("user"))
        reasons = {"rdp_outbound"} | ({"case_to_case"} if dcase else set())
        if (row.get("cert_accepted") or "").strip() == "yes":
            reasons.add("untrusted_cert")     # user clicked through a bad certificate
        _add_edge(edges, _Edge(machine.name, dl, user, 10, "TSC-MRU", "ok", True, dcase,
                               reasons=reasons), (row.get("key_last_write_utc") or "").strip())


def _collect_typed_unc(machine: Machine, index: dict[str, str], edges: dict[tuple, _Edge]) -> None:
    r"""explorer_input.csv TypedPaths that are UNC (\\host\share): SMB targets the
    user reached by hand - deliberate access the client's Security log never records."""
    for row in _open_csv(machine.path / "CSVs" / "Registry" / "explorer_input.csv"):
        if (row.get("kind") or "").strip() != "typed_path":
            continue
        val = (row.get("value") or "").strip()
        if not val.startswith("\\\\"):
            continue
        host = val.lstrip("\\").split("\\", 1)[0].strip()
        if not host:
            continue
        dl, dcase = _resolve(host, index)
        if not dl or dl == machine.name:
            continue
        reasons = {"typed_unc"} | ({"case_to_case"} if dcase else set())
        _add_edge(edges, _Edge(machine.name, dl, _clean_user(row.get("user")), None,
                               "TypedPath", "ok", True, dcase, reasons=reasons),
                  (row.get("key_last_write_utc") or "").strip())


# Destination-side inbound RDP from the TerminalServices *operational* channels.
# These survive after the Security log has rolled over (the common case on a
# workstation), and both the source and the account land in the standard
# EvtxECmd columns (RemoteHost / UserName), exactly like evtx_security.
#  LocalSessionManager 21 = session logon, 25 = session RECONNECT (the one that
#  most often has no matching 4624); RemoteConnectionManager 1149 = RDP auth OK.
_RDP_INBOUND = (
    ("EventLogs/evtx_rdpSessions.csv", {"21", "25"}, "LSM"),
    ("EventLogs/evtx_rdpAuth.csv", {"1149"}, "RCM"),
)
# IPv6 link-local (fe80::, and EvtxECmd's "0:0:fe80::..%zone" rendering): a
# same-segment address, useless for source attribution -> dropped.
_RE_LINK_LOCAL = re.compile(r"(?i)(?:^|:)fe80|^0:0:fe80")


def _rdp_session_src(remotehost: str) -> str:
    """Remote source IP from an LSM/RCM RemoteHost, or "" when the session is a
    local console ("LOCAL"), empty, loopback, or an IPv6 link-local peer."""
    raw = (remotehost or "").strip()
    if not raw or raw.lower() == "local":
        return ""
    src = _extract_src(raw)
    if not src or _RE_LINK_LOCAL.search(src):
        return ""
    return src


def _collect_rdp_inbound(machine: Machine, index: dict[str, str], edges: dict[tuple, _Edge]) -> None:
    """Inbound RDP onto this host from the operational logs (LocalSessionManager
    21/25, RemoteConnectionManager 1149): a source -> this host RDP edge that
    complements Security 4624 type 10 and outlives its rollover. A console
    (LOCAL) / link-local session is not lateral movement and is skipped."""
    dst = machine.name
    for rel, eids, tag in _RDP_INBOUND:
        for row in _open_csv(machine.path / "CSVs" / rel):
            eid = (row.get("EventId") or "").strip()
            if eid not in eids:
                continue
            src = _rdp_session_src(row.get("RemoteHost") or "")
            if not src:
                continue
            sl, scase = _resolve(src, index)
            if not sl or sl == dst:
                continue
            reasons = {"rdp"} | ({"case_to_case"} if scase else set())
            _add_edge(edges, _Edge(sl, dst, _clean_user(row.get("UserName")), 10,
                                   f"{tag}-{eid}", "ok", scase, True, reasons=reasons),
                      (row.get("TimeCreated") or "").strip())


def _remote_src(tok: str) -> str:
    """A wtmp/auth/known_hosts source token reduced to a remote IP or host, or ""
    if it is local: empty, loopback, or an X display (":0", ":0.0")."""
    t = _norm_ip((tok or "").strip())
    if not t or t in _LOCAL or t.startswith(":"):
        return ""
    return t


def _kh_target(raw: str) -> str:
    r"""The primary host/IP of a known_hosts hostspec, or "" for a hashed summary.
    Handles "host,1.2.3.4" (comma list), "[host]:2222" and "[1.2.3.4]:22"."""
    t = (raw or "").strip()
    if not t or t.startswith("("):        # "(hashed)" summary row -> no usable target
        return ""
    t = t.split(",")[0].strip()           # first name of a comma list
    if t.startswith("["):                 # [host]:port
        t = t[1:].split("]", 1)[0]
    return _remote_src(t)


def _collect_linux(machine: Machine, index: dict[str, str],
                   edges: dict[tuple, _Edge], dst: str) -> None:
    """Read one Linux/UAC machine's SSH-relevant CSVs into inbound/outbound edges.

    Inbound (peer -> this host): wtmp USER_PROCESS (real epoch timestamp), auth
    ssh_accepted (method), auth ssh_failed/invalid + btmp (brute force). Outbound
    (this host -> peer): known_hosts targets (reference). Reasons follow the same
    low-FP rule as Windows: a routine success stays in the .csv; failures,
    inter-case movement and brute_success are what the graph keeps. The Linux
    timeline/chains ride on wtmp/btmp -- classic syslog auth lines carry no year,
    so `auth` timestamps usually will not parse (method + failures still count)."""
    base = machine.path / "CSVs"
    # --- wtmp: inbound login with a real (epoch) timestamp -------------------- #
    for row in _open_csv(base / "EventLogs" / "wtmp.csv"):
        if (row.get("type") or "").strip() != "USER_PROCESS":
            continue
        src = _remote_src(row.get("host") or "")
        if not src:
            continue
        sl, scase = _resolve(src, index)
        if not sl or sl == dst:
            continue
        reasons = {"case_to_case"} if scase else set()
        _add_edge(edges, _Edge(sl, dst, _clean_user(row.get("user")), None, "wtmp", "ok",
                               scase, True, reasons=reasons),
                  (row.get("time_utc") or "").strip())
    # --- btmp: failed logins (binary, always timestamped) --------------------- #
    for row in _open_csv(base / "EventLogs" / "btmp.csv"):
        src = _remote_src(row.get("host") or "")
        if not src:
            continue
        sl, scase = _resolve(src, index)
        if not sl or sl == dst:
            continue
        reasons = {"failed_logon"} | ({"case_to_case"} if scase else set())
        _add_edge(edges, _Edge(sl, dst, _clean_user(row.get("user")), None, "btmp", "failed",
                               scase, True, reasons=reasons),
                  (row.get("time_utc") or "").strip())
    # --- auth.log: SSH method (accepted) + failures --------------------------- #
    _AUTH_EID = {"ssh_accepted": "ssh", "ssh_failed": "ssh_fail",
                 "ssh_invalid_user": "ssh_invalid"}
    for row in _open_csv(base / "EventLogs" / "auth.csv"):
        event = (row.get("event") or "").strip()
        if event not in _AUTH_EID:
            continue
        src = _remote_src(row.get("source") or "")
        if not src:
            continue
        sl, scase = _resolve(src, index)
        if not sl or sl == dst:
            continue
        ok = event == "ssh_accepted"
        reasons: set[str] = set() if ok else {"failed_logon"}
        if event == "ssh_invalid_user":
            reasons.add("invalid_user")
        if scase:
            reasons.add("case_to_case")
        _add_edge(edges, _Edge(sl, dst, _clean_user(row.get("user")), None, _AUTH_EID[event],
                               "ok" if ok else "failed", scase, True, reasons=reasons),
                  (row.get("timestamp") or "").strip())
    # --- known_hosts: outbound SSH targets (reference; graphed only inter-case) #
    for row in _open_csv(base / "Network" / "known_hosts.csv"):
        tgt = _kh_target(row.get("target") or "")
        if not tgt:
            continue
        dl, dcase = _resolve(tgt, index)
        if not dl or dl == dst:
            continue
        reasons = {"case_to_case"} if dcase else set()
        _add_edge(edges, _Edge(dst, dl, _clean_user(row.get("account")), None,
                               "known_host", "ok", True, dcase, reasons=reasons))


def _row_to_edge(machine, eid, row, payload, lt, index, dst_label, dst_case) -> _Edge | None:
    """Build the (unaggregated) edge for one logon row, or None to skip it."""
    remote = row.get("RemoteHost") or ""
    if eid in ("4624", "4625"):
        if lt is not None and lt not in _LATERAL_TYPES:
            return None                                   # local/service logon
        src = _extract_src(remote)
        if not src:
            return None
        src_label, src_case = _resolve(src, index)
        if src_label == dst_label:
            return None                                   # self logon
        user = _clean_user(row.get("UserName")) or _first(_RE_TARGET, payload)
        status = "failed" if eid == "4625" else "ok"
        clean = _clean_user(user)
        reasons = set()
        if lt == 10:
            reasons.add("rdp")
        if status == "failed":
            reasons.add("failed_logon")
        if _short_user(clean) == "anonymous logon":
            # network null-session logon: enumeration / exploit (EternalBlue,
            # SMB relay). Always worth surfacing, so it appears in the graph.
            reasons.add("anonymous_logon")
        if src_case and dst_case:
            reasons.add("case_to_case")          # movement between acquired hosts
        return _Edge(src_label, dst_label, clean, lt, eid, status,
                     src_case, dst_case, reasons=reasons)
    if eid == "4648":                                     # this host -> target server
        target = _first(_RE_TARGET_SERVER, payload)
        if not target or target.lower() in _LOCAL:
            return None                                   # runas against self, not lateral
        dl, dcase = _resolve(target, index)
        if dl == machine.name:
            return None
        user = _clean_user(row.get("UserName")) or _first(_RE_TARGET, payload)
        reasons = {"explicit_creds"}
        if dcase:
            reasons.add("case_to_case")
        return _Edge(machine.name, dl, _clean_user(user), lt, eid, "ok",
                     True, dcase, reasons=reasons)
    if eid in ("4768", "4769"):                           # Kerberos (recorded on the DC)
        src = _extract_src(remote)
        if not src:
            return None
        src_label, src_case = _resolve(src, index)
        if src_label == dst_label:
            return None
        user = _clean_user(_first(_RE_TARGET, payload))
        # 4769 (service ticket): ServiceName is the SPN of the resource the source
        # wanted to reach. When it is a host (HOST$ / svc/host), the meaningful edge
        # is source -> that host, not source -> DC. Gate to acquired-host sources so
        # the whole domain's routine ticketing doesn't flood the graph.
        if eid == "4769" and src_case:
            tl, tcase = _resolve(_spn_host(_first(_RE_SERVICE, payload)), index)
            if tl and tl not in (src_label, dst_label):
                reasons = {"kerberos_service"}
                if tcase:
                    reasons.add("case_to_case")
                return _Edge(src_label, tl, user, None, eid, "ok", src_case, tcase,
                             reasons=reasons)
        # TGT (4768) or a non-host / self / DC service ticket: source -> DC, flagged
        # only when an acquired host is the source (informational otherwise).
        reasons = {"case_to_case"} if src_case else set()
        return _Edge(src_label, dst_label, user, None, eid, "ok",
                     src_case, dst_case, reasons=reasons)
    return None


_TIMELINE_COLS = ["src", "dst", "user", "logon_type", "event_id", "status",
                  "count", "first_seen", "last_seen", "src_in_case", "suspicious",
                  "reasons", "chainsaw"]


def _write_csv(path: Path, edges: list[_Edge]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(_TIMELINE_COLS)
        for e in sorted(edges, key=lambda x: (-len(x.reasons), x.src, x.dst)):
            w.writerow([
                e.src, e.dst, e.user,
                _TYPE_NAME.get(e.logon_type, e.logon_type if e.logon_type is not None else ""),
                e.event_id, e.status, e.count, e.first, e.last,
                "yes" if e.src_case else "no",
                "yes" if e.reasons else "no", "+".join(sorted(e.reasons)),
                "+".join(sorted(e.chainsaw)),
            ])


# chainsaw detection CSVs whose verdicts corroborate an edge (its rule name is
# attached to the matching edge). "Network Logon" is dropped: it is chainsaw's label
# for every network logon and adds nothing over our own `network` category.
_CHAINSAW_FILES = ("chainsaw_login_attacks.csv", "chainsaw_lateral_movement.csv",
                   "chainsaw_rdp_attacks.csv", "chainsaw_rdp_events.csv")
_CHAINSAW_SKIP = {"", "network logon"}


def _load_chainsaw_verdicts(targets: list[Machine], index: dict[str, str]) -> dict[tuple, set[str]]:
    """Map (dst_host, short_user, event_id) -> set of chainsaw rule names, read from
    each machine's chainsaw_* CSVs. Rows without a usable event id/user (e.g. the
    TerminalServices RDP session rows) simply won't match any logon edge."""
    verdicts: dict[tuple, set[str]] = defaultdict(set)
    for m in targets:
        base = m.path / "CSVs" / "EventLogs"
        for fname in _CHAINSAW_FILES:
            p = base / fname
            if not p.is_file():
                continue
            try:
                with p.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
                    for row in csv.DictReader(fh):
                        det = (row.get("detections") or "").strip()
                        if det.lower() in _CHAINSAW_SKIP:
                            continue
                        comp = (row.get("Computer") or "").strip()
                        dst = _resolve(comp, index)[0] if comp else m.name
                        key = (dst, _short_user(row.get("User")), (row.get("Event ID") or "").strip())
                        verdicts[key].add(det)
            except OSError as e:
                log.debug(f"lateral: {p.name}: {e}")
    return verdicts


def _pair_times(ts_in: list[float], ts_out: list[float], window: float) -> tuple | None:
    """Earliest (t_in, t_out) with 0 <= t_out - t_in <= window, or None. Two-pointer
    over the sorted samples: for each outbound time take the latest inbound not
    after it -- the session that outbound most plausibly belongs to."""
    if not ts_in or not ts_out:
        return None
    a = sorted(ts_in)
    i = 0
    for t_out in sorted(ts_out):
        while i + 1 < len(a) and a[i + 1] <= t_out:
            i += 1
        if a[i] <= t_out <= a[i] + window:
            return a[i], t_out
    return None


def _find_chains(edges: list[_Edge]) -> list[dict]:
    """Pivot chains X ->(U) B ->(U) Y: a successful inbound logon of account U onto
    acquired host B, followed within a window by outbound activity from B by the
    same account (or an account-less RDP dial-out right after -- tight window).
    Machine accounts (HOST$) are excluded: their mutual auth chains everything.
    Marks both edges with reason `chain`; returns display dicts (capped)."""
    inbound: dict[tuple, list[_Edge]] = defaultdict(list)
    for e in edges:
        if (e.event_id in _CHAIN_IN_EIDS and e.status == "ok" and e.dst_case and e.ts):
            u = _short_user(e.user)
            if u and not u.endswith("$"):
                inbound[(e.dst, u)].append(e)

    found: dict[tuple, dict] = {}
    for out in edges:
        if (out.event_id not in _CHAIN_OUT_EIDS or out.status != "ok"
                or not out.src_case or not out.ts):
            continue
        u = _short_user(out.user)
        if u.endswith("$"):
            continue
        if u:
            window, candidates = _CHAIN_WINDOW, inbound.get((out.src, u), [])
        else:   # account-less source (rdpOut): any user recently landed on the pivot
            window = _CHAIN_WINDOW_NOUSER
            candidates = [e for (pivot, _), lst in inbound.items()
                          if pivot == out.src for e in lst]
        for ine in candidates:
            if ine is out or ine.src == out.dst:      # no X -> B -> X boomerang
                continue
            pair = _pair_times(ine.ts, out.ts, window)
            if pair is None:
                continue
            user = ine.user or out.user
            key = (_short_user(user), ine.src, out.src, out.dst)
            if key in found and found[key]["_t0"] <= pair[0]:
                continue
            ine.reasons.add("chain")
            out.reasons.add("chain")
            found[key] = {"user": user, "path": [ine.src, out.src, out.dst],
                          "t0": _fmt_ts(pair[0]), "t1": _fmt_ts(pair[1]),
                          "_t0": pair[0], "_in": ine, "_out": out}
    return sorted(found.values(), key=lambda c: c["_t0"])[:_MAX_CHAINS]


def _mark_brute_success(edges: list[_Edge]) -> None:
    """Flag a successful Linux SSH login where the SAME account, from the SAME
    source, first failed >= _BRUTE_MIN_FAILS times against that host (a brute
    force that worked). Keyed by (src, dst, account): keying by (src, dst) alone
    would fire on every user of a shared login/bastion host whose accumulated
    failures happen to cross the threshold -- a false-positive factory."""
    fails: dict[tuple, int] = defaultdict(int)
    for e in edges:
        if e.status == "failed" and e.event_id in ("btmp", "ssh_fail", "ssh_invalid"):
            fails[(e.src, e.dst, _short_user(e.user))] += e.count
    for e in edges:
        if (e.status == "ok" and e.event_id in ("ssh", "wtmp")
                and fails.get((e.src, e.dst, _short_user(e.user)), 0) >= _BRUTE_MIN_FAILS):
            e.reasons.add("brute_success")


def build(machines: list[Machine], root: Path) -> dict:
    """Write lateral_movement.csv (full) and .html (curated graph) at `root`."""
    targets = _machine_hosts_live(machines)
    if not targets:
        return {"hosts": 0, "edges": 0, "suspicious": 0}
    index = _load_host_index(machines)

    def _label(m: Machine) -> str:
        # canonical node label (machine_info name when known), so a host referred
        # to by IP/short-name and by its own CSVs collapses onto ONE node.
        return _resolve(m.name, index)[0] or m.name

    edges: dict[tuple, _Edge] = {}
    dc_names: set[str] = set()
    linux_names: set[str] = set()
    case_labels: set[str] = set()
    for m in targets:
        case_labels.add(_label(m))
        if m.os == "windows":
            if _collect(m, index, edges):
                dc_names.add(_label(m))
            # source-side reach (survives log rollover); 1024/1102 attribute their
            # user by resolving the UserId SID through this machine's ProfileList
            _collect_rdp_out(m, index, edges, _load_sid_users(m))
            _collect_rdp_mru(m, index, edges)
            _collect_typed_unc(m, index, edges)
            # destination-side inbound RDP (LSM 21/25, RCM 1149) -- outlives the
            # Security log's rollover
            _collect_rdp_inbound(m, index, edges)
        elif m.os == "linux":
            linux_names.add(_label(m))
            _collect_linux(m, index, edges, _label(m))
    edge_list = list(edges.values())
    if not edge_list:
        return {"hosts": 0, "edges": 0, "suspicious": 0}

    verdicts = _load_chainsaw_verdicts(targets, index)
    for e in edge_list:
        v = verdicts.get((e.dst, _short_user(e.user), e.event_id))
        if v:
            e.chainsaw |= v
            e.reasons.add("chainsaw")
    _mark_brute_success(edge_list)      # adds reason `brute_success` -> before the CSV
    chains = _find_chains(edge_list)    # adds reason `chain` -> before the CSV

    _write_csv(root / "lateral_movement.csv", edge_list)
    nodes, links, jchains = _graph_model(edge_list, case_labels, dc_names, linux_names, chains)
    (root / "lateral_movement.html").write_text(
        _render_html(nodes, links, jchains), encoding="utf-8")
    hosts = {e.src for e in edge_list} | {e.dst for e in edge_list}
    return {"hosts": len(hosts), "edges": len(edge_list),
            "suspicious": sum(1 for e in edge_list if e.reasons),
            "chains": len(chains),
            "graph_hosts": len(nodes), "graph_edges": len(links)}


def _edge_category(e: _Edge) -> str:
    """A single class per edge, used by the HTML to colour, filter and legend it.
    Failed logons and explicit-cred use win over the raw logon type."""
    if e.status == "failed":
        return "failed"
    if e.event_id == "4648":
        return "explicit"
    if e.event_id in ("4768", "4769"):
        return "kerberos"
    if e.event_id == "TSC-MRU":
        return "rdp_mru"
    if e.event_id == "TypedPath":
        return "typed_unc"
    if e.event_id in ("ssh", "wtmp"):
        return "ssh"
    if e.event_id == "known_host":
        return "ssh_known_host"
    if e.event_id in ("1024", "1102") or e.logon_type == 10:
        return "rdp"
    if e.logon_type == 9:
        return "runas"
    if e.logon_type == 3:
        return "network"
    return "other"


def _graph_model(edges: list[_Edge], case_names: set[str], dc_names: set[str],
                 linux_names: set[str], chains: list[dict]) -> tuple[list, list, list]:
    """Curated subgraph for the HTML: acquired hosts + high-signal edges (inter-case
    movement, RDP/SSH, explicit creds, failed logons) + the most active external
    peers (capped). Routine external domain auth stays in the .csv only, so a DC
    that sees the whole domain doesn't blow the graph up to hundreds of nodes.
    `case_names`/`dc_names`/`linux_names` are canonical node labels (see build)."""

    def is_case(n: str, flag: bool) -> bool:
        return flag or n in case_names

    signal = [e for e in edges if e.reasons]
    ext_weight: dict[str, int] = defaultdict(int)
    must_keep: set[str] = set()          # high-signal externals kept regardless of volume
    for e in signal:
        hot = bool(e.reasons & _HIGH_SIGNAL)
        for n, flag in ((e.src, e.src_case), (e.dst, e.dst_case)):
            if is_case(n, flag):
                continue
            ext_weight[n] += e.count
            if hot:
                must_keep.add(n)         # brute-force / anonymous / pivot source must not be culled
    by_weight = {n for n, _ in sorted(ext_weight.items(), key=lambda x: -x[1])[:_MAX_EXTERNAL]}
    keep_ext = must_keep | by_weight

    def keep(n: str, flag: bool) -> bool:
        return is_case(n, flag) or n in keep_ext

    kept = [e for e in signal if keep(e.src, e.src_case) and keep(e.dst, e.dst_case)]

    node_case: dict[str, bool] = {n: True for n in case_names}   # acquired hosts always shown
    for e in kept:
        node_case[e.src] = node_case.get(e.src, False) or is_case(e.src, e.src_case)
        node_case[e.dst] = node_case.get(e.dst, False) or is_case(e.dst, e.dst_case)

    # DC role is ground truth (the host logged Kerberos KDC events), so 2+ DCs are
    # all marked -- unlike deriving it from inbound-Kerberos volume, which named one.
    # Off-case nodes split into `server` (resolved by NAME -- an internal box the
    # admin reached, RDP-MRU / typed-UNC target) vs `external` (a bare IP -- a logon
    # SOURCE / attacker origin), so the eye separates "where it reached" from
    # "who came in" instead of a wall of red.
    def _role(n: str) -> str:
        if n in dc_names:
            return "dc"
        if n in linux_names:
            return "linux"
        if node_case[n]:
            return "case"
        return "external" if (_RE_IPV4.match(n) or ":" in n) else "server"

    nodes = [{"id": n, "role": _role(n)} for n in sorted(node_case)]
    links = [{
        "source": e.src, "target": e.dst, "user": e.user,
        "cat": _edge_category(e),
        "ltype": _TYPE_NAME.get(e.logon_type, "") if e.logon_type is not None else "",
        "eid": e.event_id, "status": e.status, "count": e.count,
        "first": e.first, "last": e.last,
        # show the actual chainsaw verdict(s) rather than the generic "chainsaw" token
        "reasons": sorted(e.chainsaw) + sorted(r for r in e.reasons if r != "chainsaw"),
    } for e in kept]
    # chains whose two edges survived the curation, with their link indices so the
    # HTML "Attack paths" panel can highlight the pair
    kept_idx = {id(e): i for i, e in enumerate(kept)}
    jchains = [{"user": c["user"], "path": c["path"], "t0": c["t0"], "t1": c["t1"],
                "links": [kept_idx[id(c["_in"])], kept_idx[id(c["_out"])]]}
               for c in chains
               if id(c["_in"]) in kept_idx and id(c["_out"]) in kept_idx]
    return nodes, links, jchains


def _json_island(obj) -> str:
    """JSON for embedding in a <script> block: neutralise a "</script>" breakout
    (event-log usernames are attacker-controllable). "<\\/" is valid inside JSON."""
    return json.dumps(obj).replace("</", "<\\/")


def _render_html(nodes: list, links: list, chains: list) -> str:
    return _HTML.replace("__NODES__", _json_island(nodes)).replace(
        "__LINKS__", _json_island(links)).replace(
        "__CHAINS__", _json_island(chains)).replace("__COUNT__", html.escape(
            f"{len(nodes)} hosts, {len(links)} edges"))


# Self-contained interactive graph (no external JS/libs, works offline): force-directed
# SVG with filters (user/host search, logon category, time-range slider), per-edge
# username + date labels, and a chronological timeline sidebar. Hover a node for detail;
# click one to focus its neighbourhood. Busy cases start with edges aggregated per
# host pair + category, the layout world scales with the host count (fit to frame).
_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Lateral movement</title>
<style>
 body{margin:0;font:13px system-ui,sans-serif;background:#0f1115;color:#d7dae0}
 #bar,#ctl{padding:6px 12px;background:#161922;border-bottom:1px solid #2a2f3a;display:flex;flex-wrap:wrap;align-items:center;gap:10px}
 #ctl{background:#12151d}
 #bar b{font-size:14px}
 label{cursor:pointer;user-select:none}
 input[type=search]{background:#0f1115;border:1px solid #2a2f3a;color:#d7dae0;padding:3px 7px;border-radius:4px;width:190px}
 .dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px;vertical-align:middle}
 .chip{padding:2px 8px;border-radius:11px;border:1px solid #2a2f3a;cursor:pointer;user-select:none;font-size:12px}
 .chip.off{opacity:.32}
 .trange{display:flex;align-items:center;gap:5px}.trange input{width:140px}
 button{background:#1b2130;color:#d7dae0;border:1px solid #2a2f3a;border-radius:4px;cursor:pointer;padding:3px 8px}
 #wrap{display:flex;height:calc(100vh - 84px)}
 svg{flex:1;cursor:grab}
 .edge{fill:none}.edge.focus{filter:drop-shadow(0 0 3px #fff)}
 .edge.dim{opacity:.12}.node.dim{opacity:.22}
 .node.sel circle{stroke:#fff;stroke-width:2.5}
 .node circle{stroke:#0f1115;stroke-width:2;cursor:pointer}
 .node text{fill:#e8eaed;font-size:12px;pointer-events:none}
 .elbl{fill:#c7ccd6;font-size:10px;pointer-events:none;paint-order:stroke;stroke:#0f1115;stroke-width:3px;stroke-linejoin:round}
 .dlbl{fill:#8a93a3;font-size:9px;pointer-events:none;paint-order:stroke;stroke:#0f1115;stroke-width:3px;stroke-linejoin:round}
 #side{width:300px;background:#12151d;border-left:1px solid #2a2f3a;overflow:auto}
 #side h3{margin:0;padding:7px 10px;font-size:12px;position:sticky;top:0;background:#12151d;border-bottom:1px solid #2a2f3a}
 .tl{padding:5px 10px;border-bottom:1px solid #1c2030;cursor:pointer;font-size:12px}
 .tl:hover,.tl.sel{background:#1b2130}.tl .t{color:#8a93a3}.tl .r{color:#e0533d;font-size:11px}
 code{color:#9ecbff}
 #tip{position:fixed;background:#000d;border:1px solid #3a4150;padding:6px 8px;border-radius:4px;pointer-events:none;display:none;max-width:360px;z-index:5}
</style></head><body>
<div id="bar"><b>Lateral movement</b> <span id="count">__COUNT__</span>
 <label><input type="checkbox" id="agg"> aggregate</label>
 <label><input type="checkbox" id="lbl" checked> usernames</label>
 <label><input type="checkbox" id="dts"> dates</label>
 <label><input type="checkbox" id="ext"> case-to-case only</label>
 <span style="color:#586074">wheel: zoom &middot; drag bg: pan &middot; click node: focus &middot; dblclick: fit</span>
 <span style="margin-left:auto">
  <span class="dot" style="background:#f2c14e"></span>DC
  <span class="dot" style="background:#4f9cf2"></span>host
  <span class="dot" style="background:#56b6c2"></span>linux
  <span class="dot" style="background:#7fb069"></span>server
  <span class="dot" style="background:#e0533d"></span>external IP
 </span></div>
<div id="ctl">
 <input type="search" id="q" placeholder="filter user / host...">
 <span id="cats"></span>
 <span class="trange">from <input type="range" id="ta" min="0" max="1000" value="0"><span id="tal"></span></span>
 <span class="trange">to <input type="range" id="tb" min="0" max="1000" value="1000"><span id="tbl"></span></span>
 <button id="play">&#9654; play</button>
 <button id="fit">fit</button>
 <button id="rst">reset</button><span id="vis" style="color:#8a93a3"></span>
</div>
<div id="wrap"><svg id="g"></svg><div id="side">
 <h3 id="ph">Attack paths (<span id="pcount">0</span>)</h3><div id="plist"></div>
 <h3>Timeline (chronological)</h3><div id="tlist"></div>
</div></div>
<div id="tip"></div>
<script>
const NODES=__NODES__, LINKS=__LINKS__, CHAINS=__CHAINS__;
const CAT_COL={failed:'#e0533d',explicit:'#c77dff',rdp:'#f2994a',rdp_mru:'#f29fd8',ssh:'#57b894',runas:'#f2c14e',kerberos:'#4f9cf2',typed_unc:'#4fd6c0',ssh_known_host:'#8bd450',network:'#8a93a3',other:'#6f7787'};
const CAT_ORDER=['failed','explicit','rdp','rdp_mru','ssh','runas','kerberos','typed_unc','ssh_known_host','network','other'];
const roleCol={dc:'#f2c14e',case:'#4f9cf2',linux:'#56b6c2',server:'#7fb069',external:'#e0533d'};
const svg=document.getElementById('g'), tip=document.getElementById('tip');
let W=svg.clientWidth||1200,H=svg.clientHeight||700;   // 0 when loaded hidden -> sane default, viewBox rescales on show
// The layout world grows with the host count, so a big case spreads out instead
// of cramming into one screen; fit() then frames whatever is visible.
const L=Math.max(1100,Math.round(Math.sqrt(NODES.length)*300));
const WLD=L, HLD=Math.round(L*0.72);
let cam={x:0,y:0,w:W,h:H}, fitW=W;
const setVB=()=>svg.setAttribute('viewBox',cam.x+' '+cam.y+' '+cam.w+' '+cam.h);
const roleOf={}; NODES.forEach(n=>roleOf[n.id]=n.role);
const isCase=id=>roleOf[id]==='dc'||roleOf[id]==='case'||roleOf[id]==='linux';   // server/external are off-case
const esc=t=>(t+'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const pt=s=>{if(!s)return null;const d=Date.parse(s.replace(' ','T').replace(/(\.\d{3})\d+/,'$1'));return isNaN(d)?null:d;};
const deg={};LINKS.forEach(l=>{deg[l.source]=(deg[l.source]||0)+1;deg[l.target]=(deg[l.target]||0)+1;});
const N={}; NODES.forEach((n,i)=>{n.x=WLD/2+(Math.random()-.5)*WLD*.6;
  n.y=HLD/2+(Math.random()-.5)*HLD*.6;n.vx=0;n.vy=0;
  n.r=(n.role==='dc'?15:10)+Math.min(7,Math.sqrt(deg[n.id]||1)*1.4);N[n.id]=n;});
LINKS.forEach((l,i)=>{l.i=i;l.s=N[l.source];l.t=N[l.target];l.t0=pt(l.first);l.t1=pt(l.last)||l.t0;});
const _grp={};LINKS.forEach(l=>{const k=[l.source,l.target].sort().join('|');(_grp[k]=_grp[k]||[]).push(l);});
Object.keys(_grp).forEach(k=>_grp[k].forEach((l,i)=>{l.pi=i;l.pn=_grp[k].length;}));
const times=LINKS.map(l=>l.t0).filter(x=>x!=null);
const TMIN=times.length?Math.min(...times):0, TMAX=times.length?Math.max(...times):1;
const CATS=CAT_ORDER.filter(c=>LINKS.some(l=>l.cat===c));
const activeCats=new Set(CATS);
const AGG_DEFAULT=LINKS.length>60;   // busy case -> start with one edge per host pair+category
let q='',showLbl=true,showDates=false,caseOnly=false,focusSet=new Set(),selNode=null,
    winStart=TMIN,winEnd=TMAX,drag=null,pan=null,playing=null,moved=0,aggOn=AGG_DEFAULT;
let VLINKS=[],VNODES=[];
const $=id=>document.getElementById(id);
$('agg').checked=aggOn;
$('agg').onchange=e=>{aggOn=e.target.checked;render();};
const catLabel=l=>l.cat+(l.ltype&&l.ltype!==l.cat?'/'+l.ltype:'');
const _p2=n=>(''+n).padStart(2,'0');
const fmt=ms=>{if(ms==null)return '';const d=new Date(ms);return d.getFullYear()+'-'+_p2(d.getMonth()+1)+'-'+_p2(d.getDate())+' '+_p2(d.getHours())+':'+_p2(d.getMinutes());};
const DEFS='<defs>'+Object.entries(CAT_COL).map(([c,col])=>`<marker id="arr-${c}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="${col}"/></marker>`).join('')+'</defs>';
$('cats').innerHTML=CATS.map(c=>`<span class="chip" data-c="${c}" style="border-color:${CAT_COL[c]}"><span class="dot" style="background:${CAT_COL[c]}"></span>${c}</span>`).join(' ');
$('cats').querySelectorAll('.chip').forEach(el=>el.onclick=()=>{const c=el.dataset.c;
  activeCats.has(c)?(activeCats.delete(c),el.classList.add('off')):(activeCats.add(c),el.classList.remove('off'));applyFilters();});
const sliderTime=v=>TMIN+(v/1000)*(TMAX-TMIN);
const syncT=()=>{$('tal').textContent=fmt(winStart);$('tbl').textContent=fmt(winEnd);};
$('ta').oninput=()=>{winStart=sliderTime(+$('ta').value);if(winStart>winEnd){winEnd=winStart;$('tb').value=$('ta').value;}syncT();applyFilters();};
$('tb').oninput=()=>{winEnd=sliderTime(+$('tb').value);if(winEnd<winStart){winStart=winEnd;$('ta').value=$('tb').value;}syncT();applyFilters();};
$('q').oninput=e=>{q=e.target.value;applyFilters();};
$('lbl').onchange=e=>{showLbl=e.target.checked;render();};
$('dts').onchange=e=>{showDates=e.target.checked;render();};
$('ext').onchange=e=>{caseOnly=e.target.checked;applyFilters();};
function stopPlay(){if(playing){clearInterval(playing);playing=null;$('play').innerHTML='&#9654; play';}}
$('play').onclick=()=>{
 if(playing){stopPlay();return;}
 const span=(TMAX-TMIN)||1;
 winStart=TMIN;$('ta').value=0;winEnd=TMIN;$('tb').value=0;syncT();applyFilters();
 $('play').innerHTML='&#9632; stop';
 playing=setInterval(()=>{
  winEnd=Math.min(TMAX,winEnd+span/240);
  $('tb').value=Math.round((winEnd-TMIN)/span*1000);syncT();applyFilters();
  if(winEnd>=TMAX)stopPlay();
 },50);
};
$('rst').onclick=()=>{stopPlay();q='';$('q').value='';activeCats.clear();CATS.forEach(c=>activeCats.add(c));
  $('cats').querySelectorAll('.chip').forEach(el=>el.classList.remove('off'));
  winStart=TMIN;winEnd=TMAX;$('ta').value=0;$('tb').value=1000;caseOnly=false;$('ext').checked=false;
  focusSet=new Set();selNode=null;aggOn=AGG_DEFAULT;$('agg').checked=aggOn;syncT();applyFilters();fit();};
$('fit').onclick=()=>fit();
function applyFilters(){
 const qs=q.trim().toLowerCase();
 VLINKS=LINKS.filter(l=>activeCats.has(l.cat)
   && (!qs||(l.user&&l.user.toLowerCase().includes(qs))||l.source.toLowerCase().includes(qs)||l.target.toLowerCase().includes(qs))
   && (l.t0==null||(l.t1>=winStart&&l.t0<=winEnd))
   && (!caseOnly||(isCase(l.source)&&isCase(l.target))));
 const shown=new Set();VLINKS.forEach(l=>{shown.add(l.source);shown.add(l.target);});
 VNODES=NODES.filter(n=>shown.has(n.id));NODES.forEach(n=>n.vis=shown.has(n.id));
 $('vis').textContent=VLINKS.length+' / '+LINKS.length+' edges, '+VNODES.length+' hosts';
 buildTimeline();render();wake();
}
if(CHAINS.length){
 $('pcount').textContent=CHAINS.length;
 $('plist').innerHTML=CHAINS.map((c,i)=>
  `<div class="tl" data-p="${i}">`+
  `<div class="t">${esc(c.t0)} &rarr; ${esc(c.t1)}</div>`+
  `<div><code>${esc(c.path[0])}</code> &rarr; <b><code>${esc(c.path[1])}</code></b> &rarr; <code>${esc(c.path[2])}</code></div>`+
  `<div>${esc(c.user||'')} <span class="r">pivot chain</span></div></div>`).join('');
 $('plist').querySelectorAll('.tl').forEach(el=>el.onclick=()=>{
  const c=CHAINS[+el.dataset.p];focusSet=new Set(c.links);selNode=null;
  $('plist').querySelectorAll('.tl').forEach(x=>x.classList.toggle('sel',x===el));
  $('tlist').querySelectorAll('.tl').forEach(x=>x.classList.remove('sel'));render();});
}else{$('ph').style.display='none';}
function buildTimeline(){
 const rows=VLINKS.slice().sort((a,b)=>(a.t0||0)-(b.t0||0));
 $('tlist').innerHTML=rows.map(l=>
  `<div class="tl${focusSet.has(l.i)?' sel':''}" data-i="${l.i}">`+
  `<div class="t">${esc(l.first?l.first.slice(0,19):'-')}</div>`+
  `<div><span class="dot" style="background:${CAT_COL[l.cat]}"></span><code>${esc(l.source)}</code> &rarr; <code>${esc(l.target)}</code></div>`+
  `<div>${esc(l.user||'')} <span style="color:#8a93a3">${esc(catLabel(l))}${l.count>1?' x'+l.count:''}</span>`+
  `${l.reasons.length?` <span class="r">${esc(l.reasons.join('+'))}</span>`:''}</div></div>`).join('')
  || '<div style="padding:8px 10px;color:#8a93a3">no edges match</div>';
 $('tlist').querySelectorAll('.tl').forEach(el=>el.onclick=()=>{focusSet=new Set([+el.dataset.i]);selNode=null;
   $('tlist').querySelectorAll('.tl').forEach(x=>x.classList.toggle('sel',+x.dataset.i===+el.dataset.i));
   $('plist').querySelectorAll('.tl').forEach(x=>x.classList.remove('sel'));render();});
}
const REP=4000*Math.pow(L/1100,1.6), LD=Math.min(300,150*L/1100);
// The simulation sleeps once the layout settles (a big case redrawn at 25fps
// forever would pin a core with the report just sitting open) and wakes on
// anything that moves nodes again: drag, filters, reset.
let sim=null, calm=0;
function wake(){calm=0;if(!sim)sim=setInterval(step,40);}
function step(){
 let ke=0;for(const n of VNODES)ke+=Math.abs(n.vx)+Math.abs(n.vy);
 if(ke<0.06*(VNODES.length||1)&&!drag){if(++calm>25&&sim){clearInterval(sim);sim=null;}}
 else calm=0;
 for(const a of VNODES){for(const b of VNODES){if(a===b)continue;
   let dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy)||1;let f=REP/(d*d);a.vx+=dx/d*f;a.vy+=dy/d*f;}}
 for(const l of VLINKS){if(!l.s||!l.t)continue;let dx=l.t.x-l.s.x,dy=l.t.y-l.s.y,d=Math.hypot(dx,dy)||1;
   let f=(d-LD)*0.008;l.s.vx+=dx/d*f;l.s.vy+=dy/d*f;l.t.vx-=dx/d*f;l.t.vy-=dy/d*f;}
 for(const n of VNODES){if(n===drag)continue;n.vx+=(WLD/2-n.x)*0.0012;n.vy+=(HLD/2-n.y)*0.0012;
   n.x+=n.vx*=0.85;n.y+=n.vy*=0.85;n.x=Math.max(40,Math.min(WLD-40,n.x));n.y=Math.max(46,Math.min(HLD-40,n.y));}
 // hard anti-overlap pass so labels stay separable however dense the case is
 for(let i=0;i<VNODES.length;i++)for(let j=i+1;j<VNODES.length;j++){
   const a=VNODES[i],b=VNODES[j];let dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy)||1;
   const m=a.r+b.r+18-d;if(m>0){const px=dx/d*m/2,py=dy/d*m/2;a.x+=px;a.y+=py;b.x-=px;b.y-=py;}}
 render();
}
function fit(){
 if(!VNODES.length){cam={x:0,y:0,w:W,h:H};fitW=W;setVB();render();return;}
 let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
 for(const n of VNODES){x0=Math.min(x0,n.x);y0=Math.min(y0,n.y);x1=Math.max(x1,n.x);y1=Math.max(y1,n.y);}
 x0-=90;y0-=90;x1+=210;y1+=90;                       // extra right pad: labels stick out that side
 let w=x1-x0,h=y1-y0;const ar=W/H;
 if(w/h<ar){const nw=h*ar;x0-=(nw-w)/2;w=nw;}else{const nh=w/ar;y0-=(nh-h)/2;h=nh;}
 cam={x:x0,y:y0,w:w,h:h};fitW=w;setVB();render();
}
function egeom(l){
 const x1=l.s.x,y1=l.s.y,x2=l.t.x,y2=l.t.y;
 const dx=x2-x1,dy=y2-y1,d=Math.hypot(dx,dy)||1;
 // fan parallel edges apart; the canonical sign keeps A->B and B->A on opposite
 // sides instead of mirroring onto each other
 const sgn=l.source<l.target?1:-1;
 const off=(l.pi-(l.pn-1)/2)*26*sgn;
 const cx=(x1+x2)/2-dy/d*off, cy=(y1+y2)/2+dx/d*off;
 // stop short of the target circle so the arrowhead stays visible
 const r=(N[l.target]?N[l.target].r:12)+5;
 const ex=x2-cx,ey=y2-cy,ed=Math.hypot(ex,ey)||1;
 const tx=x2-ex/ed*r, ty=y2-ey/ed*r;
 return {d:'M'+x1.toFixed(1)+' '+y1.toFixed(1)+'Q'+cx.toFixed(1)+' '+cy.toFixed(1)+' '+tx.toFixed(1)+' '+ty.toFixed(1),
         lx:(x1+2*cx+tx)/4, ly:(y1+2*cy+ty)/4};
}
function drawList(){
 // Aggregated view: one edge per (src, dst, category) with the per-visit LINKS
 // folded in (ids kept so chain/timeline focus still lights the right curve).
 if(!aggOn)return VLINKS;
 const g={};
 for(const l of VLINKS){if(!l.s||!l.t)continue;const k=l.source+'>'+l.target+'|'+l.cat;
  let a=g[k];
  if(!a)a=g[k]={source:l.source,target:l.target,cat:l.cat,s:l.s,t:l.t,count:0,
                users:new Set(),ids:[],first:null,last:null};
  a.count+=l.count;if(l.user)a.users.add(l.user);a.ids.push(l.i);
  if(l.first&&(!a.first||l.first<a.first))a.first=l.first;
  if(l.last&&(!a.last||l.last>a.last))a.last=l.last;}
 const out=Object.values(g);
 const grp={};out.forEach(a=>{const k=[a.source,a.target].sort().join('|');(grp[k]=grp[k]||[]).push(a);});
 Object.keys(grp).forEach(k=>grp[k].forEach((a,i)=>{a.pi=i;a.pn=grp[k].length;}));
 return out;
}
function render(){
 const dl=drawList();
 // Constant on-screen sizing: text and stroke widths scale with the camera, so
 // zooming changes what fits, not how fat things are.
 const pxf=Math.max(.35,Math.min(2.6,cam.w/W));
 const focused=l=>l.ids?l.ids.some(i=>focusSet.has(i)):focusSet.has(l.i);
 const hasFocus=focusSet.size>0;
 const fnodes=new Set();if(selNode)fnodes.add(selNode);
 if(hasFocus)for(const l of dl)if(focused(l)){fnodes.add(l.source);fnodes.add(l.target);}
 let s=DEFS;
 for(const l of dl){if(!l.s||!l.t)continue;const g=l._g=egeom(l);
   const w=(1.4+Math.min(l.count,6)*0.35)*pxf, foc=focused(l), dim=hasFocus&&!foc;
   const dash=l.cat==='failed'?` stroke-dasharray="${5*pxf} ${3*pxf}"`:'';
   s+=`<path class="edge${foc?' focus':''}${dim?' dim':''}" d="${g.d}" stroke="${CAT_COL[l.cat]}" stroke-width="${(foc?w+1.6*pxf:w).toFixed(2)}" marker-end="url(#arr-${l.cat})"${dash}/>`;}
 if(showLbl||showDates){
  // Label only what can breathe: every focused edge, otherwise only when the
  // current viewport holds few enough edges (zooming in thins the crowd).
  const inView=g=>g.lx>=cam.x&&g.lx<=cam.x+cam.w&&g.ly>=cam.y&&g.ly<=cam.y+cam.h;
  let cand=dl.filter(l=>l.s&&l.t&&inView(l._g));
  if(hasFocus)cand=cand.filter(focused);
  else if(cand.length>80)cand=[];
  for(const l of cand){const g=l._g;
   const u=l.users?(l.users.size===1?l.users.values().next().value:l.users.size+' users'):l.user;
   const lbl=u?u+(l.count>1?' x'+l.count:''):'';
   if(showLbl&&lbl)s+=`<text class="elbl" font-size="${(10*pxf).toFixed(1)}" stroke-width="${(3*pxf).toFixed(1)}" x="${g.lx}" y="${g.ly-2*pxf}" text-anchor="middle">${esc(lbl)}</text>`;
   if(showDates&&l.first)s+=`<text class="dlbl" font-size="${(9*pxf).toFixed(1)}" stroke-width="${(3*pxf).toFixed(1)}" x="${g.lx}" y="${g.ly+(showLbl&&lbl?10*pxf:8*pxf)}" text-anchor="middle">${esc(l.first.slice(5,16))}</text>`;}}
 for(const n of VNODES){const dim=hasFocus&&!fnodes.has(n.id);
   s+=`<g class="node${dim?' dim':''}${n.id===selNode?' sel':''}" data-id="${esc(n.id)}"><circle cx="${n.x}" cy="${n.y}" r="${n.r}" fill="${roleCol[n.role]}"/>`+
      `<text font-size="${(12*pxf).toFixed(1)}" x="${n.x+n.r+3}" y="${n.y+4}">${esc(n.id)}</text></g>`;}
 svg.innerHTML=s;
}
const toWorld=e=>{const r=svg.getBoundingClientRect();
 return {x:cam.x+(e.clientX-r.left)/r.width*cam.w, y:cam.y+(e.clientY-r.top)/r.height*cam.h};};
const clearSel=()=>{$('plist').querySelectorAll('.tl').forEach(x=>x.classList.remove('sel'));
 $('tlist').querySelectorAll('.tl').forEach(x=>x.classList.remove('sel'));};
svg.addEventListener('mousedown',e=>{const g=e.target.closest('.node');moved=0;
 if(g){drag=N[g.dataset.id];wake();}
 else{pan={x:e.clientX,y:e.clientY,cx:cam.x,cy:cam.y};svg.style.cursor='grabbing';}});
window.addEventListener('mouseup',()=>{
 // a press that never travelled is a click: node -> focus its neighbourhood,
 // background -> clear the focus (drag/pan handled in mousemove)
 if(moved<5){
  if(drag){const id=drag.id;
   if(selNode===id){selNode=null;focusSet=new Set();}
   else{selNode=id;focusSet=new Set(LINKS.filter(l=>l.source===id||l.target===id).map(l=>l.i));}
   clearSel();render();}
  else if(pan){selNode=null;focusSet=new Set();clearSel();render();}}
 drag=null;pan=null;svg.style.cursor='grab';});
let _raf=0; const sched=()=>{if(!_raf)_raf=requestAnimationFrame(()=>{_raf=0;render();});};
svg.addEventListener('wheel',e=>{e.preventDefault();
 const p=toWorld(e), f=e.deltaY>0?1.15:1/1.15;
 const nw=Math.min(Math.max(cam.w*f,W/6),WLD*1.6), nh=nw*(cam.h/cam.w);
 cam.x=p.x-(p.x-cam.x)*nw/cam.w; cam.y=p.y-(p.y-cam.y)*nh/cam.h;
 cam.w=nw; cam.h=nh; setVB(); sched();},{passive:false});
svg.addEventListener('dblclick',()=>fit());
window.addEventListener('mousemove',e=>{
 moved+=Math.abs(e.movementX||0)+Math.abs(e.movementY||0);
 if(drag&&moved>=5){const p=toWorld(e);drag.x=p.x;drag.y=p.y;drag.vx=drag.vy=0;}
 else if(pan){const r=svg.getBoundingClientRect();
  cam.x=pan.cx-(e.clientX-pan.x)/r.width*cam.w;cam.y=pan.cy-(e.clientY-pan.y)/r.height*cam.h;setVB();}
 const g=e.target.closest&&e.target.closest('.node');
 if(g){const id=g.dataset.id;const inc=VLINKS.filter(l=>l.source===id||l.target===id).sort((a,b)=>(a.t0||0)-(b.t0||0));
   tip.style.display='block';tip.style.left=(e.clientX+12)+'px';tip.style.top=(e.clientY+12)+'px';
   tip.innerHTML='<b>'+esc(id)+'</b> <span style="color:#8a93a3">('+esc(roleOf[id])+')</span><br>'+inc.map(l=>
     (l.source===id?'&rarr; ':'&larr; ')+esc(l.source===id?l.target:l.source)+' : '+esc(l.user||'')+
     ' <span style="color:#8a93a3">'+esc(catLabel(l))+(l.count>1?' x'+l.count:'')+'</span>'+
     (l.first?' <span style="color:#8a93a3">'+esc(l.first.slice(0,19))+'</span>':'')+
     (l.reasons.length?' <span style="color:#e0533d">['+esc(l.reasons.join('+'))+']</span>':'')).join('<br>');
 } else tip.style.display='none';
});
window.addEventListener('resize',()=>{W=svg.clientWidth||W;H=svg.clientHeight||H;fit();});
setVB();syncT();applyFilters();
for(let i=0;i<300;i++)step();
fit();
wake();
</script></body></html>
"""
