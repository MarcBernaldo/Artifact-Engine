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
import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from artifact_engine.core import lateral_report
from artifact_engine.core.detector import Machine, name_evtx_drops
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
# ...but an external touching one of these NEVER gets culled by the volume cap: a
# one-shot anonymous / pivot / internet-RDP source, or a brute force that WORKED,
# matters even at count 1. `rdp_public` is here rather than special-cased in the
# curation because internet-facing RDP landing on an internal host IS the finding.
_HIGH_SIGNAL = {"anonymous_logon", "chain", "chainsaw", "explicit_creds",
                "untrusted_cert", "rdp_public", "brute_success"}
# `failed_logon` is deliberately NOT above: see _MAX_BRUTE.
# A password spray from the internet is ONE fact ("we are being sprayed"), not one
# finding per source. Keeping every failed-only source unconditionally turned a real
# case into a 443-node graph of which 368 were public IPs that had never done
# anything but fail -- the volume cap ended up deciding just 4 nodes, and the actual
# lateral movement was buried. So they are kept in full while they are FEW (each one
# still matters then), and past this many only the loudest are drawn; the rest are
# counted in the header and remain, complete, in the CSV.
_MAX_BRUTE = 40


def _is_public_ip(node: str) -> bool:
    """True only for a globally-routable IP (public internet source). RFC1918,
    CGNAT, loopback, link-local (169.254/fe80) and non-IP names all return False."""
    try:
        return ipaddress.ip_address(node).is_global
    except ValueError:
        return False


def _rdp_in_reasons(src_label: str, src_case: bool) -> set[str]:
    """Reasons for a SUCCESSFUL inbound RDP -- often none, on purpose.

    RDP is the normal administration transport on a Windows estate, so flagging
    every inbound session is the same mistake as flagging every successful SSH:
    on a real case it put 83% of all edges under `suspicious=yes`, of which 500
    were a private host RDP-ing to another private host and nothing else. A column
    that says "yes" to five edges out of six tells the analyst nothing, and the
    flood then forced the graph's volume cap to drop ~200 hosts chosen BY VOLUME,
    i.e. blindly -- which is how three internet-facing RDP sources came to be
    invisible in the first place.

    So routine inbound RDP is CSV-only, exactly like a routine inbound SSH
    (`_collect_linux`), and only the genuinely notable shapes carry a reason:
      * `rdp_public`   -- the source is a globally-routable internet address.
                          Internet-facing RDP straight onto an internal host is a
                          top-tier finding (initial access / hands-on-keyboard).
      * `case_to_case` -- movement BETWEEN two acquired hosts.
    A failed attempt, a chainsaw verdict, an ANONYMOUS LOGON or a pivot chain add
    their own reasons elsewhere, so an attack-shaped RDP never relies on this."""
    reasons: set[str] = set()
    if _is_public_ip(src_label):
        reasons.add("rdp_public")
    if src_case:
        reasons.add("case_to_case")
    return reasons

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


_RE_TS_OFFSET = re.compile(
    r"^(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)(?:\.\d+)?\s*([+-])(\d\d):?(\d\d)$")


def _as_utc(s: str) -> str:
    """Normalise an as-logged auth.log timestamp for a column named `_utc`.

    `auth.csv` writes what the log wrote, which ARCHITECTURE.md §5 documents and
    which is right for that file: syslog local, or RFC3339 with an offset. It is
    wrong the moment the value is dropped into the same slot as wtmp/btmp epochs
    and lands under `first_seen_utc` / `last_seen_utc`.

    Two concrete failures, both fixed here. `2026-05-19T10:15:03+02:00` was matched
    only on its leading 19 characters and rebuilt with `tzinfo=utc`, so the offset
    was DISCARDED rather than applied and the edge read two hours late. And the
    classic `May 19 10:15:03` form has no year, so `_add_edge`'s `max()` compared
    it as text: "May ..." sorts after "Aug ...", and an edge spanning a month
    boundary reported its first and last activity the wrong way round.

    So: apply a real offset, keep an already-bare timestamp, and drop anything
    that cannot be ordered. An edge with an empty window is honest; an edge with
    an inverted one is not.
    """
    t = (s or "").strip()
    if not t:
        return ""
    m = _RE_TS_OFFSET.match(t)
    if m:
        day, clock, sign, hh, mm = m.groups()
        delta = timedelta(hours=int(hh), minutes=int(mm))
        tz = timezone(-delta if sign == "-" else delta)
        aware = datetime.strptime(f"{day} {clock}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
        return aware.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return t if _RE_TS.match(t) else ""


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
    stays distinct ON PURPOSE -- a machine's LOCAL administrator is not the domain
    administrator, and merging them would invent lateral movement that never
    happened.

    Two forms that are NOT a different domain:
      * `-\\user` -- "-" is the placeholder for "no domain recorded", which the RDP
        operational channels emit constantly. Kept as-is it split one principal
        roughly in half (`-\\svc` and `CORP\\svc` as separate actors), so half their
        activity hid behind a search for either form.
      * a bare name in another case (`Administrador` vs `administrador`), which
        `_short_user` -- used for chain and brute_success matching -- already folds.
        Not folding it here left the label inconsistent with the matching.
    Both collapse to the bare lower-case name. Linux accounts ARE case-sensitive,
    so this could in theory merge `Bob` and `bob` on a UNIX host; usernames there
    are lower-case by convention and a split Windows principal is the far more
    likely, and far more damaging, error."""
    # Only the LEADING separator is stripped up front: a trailing one is meaningful
    # ("CORP\\" is a domain with no account, not an account called CORP), so it is
    # dealt with on the name below.
    u = (user or "").strip().lstrip("\\")
    if u in ("-", "-\\-", ""):
        return ""
    if "\\" in u:
        dom, _, name = u.partition("\\")
        name = name.strip().strip("\\")
        if name in ("", "-"):
            return ""                       # "CORP\\" / "CORP\\-": a domain, no account
        dom = dom.split(".")[0].upper().strip()
        return f"{dom}\\{name.lower()}" if dom and dom != "-" else name.lower()
    return u.lower()


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
        agg.last = max(agg.last, ts)
        if len(agg.ts) < _CHAIN_TS_CAP:
            t = _parse_ts(ts)
            if t is not None:
                agg.ts.append(t)
    return agg


# Loose-drop machines (a folder of web/firewall logs) are os=linux but are not
# hosts with a logon identity: they carry no auth/wtmp/known_hosts and no
# machine_info, so they must not become graph nodes. A loose EVTX drop is the
# opposite case and is deliberately absent here: event logs ARE logon evidence, so
# the drop joins the graph as the host its events name (see _name_evtx_drops).
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


def _node_label(machine: Machine, index: dict[str, str]) -> str:
    """Canonical node name for a machine: the hostname from machine_info when it is
    known, the acquisition folder otherwise.

    `Machine.name` is the FOLDER, produced by the profile's regex with `dir_name`
    as fallback -- so a KAPE collection delivered as `HOST-01_2026-07-01/` (no
    `_kape` in the name) falls back to the drive letter and the machine is called
    `C`. Every other host that saw a logon FROM it resolves the IP through
    machine_info to `HOST-01`, so the same host lands on the graph twice with its
    edges split; `dc_names` holds the resolved spelling, so a domain controller
    stops being recognised as one; and `_find_chains` keys inbound on `dst` and
    outbound on `src`, so the two halves of a pivot never join. Case alone is
    enough to trigger it, because the index lower-cases keys and returns the
    registry spelling. The Linux path was corrected for this; the Windows ones
    were not.
    """
    return _resolve(machine.name, index)[0] or machine.name


def _collect(machine: Machine, index: dict[str, str], edges: dict[tuple, _Edge]) -> bool:
    """Read one machine's evtx_security.csv, accumulate logon edges. Returns True if
    the machine logged Kerberos 4768/4769 (i.e. it is a domain controller)."""
    csv_path = machine.path / "CSVs" / "EventLogs" / "evtx_security.csv"
    if not csv_path.is_file():
        return False
    dst_label, dst_case = _node_label(machine, index), True
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
    src_label = _node_label(machine, index)
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
        if not dl or dl == src_label:
            continue
        user = _clean_user(sid_users.get((row.get("UserId") or "").strip(), ""))
        reasons = {"rdp_outbound"} | ({"case_to_case"} if dcase else set())
        _add_edge(edges, _Edge(src_label, dl, user, 10, eid, "ok", True, dcase,
                               reasons=reasons), (row.get("TimeCreated") or "").strip())


def _collect_rdp_mru(machine: Machine, index: dict[str, str], edges: dict[tuple, _Edge]) -> None:
    """rdp_outbound.csv (Terminal Server Client MRU): every host this box RDP'd to and
    the account used against it - the years-deep client-side lateral map."""
    src_label = _node_label(machine, index)
    for row in _open_csv(machine.path / "CSVs" / "Registry" / "rdp_outbound.csv"):
        target = (row.get("target") or "").strip()
        if not target:
            continue
        dl, dcase = _resolve(target, index)
        if not dl or dl == src_label:
            continue
        user = _clean_user(row.get("username_hint")) or _clean_user(row.get("user"))
        reasons = {"rdp_outbound"} | ({"case_to_case"} if dcase else set())
        if (row.get("cert_accepted") or "").strip() == "yes":
            reasons.add("untrusted_cert")     # user clicked through a bad certificate
        _add_edge(edges, _Edge(src_label, dl, user, 10, "TSC-MRU", "ok", True, dcase,
                               reasons=reasons), (row.get("key_last_write_utc") or "").strip())


def _collect_typed_unc(machine: Machine, index: dict[str, str], edges: dict[tuple, _Edge]) -> None:
    r"""explorer_input.csv TypedPaths that are UNC (\\host\share): SMB targets the
    user reached by hand - deliberate access the client's Security log never records."""
    src_label = _node_label(machine, index)
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
        if not dl or dl == src_label:
            continue
        reasons = {"typed_unc"} | ({"case_to_case"} if dcase else set())
        _add_edge(edges, _Edge(src_label, dl, _clean_user(row.get("user")), None,
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
    dst = _node_label(machine, index)
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
            _add_edge(edges, _Edge(sl, dst, _clean_user(row.get("UserName")), 10,
                                   f"{tag}-{eid}", "ok", scase, True,
                                   reasons=_rdp_in_reasons(sl, scase)),
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
                  _as_utc(row.get("timestamp") or ""))
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
        # A successful inbound RDP is only notable when it comes from the internet
        # or moves between two acquired hosts (see _rdp_in_reasons); a FAILED one
        # is always kept below, on its own reason.
        reasons = _rdp_in_reasons(src_label, src_case) if lt == 10 else set()
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
        # `dst_label` is THIS machine's canonical label (set by the caller); for
        # 4648 this host is the source, so it is the right name on both sides.
        if dl == dst_label:
            return None
        user = _clean_user(row.get("UserName")) or _first(_RE_TARGET, payload)
        reasons = {"explicit_creds"}
        if dcase:
            reasons.add("case_to_case")
        return _Edge(dst_label, dl, _clean_user(user), lt, eid, "ok",
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


# first_seen_utc/last_seen_utc carry the `_utc` suffix for the same reason every
# other engine CSV does: every source feeding an edge is UTC (EvtxECmd renders the
# event log's UTC FILETIME, wtmp/btmp are epoch->UTC, and the registry key-write
# columns are already `_utc`), so the header states it instead of leaving the
# analyst to assume.
_TIMELINE_COLS = ["src", "dst", "user", "logon_type", "event_id", "status",
                  "count", "first_seen_utc", "last_seen_utc", "src_in_case",
                  "suspicious", "reasons", "chainsaw"]


def _write_out(path: Path, write) -> bool:
    """Run `write(path)`, turning an unwritable output into a warning instead of a
    crash. Phase 5 is the LAST thing a run does, so an analyst who left
    lateral_movement.csv open in Excel used to lose the whole run to a
    PermissionError after every parser had already finished -- the same trap
    consolidate.build already sidesteps for a locked .db."""
    try:
        write(path)
        return True
    except OSError as e:
        log.warning(f"[!] could not write {path.name} (open elsewhere?): {e}")
        return False


def _write_csv(path: Path, edges: list[_Edge]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(_TIMELINE_COLS)
        for e in sorted(edges, key=lambda x: (-len(x.reasons), x.src, x.dst)):
            w.writerow([
                e.src, e.dst, e.user,
                _TYPE_NAME.get(e.logon_type, e.logon_type if e.logon_type is not None else ""),
                e.event_id, e.status, e.count, e.first, e.last,
                # not `suspicious`: a plain two-valued column, where "no" is a real
                # answer rather than a value that lands every row in a filter
                "yes" if e.src_case else "no",
                # `yes` or EMPTY, never `no` -- ARCHITECTURE.md §5. "Show me
                # everything flagged" is one filter, `suspicious` is not blank, and
                # a literal `no` puts every unflagged edge into it. The meta-test
                # that pins this only globbed handlers/, so core/ escaped it.
                "yes" if e.reasons else "", "+".join(sorted(e.reasons)),
                "+".join(sorted(e.chainsaw)),
            ])


# chainsaw detection CSVs whose verdicts corroborate an edge (its rule name is
# attached to the matching edge). "Network Logon" is dropped: it is chainsaw's label
# for every network logon and adds nothing over our own `network` category.
_CHAINSAW_FILES = ("chainsaw_login_attacks.csv", "chainsaw_lateral_movement.csv",
                   "chainsaw_rdp_attacks.csv", "chainsaw_rdp_events.csv")
# Chainsaw's RDP/logon rulesets emit a verdict for every ORDINARY session event as
# well as for real detections. "RDS - Session logoff succeeded" or "File Explorer
# shell start notification received" is a label for something that happened, not a
# finding -- and treating them as one makes an edge `suspicious` for the crime of
# being an RDP session, which the `event_id` / `logon_type` columns already say.
# Dropped here so `chainsaw` in the reasons column always means a real verdict.
_CHAINSAW_SKIP = {
    "", "network logon", "user authentication succeeded", "unlock logon",
    "rdp logon", "rdp session connected", "rdp session disconnected",
    "rds - session logon succeeded", "rds - session logoff succeeded",
    "rds - file explorer shell start notification received",
}


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
    over the samples: for each outbound time take the latest inbound not after it --
    the session that outbound most plausibly belongs to.

    Both lists must already be SORTED; `_find_chains` sorts each edge's `ts` once up
    front. Sorting here instead meant re-sorting the same (up to `_CHAIN_TS_CAP`)
    samples on every candidate pair -- the same outbound edge's list re-sorted once
    per candidate, thousands of times over on a busy case."""
    if not ts_in or not ts_out:
        return None
    i = 0
    for t_out in ts_out:
        while i + 1 < len(ts_in) and ts_in[i + 1] <= t_out:
            i += 1
        if ts_in[i] <= t_out <= ts_in[i] + window:
            return ts_in[i], t_out
    return None


def _find_chains(edges: list[_Edge]) -> list[dict]:
    """Pivot chains X ->(U) B ->(U) Y: a successful inbound logon of account U onto
    acquired host B, followed within a window by outbound activity from B by the
    same account (or an account-less RDP dial-out right after -- tight window).
    Machine accounts (HOST$) are excluded: their mutual auth chains everything.
    Marks both edges with reason `chain`; returns display dicts (capped)."""
    inbound: dict[tuple, list[_Edge]] = defaultdict(list)
    # Same inbound edges keyed by pivot alone, for the account-less lookup below:
    # scanning the whole `inbound` dict per account-less outbound edge was a full
    # pass over every pivot/user pair just to keep the few sharing that host.
    by_pivot: dict[str, list[_Edge]] = defaultdict(list)
    for e in edges:
        e.ts.sort()          # sorted ONCE here; _pair_times relies on it
        if (e.event_id in _CHAIN_IN_EIDS and e.status == "ok" and e.dst_case and e.ts):
            u = _short_user(e.user)
            if u and not u.endswith("$"):
                inbound[(e.dst, u)].append(e)
                by_pivot[e.dst].append(e)

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
            window, candidates = _CHAIN_WINDOW_NOUSER, by_pivot.get(out.src, [])
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
    # `aeng run` already named the drops right after parsing; `aeng lateral` re-detects
    # from scratch, so repeat it here (idempotent) -- the identity index below must key
    # on the real host or a dropped Security.evtx becomes a folder-shaped stranger.
    name_evtx_drops(machines)
    targets = _machine_hosts_live(machines)
    if not targets:
        return {"hosts": 0, "edges": 0, "suspicious": 0}
    index = _load_host_index(machines)

    def _label(m: Machine) -> str:
        # canonical node label (machine_info name when known), so a host referred
        # to by IP/short-name and by its own CSVs collapses onto ONE node.
        # Same helper the collectors use, so both sides of an edge agree.
        return _node_label(m, index)

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

    _write_out(root / "lateral_movement.csv", lambda p: _write_csv(p, edge_list))
    nodes, links, jchains, gstats = _graph_model(
        edge_list, case_labels, dc_names, linux_names, chains)
    _write_out(root / "lateral_movement.html",
               lambda p: p.write_text(lateral_report.render_html(nodes, links, jchains, gstats),
                                      encoding="utf-8"))
    hosts = {e.src for e in edge_list} | {e.dst for e in edge_list}
    return {"hosts": len(hosts), "edges": len(edge_list),
            "suspicious": sum(1 for e in edge_list if e.reasons),
            "chains": len(chains),
            "graph_hosts": len(nodes), "graph_edges": len(links),
            "graph_hidden": gstats["hidden"], "graph_brute": gstats["brute"]}


def _edge_category(e: _Edge) -> str:
    """The MECHANISM of an edge -- how the access was attempted -- never whether it
    succeeded. `status` carries that, orthogonally.

    `failed` used to be returned here and won over everything else, which threw the
    mechanism away: a failed Kerberos request and a failed network logon both
    collapsed to one class, so the graph could say that something failed but not
    what. The CSV always kept `status` and `event_id` in separate columns; only the
    graph model flattened them. Keeping the two axes apart is what lets the HTML
    filter "Kerberos" and "failed" independently, and it costs nothing visually
    because a failure was already drawn dashed -- that dash now keys off `status`.
    """
    if e.event_id == "4648":
        return "explicit"
    if e.event_id in ("4768", "4769"):
        return "kerberos"
    if e.event_id == "TSC-MRU":
        return "rdp_mru"
    if e.event_id == "TypedPath":
        return "typed_unc"
    # The Linux failure records name their own mechanism: without them here they
    # would fall through to "other", since they carry no Windows logon type.
    if e.event_id in ("ssh", "wtmp", "ssh_fail", "ssh_invalid", "btmp"):
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
                 linux_names: set[str], chains: list[dict]) -> tuple[list, list, list, dict]:
    """Curated subgraph for the HTML: acquired hosts + high-signal edges (inter-case
    movement, RDP/SSH, explicit creds, failed logons) + the most active external
    peers (capped). Routine external domain auth stays in the .csv only, so a DC
    that sees the whole domain doesn't blow the graph up to hundreds of nodes.
    `case_names`/`dc_names`/`linux_names` are canonical node labels (see build).

    Also returns the curation stats, so the page can SAY what it left out: a graph
    that silently drops peers is the reason three internet-facing RDP sources once
    went unnoticed, and an analyst reading only the HTML must never believe it is
    the whole case."""

    def is_case(n: str, flag: bool) -> bool:
        return flag or n in case_names

    signal = [e for e in edges if e.reasons]
    ext_weight: dict[str, int] = defaultdict(int)
    must_keep: set[str] = set()          # high-signal externals kept regardless of volume
    ext_ok: set[str] = set()             # externals that authenticated SUCCESSFULLY
    for e in signal:
        # anonymous / pivot / internet-RDP / brute-force-that-worked sources must
        # never be culled by the volume cap -- they matter at count 1. Internet-facing
        # RDP used to need its own clause here; it now arrives as the `rdp_public`
        # reason, so one _HIGH_SIGNAL test covers every case.
        hot = bool(e.reasons & _HIGH_SIGNAL)
        for n, flag in ((e.src, e.src_case), (e.dst, e.dst_case)):
            if is_case(n, flag):
                continue
            ext_weight[n] += e.count
            if e.status != "failed":
                ext_ok.add(n)
                if hot:
                    must_keep.add(n)
    # An external seen ONLY on failed logons never got in: a would-be intruder. Which
    # LABEL says so does not matter -- our own `failed_logon` or chainsaw's "Account
    # Brute Force" describe the same thing, and keying on the outcome instead of the
    # rule name keeps this working when the rulesets change. One such source is worth
    # a node; hundreds are ONE spray campaign, and drawing each of them buried the
    # real movement (a real case: 368 of 443 nodes, of which 334 were kept by that
    # single chainsaw rule). So: all of them while few, the loudest past _MAX_BRUTE.
    brute_only = set(ext_weight) - ext_ok
    hidden_brute = 0
    if len(brute_only) > _MAX_BRUTE:
        loudest = sorted(brute_only, key=lambda n: -ext_weight[n])[:_MAX_BRUTE]
        hidden_brute = len(brute_only) - len(loudest)
        brute_only = set(loudest)
    must_keep |= brute_only

    by_weight = {n for n, _ in sorted(ext_weight.items(), key=lambda x: -x[1])[:_MAX_EXTERNAL]}
    keep_ext = must_keep | by_weight
    hidden_total = len(set(ext_weight) - keep_ext)

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
    # admin reached, RDP-MRU / typed-UNC target) vs a bare source IP, itself split
    # into `public` (a globally-routable internet address -- attacker origin / C2 /
    # internet-facing access) and `external` (a private RFC1918/CGNAT/link-local IP
    # -- internal host), so the eye separates "where it reached" from "who came in"
    # and, above all, makes internet sources jump out for filtering.
    def _role(n: str) -> str:
        if n in dc_names:
            return "dc"
        if n in linux_names:
            return "linux"
        if node_case[n]:
            return "case"
        if _RE_IPV4.match(n) or ":" in n:
            return "public" if _is_public_ip(n) else "external"
        return "server"

    nodes = [{"id": n, "role": _role(n)} for n in sorted(node_case)]
    links = [{
        "source": e.src, "target": e.dst, "user": e.user,
        "cat": _edge_category(e),
        "ltype": _TYPE_NAME.get(e.logon_type, "") if e.logon_type is not None else "",
        "eid": e.event_id, "status": e.status, "count": e.count,
        "first": e.first, "last": e.last,
        # show the actual chainsaw verdict(s) rather than the generic "chainsaw" token
        "reasons": sorted(e.chainsaw) + sorted(r for r in e.reasons if r != "chainsaw"),
        # ...but FILTERING needs the canonical tokens, chainsaw rule names excluded:
        # the display list mixes in verdict text, which would give one chip per rule.
        "rs": sorted(e.reasons),
    } for e in kept]
    # chains whose two edges survived the curation, with their link indices so the
    # HTML "Attack paths" panel can highlight the pair
    kept_idx = {id(e): i for i, e in enumerate(kept)}
    jchains = [{"user": c["user"], "path": c["path"], "t0": c["t0"], "t1": c["t1"],
                "links": [kept_idx[id(c["_in"])], kept_idx[id(c["_out"])]]}
               for c in chains
               if id(c["_in"]) in kept_idx and id(c["_out"]) in kept_idx]
    return nodes, links, jchains, {"hidden": hidden_total, "brute": hidden_brute}


