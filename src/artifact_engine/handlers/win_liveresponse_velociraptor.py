"""Handler: Velociraptor LiveResponse. Output: JSONs/<artifact>.json + suspicious.json

LiveResponse is the volatile/live state of the host (running processes with
hashes, live netstat, listening ports, services, scheduled tasks, drivers, WMI
persistence, logged-in users, ...) that the disk-based KAPE parsers cannot see.
Velociraptor writes each artifact as JSONL under
<collection>/Velociraptor/LiveResponse/results/.

This handler stays JSON-native (no CSV round-trip): it normalises the wanted
artifacts into a `JSONs/` folder. Crucially, every activity artifact is ENRICHED
with a per-row `flag` column (the DFIR reason a row is interesting, empty when
benign) so each table is self-flagging and sortable in the consolidated db/xlsx
-- not a raw dump. The cross-artifact `suspicious.json` rollup is derived from
those same flags. Rules are low-FP by design (the Windows counterpart of the
Linux suspicious rules): execution from a staging dir, LOLBIN command lines,
system-process masquerading, unsigned/known-vulnerable (BYOVD) drivers, code-
executing WMI persistence, staged listeners/connections, RDP sessions, non-
default shares, hosts-file redirection, duplicate ARP MACs, recon/dyn-DNS, etc.

Robust to output renames: artifacts are matched by their basename (the part
after the last `%2F`), independent of the `Eiffel.LiveResponse.Windows` prefix,
which Velociraptor may change. Edit ARTIFACTS / _ANNOTATORS / the rule constants
to adapt.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._webcommon import Geo

# Where the results live, relative to a collection root. The handler tries this
# under the evidence dir and its parents (KAPE evidence root is <collection>/C,
# Velociraptor is its sibling). Change here if the collection layout changes.
_RESULTS_SUBPATH = Path("Velociraptor") / "LiveResponse" / "results"

# Artifact basename (after the `Eiffel.*%2F` prefix, without .json) -> output name.
# Only these are normalised into JSONs/; add an entry to surface more. The prefix
# is intentionally NOT part of the key, so a renamed output still matches.
ARTIFACTS = {
    "Generic.Client.Info": "client_info",
    "Windows.System.Pslist": "processes",
    "Windows.Network.Netstat": "netstat",
    "Windows.Network.ListeningPorts": "listening_ports",
    "Windows.System.Services": "services",
    "Windows.System.TaskScheduler": "scheduled_tasks",
    "Windows.Sys.StartupItems": "startup_items",
    "Windows.Persistence.PermanentWMIEvents": "wmi_persistence",
    "Windows.System.DNSCache": "dns_cache",
    "Windows.Network.ArpCache": "arp_cache",
    "Windows.System.Drivers": "drivers",
    "Windows.Sys.AllUsers": "users",
    "Windows.System.LocalAdmins": "local_admins",
    "Windows.System.LoggedInUsers": "logged_in_users",
    "Windows.System.Shares": "shares",
    "Windows.System.HostsFile": "hosts_file",
}

# User-writable / staging locations an attacker drops payloads in. Kept tight
# (high signal, low FP): ProgramData/AppData\Roaming are excluded on purpose
# (too many legitimate vendors live there).
_STAGING = (
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\",
    "\\users\\public\\", "\\$recycle.bin\\", "\\windows\\temp\\", "\\perflogs\\",
)
# LOLBIN / download-cradle hints in a command line (already lowercased).
_LOLBIN = (
    "-enc", "-encodedcommand", "frombase64string", "downloadstring", "downloadfile",
    "-w hidden", "-windowstyle hidden", "iex(", "iex ", "invoke-expression",
    "mshta http", "mshta vbscript", "mshta javascript", "regsvr32 /i:http",
    "scrobj.dll", "certutil -urlcache", "certutil -decode", "bitsadmin /transfer",
    "/transfer ", "-nop -", "-noprofile -enc",
)
# Default backdoor / handler listen ports (tight set to avoid dev-port FPs).
_BACKDOOR_PORTS = {1337, 4444, 4445, 5554, 5555, 6666, 9001, 12345, 31337}
# Known-abused (BYOVD) driver basenames (no .sys). Editable; representative set.
_VULN_DRIVERS = {
    "rtcore64", "rtkio64", "gdrv", "dbutil_2_3", "dbutil_2_5", "dbutildrv2",
    "capcom", "winring0", "winring0x64", "msio64", "ene", "eneio64", "wineio64",
    "atillk64", "gpcidrv64", "asrdrv", "asrdrv101", "asrdrv102", "asrdrv103",
    "asrdrv104", "asusio2", "asio2", "asio3", "iqvw64e", "naldrv", "phlashnt",
    "viragt64", "mhyprot2", "mhyprot3", "procexp152", "speedfan", "kprocesshacker",
}
# Dynamic-DNS / external-IP-recon / anonymity domain fragments (DNS cache).
_DYNDNS_RECON = (
    "no-ip.", "noip.", "ddns.", "duckdns.", "ngrok.", "hopto.", "zapto.",
    "serveo.", "myexternalip", "ipify", "ip-api", "icanhazip", "ifconfig.me",
    "checkip", "wtfismyip", ".onion", "dyndns", "portmap.io",
)
# System processes and the only dirs they legitimately run from (masquerading).
_SYS_PROC = {
    "svchost.exe": ("\\windows\\system32\\", "\\windows\\syswow64\\"),
    "lsass.exe": ("\\windows\\system32\\",),
    "services.exe": ("\\windows\\system32\\",),
    "csrss.exe": ("\\windows\\system32\\",),
    "wininit.exe": ("\\windows\\system32\\",),
    "winlogon.exe": ("\\windows\\system32\\",),
    "smss.exe": ("\\windows\\system32\\",),
    "lsaiso.exe": ("\\windows\\system32\\",),
    "spoolsv.exe": ("\\windows\\system32\\",),
    "taskhostw.exe": ("\\windows\\system32\\",),
    "dllhost.exe": ("\\windows\\system32\\", "\\windows\\syswow64\\"),
    "conhost.exe": ("\\windows\\system32\\",),
    "explorer.exe": ("\\windows\\explorer.exe", "\\windows\\syswow64\\explorer.exe"),
    "rundll32.exe": ("\\windows\\system32\\", "\\windows\\syswow64\\"),
}
_DRIVE_SHARE = re.compile(r"^[a-z]\$$")
_DEFAULT_SHARES = {"admin$", "ipc$", "print$", "fax$", "netlogon", "sysvol"}

# flag -> severity (any "high" component makes the row high).
_SEVERITY = {
    "exec_from_staging": "high", "lolbin": "high", "masquerade": "high",
    "servicedll_in_staging": "high", "owner_in_staging": "high",
    "suspicious_port": "high", "vulnerable_driver": "high", "code_consumer": "high",
    "duplicate_mac": "high", "estab_tor": "high", "estab_bulletproof": "high",
    # cross-artifact correlation flags (folded into the process row after linking)
    "suspicious_ancestry": "high", "staged_beacon": "high", "staged_listener": "high",
    "failure_command": "medium",
    "unsigned_driver": "medium", "recon_or_dyndns": "medium",
    "non_default_share": "medium", "local_account_admin": "medium",
    "rdp_session": "medium", "nonstandard_profile_path": "medium",
    "hosts_entry": "medium",
}


def _find_results(ctx) -> Path | None:
    ev = Path(ctx.evidence)
    for base in (ev, ev.parent, ev.parent.parent):
        cand = base / _RESULTS_SUBPATH
        if cand.is_dir():
            return cand
    return None


def _artifact_key(path: Path) -> str:
    """Velociraptor file name -> bare artifact basename (prefix-independent)."""
    name = path.name
    if name.endswith(".json"):
        name = name[:-5]
    for sep in ("%2F", "/"):           # encoded or already-decoded path separator
        if sep in name:
            name = name.rsplit(sep, 1)[1]
    return name


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return rows


def _norm(p) -> str:
    return str(p or "").strip().strip('"').lower().replace("/", "\\")


def _in_staging(*paths) -> bool:
    for p in paths:
        s = _norm(p)
        if not s:
            continue
        s = "\\" + s + "\\"
        if any(tok in s for tok in _STAGING):
            return True
    return False


def _is_lolbin(*cmds) -> bool:
    for c in cmds:
        low = str(c or "").lower()
        if low and any(tok in low for tok in _LOLBIN):
            return True
    return False


def _ip_scope(addr: str) -> str:
    try:
        ip = ipaddress.ip_address(str(addr).strip())
    except ValueError:
        return ""
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private or ip.is_link_local:
        return "private"
    if ip.is_unspecified or ip.is_reserved:
        return ""
    return "public"


def _task_exec(rec: dict) -> tuple[str, str]:
    """Real exec command/args of a scheduled task (the top-level Command is
    truncated/lowercased; the _XML has the full one)."""
    cmd, args = rec.get("Command") or "", rec.get("Arguments") or ""
    try:
        exe = rec["_XML"]["Task"]["Actions"]["Exec"]
        if isinstance(exe, dict):
            cmd = exe.get("Command") or cmd
            args = exe.get("Arguments") or args
    except (KeyError, TypeError):
        pass
    return str(cmd), str(args)


# --------------------------------------------------------------------------- #
# Per-artifact row annotators: return a "+"-joined flag string ("" = benign),
# may enrich the record in place (e.g. netstat scope). `sh` carries shared,
# cross-artifact data (pid->exe, duplicate MACs).
# --------------------------------------------------------------------------- #
def _flag_process(rec: dict, sh: dict) -> str:
    flags = []
    exe, cl, name = rec.get("Exe") or "", rec.get("CommandLine") or "", (rec.get("Name") or "").lower()
    if _in_staging(exe):
        flags.append("exec_from_staging")
    if _is_lolbin(cl):
        flags.append("lolbin")
    exp = _SYS_PROC.get(name)
    if exp and exe and not any(d in _norm(exe) for d in exp):
        flags.append("masquerade")
    # NOTE: a bare "unsigned process outside system dirs" flag was dropped -- it is
    # inherently noisy (portable/LOB apps, the examiner's own captured tooling) and
    # the high-value case (unsigned in a staging dir) is already exec_from_staging.
    # The full Authenticode is kept in the table for manual sorting.
    return "+".join(flags)


def _flag_service(rec: dict, sh: dict) -> str:
    flags = []
    path = rec.get("AbsoluteExePath") or rec.get("PathName") or ""
    dll = rec.get("ServiceDll") or ""
    if _in_staging(path):
        flags.append("exec_from_staging")
    if _in_staging(dll):
        flags.append("servicedll_in_staging")
    if _is_lolbin(path, dll):
        flags.append("lolbin")
    # Most services with a recovery command are legit (Windows/vendor "-safemode",
    # "sc.exe start ..."); only a recovery command in staging or a LOLBIN matters.
    fc = rec.get("FailureCommand")
    if fc and (_in_staging(fc) or _is_lolbin(fc)):
        flags.append("failure_command")
    return "+".join(flags)


def _flag_task(rec: dict, sh: dict) -> str:
    cmd, args = _task_exec(rec)
    flags = []
    if _in_staging(cmd, args):
        flags.append("exec_from_staging")
    if _is_lolbin(f"{cmd} {args}"):
        flags.append("lolbin")
    return "+".join(flags)


def _flag_startup(rec: dict, sh: dict) -> str:
    details = rec.get("Details") or ""
    flags = []
    if _in_staging(details):
        flags.append("exec_from_staging")
    if _is_lolbin(details):
        flags.append("lolbin")
    return "+".join(flags)


_BULLETPROOF = ("aeza", "stark industries", "chang way", "flokinet", "njalla",
                "pq hosting", "mivocloud", "bucklog", "spectre operations",
                "railnet", "green floid")


def _is_bulletproof(asn: str) -> bool:
    """True if the AS-org is a documented bulletproof / abuse-friendly provider.
    Major clouds (Azure/AWS/Google/Akamai) are hosting too but dominate a normal
    host's ESTAB traffic, so they stay context-only -- only these get a flag."""
    a = asn.lower()
    return any(k in a for k in _BULLETPROOF)


def _flag_netstat(rec: dict, sh: dict) -> str:
    raddr = rec.get("Raddr.IP") or ""
    rec["scope"] = _ip_scope(raddr)
    pid = rec.get("Pid")
    exe = sh["pid_exe"].get(pid, "") if isinstance(pid, int) else ""
    rec["owner_exe"] = exe
    # ASN/geo context for routable remote peers (columns, 0 FP: the analyst sorts
    # the odd cloud out; `asn` always carries the raw AS-org).
    country = origin = asn = ""
    geo = sh.get("geo")
    if geo is not None and rec["scope"] == "public":
        country, origin, asn = geo.lookup(raddr)
    rec["country"], rec["origin"], rec["asn"] = country, origin, asn
    # Flags: low-FP only. A normal host holds 20-50 ESTAB connections to major
    # clouds (svchost/OneDrive/Teams/browsers), so hosting/foreign are context, not
    # flags; only unambiguous C2 destinations (Tor, bulletproof AS) are flagged --
    # plus the existing "owner runs from a staging dir".
    flags = []
    estab = rec.get("Status") == "ESTAB"
    if estab and exe and _in_staging(exe):
        flags.append("owner_in_staging")
    if estab and origin == "tor":
        flags.append("estab_tor")
    if estab and _is_bulletproof(asn):
        flags.append("estab_bulletproof")
    return "+".join(flags)


def _flag_listen(rec: dict, sh: dict) -> str:
    flags = []
    pid = rec.get("Pid")
    exe = sh["pid_exe"].get(pid, "") if isinstance(pid, int) else ""
    rec["owner_exe"] = exe
    if rec.get("Port") in _BACKDOOR_PORTS:
        flags.append("suspicious_port")
    if exe and _in_staging(exe):
        flags.append("owner_in_staging")
    return "+".join(flags)


def _flag_driver(rec: dict, sh: dict) -> str:
    flags = []
    if rec.get("IsSigned") is False:
        flags.append("unsigned_driver")
    base = _norm(rec.get("DriverName") or rec.get("Name") or "").rsplit("\\", 1)[-1]
    base = base.rsplit(".sys", 1)[0]
    if base in _VULN_DRIVERS:
        flags.append("vulnerable_driver")
    return "+".join(flags)


def _flag_wmi(rec: dict, sh: dict) -> str:
    # Only CommandLine/ActiveScript consumers execute code -> persistence. Log-only
    # consumers (e.g. the built-in "SCM Event Log Consumer") carry no command/script.
    cons = rec.get("ConsumerDetails") or {}
    if cons.get("CommandLineTemplate") or cons.get("ScriptText") or cons.get("ScriptFileName"):
        return "code_consumer"
    return ""


def _flag_dns(rec: dict, sh: dict) -> str:
    name = (rec.get("Name") or "").lower().rstrip(".")
    return "recon_or_dyndns" if any(tok in name for tok in _DYNDNS_RECON) else ""


def _flag_arp(rec: dict, sh: dict) -> str:
    mac = (rec.get("RemoteMACAddress") or "").lower()
    if rec.get("AddressFamily") == "IPv4" and mac and mac in sh["dup_macs"]:
        return "duplicate_mac"
    return ""


def _flag_user(rec: dict, sh: dict) -> str:
    path = rec.get("Directory") or (rec.get("Data") or {}).get("ProfileImagePath") or ""
    return "nonstandard_profile_path" if _in_staging(path) else ""


def _flag_admin(rec: dict, sh: dict) -> str:
    src = (rec.get("PrincipalSource") or "").lower()
    sid = rec.get("SID") or ""
    return "local_account_admin" if src == "local" and not sid.endswith("-500") else ""


def _flag_logon(rec: dict, sh: dict) -> str:
    return "rdp_session" if rec.get("LogonType") == 10 else ""


def _flag_hosts(rec: dict, sh: dict) -> str:
    host = (rec.get("Hostname") or "").strip()
    res = (rec.get("Resolution") or "").strip() if rec.get("Resolution") else ""
    return "hosts_entry" if host or res else ""


_ANNOTATORS = {
    "Windows.System.Pslist": _flag_process,
    "Windows.System.Services": _flag_service,
    "Windows.System.TaskScheduler": _flag_task,
    "Windows.Sys.StartupItems": _flag_startup,
    "Windows.Network.Netstat": _flag_netstat,
    "Windows.Network.ListeningPorts": _flag_listen,
    "Windows.System.Drivers": _flag_driver,
    "Windows.Persistence.PermanentWMIEvents": _flag_wmi,
    "Windows.System.DNSCache": _flag_dns,
    "Windows.Network.ArpCache": _flag_arp,
    "Windows.Sys.AllUsers": _flag_user,
    "Windows.System.LocalAdmins": _flag_admin,
    "Windows.System.LoggedInUsers": _flag_logon,
    "Windows.System.HostsFile": _flag_hosts,
    # client_info has no flag: it is identity/reference (cross-checked with the
    # registry machine_info table), not activity.
}
# shares uses a regex match, kept out of the simple map.


def _sev(flag: str) -> str:
    return "high" if any(_SEVERITY.get(f) == "high" for f in flag.split("+")) else "medium"


def _mac_dups(arp_rows: list[dict]) -> set[str]:
    """MACs answering for 2+ distinct IPv4 unicast addresses -> ARP spoofing /
    gateway impersonation."""
    by_mac: dict[str, set[str]] = defaultdict(set)
    for r in arp_rows:
        if r.get("AddressFamily") != "IPv4":
            continue
        mac = (r.get("RemoteMACAddress") or "").lower()
        ip = r.get("RemoteAddress") or ""
        if not mac or mac in ("ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00"):
            continue
        if _ip_scope(ip) not in ("private", "public"):   # skip multicast/loopback
            continue
        by_mac[mac].add(ip)
    return {mac for mac, ips in by_mac.items() if len(ips) >= 2}


def _detail(key: str, r: dict) -> str:
    if key == "Windows.Network.Netstat":
        return f"{r.get('Name')} (pid {r.get('Pid')}) -> {r.get('Raddr.IP')}:{r.get('Raddr.Port')}"
    if key == "Windows.Network.ListeningPorts":
        return f"{r.get('Name')} (pid {r.get('Pid')}) listening :{r.get('Port')}"
    if key == "Windows.System.DNSCache":
        return f"{r.get('Name')} -> {r.get('Record')}"
    if key == "Windows.Network.ArpCache":
        return f"{r.get('RemoteAddress')} = {r.get('RemoteMACAddress')}"
    if key == "Windows.System.HostsFile":
        return f"{r.get('Resolution')} {r.get('Hostname')}".strip()
    if key == "Windows.System.Drivers":
        return f"{r.get('DriverName') or r.get('Name')} ({r.get('Signer') or 'unsigned'})"
    name = (r.get("TaskName") or r.get("Name") or r.get("DisplayName")
            or r.get("LogonName") or "")
    path = (r.get("AbsoluteExePath") or r.get("Exe") or r.get("PathName")
            or r.get("Details") or r.get("OSPath") or "")
    return f"{name} -> {path}".strip(" ->") or name or path


# --------------------------------------------------------------------------- #
# Cross-artifact correlation: tie the live artifacts together around each process
# (Pid/Ppid/path) so an isolated flag becomes an entity with its full story --
# process tree + owned connections/listeners + the service/task that launched it.
# --------------------------------------------------------------------------- #
# Parent -> child basenames that are rarely a benign pair (macro / exploit spawn).
_SPAWN_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "mspub.exe", "msaccess.exe", "visio.exe", "wordpad.exe",
    "acrord32.exe", "acrobat.exe",
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
}
_SPAWN_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe",
    "wmic.exe", "msbuild.exe", "installutil.exe", "curl.exe", "hh.exe",
}


def _pname(p: dict) -> str:
    return (p.get("Name") or "").strip().lower()


def _label(p: dict) -> str:
    return f"{p.get('Name') or '?'}({p.get('Pid')})"


def _correlate(out_by_key: dict) -> tuple[list, dict, dict]:
    """Return (entities, corr_flags_by_pid, corr_detail_by_pid). Builds one entity
    per process that is suspicious in any way (own flag, a correlation flag, or it
    owns a flagged connection/listener) with its ancestry, children, external
    connections, listeners and launching service/task. Mutates nothing."""
    procs = out_by_key.get("Windows.System.Pslist", [])
    if not procs:
        return [], {}, {}

    by_pid: dict[int, dict] = {}
    children: dict[int, list] = defaultdict(list)
    for p in procs:
        pid, ppid = p.get("Pid"), p.get("Ppid")
        if isinstance(pid, int):
            by_pid[pid] = p
        if isinstance(ppid, int):
            children[ppid].append(p)

    net_by_pid: dict[int, list] = defaultdict(list)
    for r in out_by_key.get("Windows.Network.Netstat", []):
        if isinstance(r.get("Pid"), int):
            net_by_pid[r["Pid"]].append(r)
    listen_by_pid: dict[int, list] = defaultdict(list)
    for r in out_by_key.get("Windows.Network.ListeningPorts", []):
        if isinstance(r.get("Pid"), int):
            listen_by_pid[r["Pid"]].append(r)

    svc_by_pid: dict[int, dict] = {}
    svc_by_path: dict[str, dict] = {}
    for s in out_by_key.get("Windows.System.Services", []):
        if isinstance(s.get("Pid"), int) and s["Pid"] > 0:
            svc_by_pid[s["Pid"]] = s
        ap = _norm(s.get("AbsoluteExePath") or s.get("PathName"))
        if ap:
            svc_by_path.setdefault(ap, s)
    task_by_path: dict[str, dict] = {}
    for t in out_by_key.get("Windows.System.TaskScheduler", []):
        ap = _norm(_task_exec(t)[0])
        if ap:
            task_by_path.setdefault(ap, t)

    def ancestry(p: dict) -> list[dict]:
        chain, seen, cur = [], set(), p
        while cur is not None and cur.get("Pid") not in seen and len(chain) < 8:
            seen.add(cur.get("Pid"))
            chain.append(cur)
            ppid = cur.get("Ppid")
            cur = by_pid.get(ppid) if isinstance(ppid, int) else None
        return chain

    def launcher(p: dict):
        s = svc_by_pid.get(p.get("Pid")) or svc_by_path.get(_norm(p.get("Exe")))
        if s:
            return {"kind": "service", "name": s.get("Name") or s.get("DisplayName"),
                    "state": s.get("State")}
        t = task_by_path.get(_norm(p.get("Exe")))
        if t:
            return {"kind": "task", "name": t.get("TaskName") or t.get("Name")}
        return None

    corr_flags: dict[int, list] = defaultdict(list)
    corr_detail: dict[int, str] = {}
    interesting: set[int] = set()
    for p in procs:
        pid = p.get("Pid")
        if not isinstance(pid, int):
            continue
        staged, lol = _in_staging(p.get("Exe")), _is_lolbin(p.get("CommandLine"))
        parent = by_pid.get(p.get("Ppid")) if isinstance(p.get("Ppid"), int) else None
        ext = [r for r in net_by_pid.get(pid, [])
               if r.get("Status") == "ESTAB" and _ip_scope(r.get("Raddr.IP")) == "public"]
        reasons = []
        if parent and _pname(parent) in _SPAWN_PARENTS and _pname(p) in _SPAWN_CHILDREN:
            corr_flags[pid].append("suspicious_ancestry")
            reasons.append(f"spawned by {_label(parent)}")
        if (staged or lol) and ext:
            corr_flags[pid].append("staged_beacon")
            reasons.append(f"beacons to {ext[0].get('Raddr.IP')}:{ext[0].get('Raddr.Port')}")
        if staged and listen_by_pid.get(pid):
            corr_flags[pid].append("staged_listener")
            reasons.append(f"listening :{listen_by_pid[pid][0].get('Port')}")
        if reasons:
            corr_detail[pid] = f"{_label(p)}: " + "; ".join(reasons)
        owns_flagged = (any(r.get("flag") for r in net_by_pid.get(pid, []))
                        or any(r.get("flag") for r in listen_by_pid.get(pid, [])))
        if p.get("flag") or corr_flags.get(pid) or owns_flagged:
            interesting.add(pid)

    entities = []
    for pid in interesting:
        p = by_pid[pid]
        flags = sorted(set((p.get("flag") or "").split("+")) - {""} | set(corr_flags.get(pid, [])))
        sev = "high" if any(_SEVERITY.get(f) == "high" for f in flags) else "medium"
        conns = [{"raddr": r.get("Raddr.IP"), "rport": r.get("Raddr.Port"),
                  "status": r.get("Status"), "origin": r.get("origin"), "asn": r.get("asn"),
                  "flag": r.get("flag") or ""}
                 for r in net_by_pid.get(pid, [])
                 if r.get("flag") or (r.get("Status") == "ESTAB"
                                      and _ip_scope(r.get("Raddr.IP")) == "public")][:20]
        listens = [{"port": r.get("Port"), "flag": r.get("flag") or ""}
                   for r in listen_by_pid.get(pid, [])][:20]
        entities.append({
            "severity": sev, "pid": pid, "ppid": p.get("Ppid"),
            "name": p.get("Name"), "exe": p.get("Exe"),
            "cmdline": (p.get("CommandLine") or "")[:300],
            "username": p.get("Username"), "elevated": p.get("TokenIsElevated"),
            "create_time": p.get("CreateTime"), "flags": flags,
            "ancestry": [_label(x) for x in reversed(ancestry(p))],
            "children": [_label(c) for c in children.get(pid, [])][:20],
            "connections": conns, "listening": listens, "launched_by": launcher(p),
        })
    entities.sort(key=lambda e: (0 if e["severity"] == "high" else 1, e["name"] or ""))
    return entities, corr_flags, corr_detail


_HEAVY = {"_XML", "TokenInfo", "Data", "FailureActions", "Hash", "Authenticode",
          "HardWareID", "CompatID", "PDO", "ConsumerDetails", "FilterDetails"}


def _compact(r: dict) -> dict:
    """Scalar fields only -> a small finding record (drops heavy nested blobs)."""
    return {k: v for k, v in r.items() if k not in _HEAVY and not isinstance(v, (dict, list))}


def run(ctx) -> None:
    if str(ctx.volume).upper().startswith("VSS"):
        raise HandlerSkip("LiveResponse is host-global, parsed on the live volume only")

    results = _find_results(ctx)
    if results is None:
        raise HandlerSkip("no Velociraptor LiveResponse results")

    present: dict[str, Path] = {}
    for f in results.glob("*.json"):           # the .json.index sidecars are skipped
        present[_artifact_key(f)] = f
    wanted = {key: present[key] for key in ARTIFACTS if key in present}
    if not wanted:
        raise HandlerSkip("no known LiveResponse artifacts present")

    ctx.out.mkdir(parents=True, exist_ok=True)
    loaded = {key: _read_jsonl(path) for key, path in wanted.items()}

    # Shared cross-artifact context for the annotators.
    sh = {
        "pid_exe": {r["Pid"]: (r.get("Exe") or "")
                    for r in loaded.get("Windows.System.Pslist", [])
                    if isinstance(r.get("Pid"), int)},
        "dup_macs": _mac_dups(loaded.get("Windows.Network.ArpCache", [])),
        "geo": Geo(ctx.assets),          # offline ASN/country for netstat enrichment
    }

    # Pass 1: annotate every row with its per-artifact flag (no findings yet, so the
    # cross-artifact correlation below can still raise a benign-looking process to
    # suspicious before the findings are frozen).
    out_by_key: dict[str, list] = {}
    for key, rows in loaded.items():
        if not rows:                            # 0-row policy: no file
            continue
        ann = _ANNOTATORS.get(key)
        if key == "Windows.System.Shares":
            ann = lambda r, _sh: (                                       # noqa: E731
                "" if (r.get("Name") or "").lower() in _DEFAULT_SHARES
                or _DRIVE_SHARE.match((r.get("Name") or "").lower())
                else "non_default_share")
        out_by_key[key] = [({"flag": ann(r, sh), **r} if ann else r) for r in rows]

    # Pass 2: correlate around each process and fold the correlation flags into the
    # process rows, so process.json and suspicious.json both reflect them.
    entities, corr_flags, corr_detail = _correlate(out_by_key)
    for p in out_by_key.get("Windows.System.Pslist", []):
        cf = corr_flags.get(p.get("Pid"))
        if cf:
            p["flag"] = "+".join(x for x in [p.get("flag") or "", *cf] if x)

    # Pass 3: derive findings from the FINAL flags and write each artifact.
    findings: list[dict] = []
    for key, out_rows in out_by_key.items():
        for r in out_rows:
            flag = r.get("flag") if isinstance(r, dict) else ""
            if flag:
                detail = (corr_detail.get(r.get("Pid")) if key == "Windows.System.Pslist"
                          and r.get("Pid") in corr_detail else _detail(key, r))
                findings.append({"artifact": ARTIFACTS[key], "severity": _sev(flag),
                                 "flag": flag, "detail": detail, "fields": _compact(r)})
        out = ctx.out / f"{ARTIFACTS[key]}.json"
        try:
            out.write_text(json.dumps(out_rows, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as e:
            if ctx.log:
                ctx.log.warning(f"[!] liveresponse: could not write {out.name}: {e}")

    info = (loaded.get("Generic.Client.Info", []) or [{}])[0]
    # correlation.json: the pivot view (one entry per suspicious process + its story).
    if entities:
        (ctx.out / "correlation.json").write_text(json.dumps({
            "machine": ctx.machine_name, "hostname": info.get("Hostname"),
            "counts": {"total": len(entities),
                       "high": sum(1 for e in entities if e["severity"] == "high"),
                       "medium": sum(1 for e in entities if e["severity"] == "medium")},
            "entities": entities,
        }, ensure_ascii=False, indent=2), encoding="utf-8")

    if not findings:
        return                                  # 0-row policy: no suspicious.json

    findings.sort(key=lambda f: (0 if f["severity"] == "high" else 1, f["artifact"], f["flag"]))
    summary = {
        "machine": ctx.machine_name,
        "hostname": info.get("Hostname"),
        "fqdn": info.get("Fqdn"),
        "counts": {
            "total": len(findings),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
        },
        "findings": findings,
    }
    (ctx.out / "suspicious.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if ctx.log:
        ctx.log.info(f"    [liveresponse] {ctx.machine_name}: {summary['counts']['total']} "
                     f"suspicious ({summary['counts']['high']} high)")
