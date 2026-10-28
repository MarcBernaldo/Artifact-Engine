"""Handler: machine information from the hives (SYSTEM/SOFTWARE).

Extracts hostname, OS version, IPs and users and writes them to art_machine_info.json
(+ .csv) to enrich the report and the consolidation. Tolerates missing or corrupt
hives (each section runs in its own try).

Where the acquisition carries a Velociraptor live response, its
`Generic.Client.Info` adds what the hives do not say: the domain role, the
architecture and memory, boot time and uptime, the time zone the host ran in, the
hypervisor, each interface's addresses, gateway and DNS servers, and the local
accounts with their last logon. The hives win where both answer (they are the
evidence on disk); the live view only fills the gaps. It used to be a table of its
own, `lr_client_info`, holding the same identity twice (v0.7.161).
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from Registry.Registry import Registry

_CONTROL_SETS = ("ControlSet001", "ControlSet002", "CurrentControlSet")
# Velociraptor's results beside a KAPE volume (<collection>/C and
# <collection>/Velociraptor are siblings), as the liveresponse parser finds them.
_LR_RESULTS = Path("Velociraptor") / "LiveResponse" / "results"
# Generic.Client.Info `Param` rows kept, and the key each takes. The rest describe
# the collector itself (its exe, working dir, start time), not the host.
_LR_PARAMS = {"BootTime": "boot_time_utc", "Uptime": "uptime_s", "LocalTZ": "timezone",
              "LocalTZOffset": "timezone_offset_s", "VirtualizationSystem": "virtualization",
              "VirtualizationRole": "virtualization_role"}


def _norm(value):
    """Normalize registry values to readable str/list."""
    if isinstance(value, bytes):
        for enc in ("utf-16-le", "utf-8", "latin1"):
            try:
                return value.decode(enc).rstrip("\x00")
            except Exception:  # noqa: BLE001
                pass
        return value.decode("latin1", errors="replace")
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    return value


def _open(path: Path) -> Registry | None:
    try:
        return Registry(str(path)) if path.is_file() else None
    except Exception:  # noqa: BLE001
        return None


def _os_info(software: Registry) -> dict:
    try:
        key = software.open(r"Microsoft\Windows NT\CurrentVersion")
    except Exception:  # noqa: BLE001
        return {}
    vals = {v.name(): _norm(v.value()) for v in key.values()}
    return {
        "product_name": vals.get("ProductName"),
        "release": vals.get("DisplayVersion") or vals.get("ReleaseId"),
        "build": vals.get("CurrentBuild"),
        "registered_owner": vals.get("RegisteredOwner"),
    }


def _computer_name(system: Registry) -> str | None:
    for cs in _CONTROL_SETS:
        try:
            key = system.open(cs + r"\Control\ComputerName\ComputerName")
        except Exception:  # noqa: BLE001
            continue
        for v in key.values():
            if v.name() == "ComputerName":
                return _norm(v.value())
    return None


def _domain(system: Registry) -> dict:
    """DNS domain / FQDN from the Tcpip parameters (cross-collection equivalent of
    Velociraptor's Generic.Client.Info.Fqdn, which is only present where there is a
    LiveResponse). `Domain` is the joined AD domain; `NV Domain` its non-volatile
    copy."""
    for cs in _CONTROL_SETS:
        try:
            key = system.open(cs + r"\Services\Tcpip\Parameters")
        except Exception:  # noqa: BLE001
            continue
        vals = {v.name(): _norm(v.value()) for v in key.values()}
        host = vals.get("Hostname")
        dom = vals.get("Domain") or vals.get("NV Domain")
        out: dict = {}
        if dom:
            out["domain"] = dom
        if host and dom:
            out["fqdn"] = f"{host}.{dom}"
        if out:
            return out
    return {}


def _ips(system: Registry) -> list[str]:
    ips: list[str] = []
    for cs in _CONTROL_SETS:
        try:
            key = system.open(cs + r"\Services\Tcpip\Parameters\Interfaces")
        except Exception:  # noqa: BLE001
            continue
        for sub in key.subkeys():
            for v in sub.values():
                if v.name() in ("DhcpIPAddress", "IPAddress"):
                    val = _norm(v.value())
                    for ip in (val if isinstance(val, list) else [val]):
                        if ip and str(ip) not in ("0.0.0.0", "") and str(ip) not in ips:
                            ips.append(str(ip))
        if ips:
            break
    return ips


def _users(software: Registry) -> dict[str, str]:
    users: dict[str, str] = {}
    try:
        key = software.open(r"Microsoft\Windows NT\CurrentVersion\ProfileList")
    except Exception:  # noqa: BLE001
        return users
    for sub in key.subkeys():
        for v in sub.values():
            if v.name() == "ProfileImagePath":
                name = str(_norm(v.value())).replace("/", "\\").split("\\")[-1]
                users[name] = sub.name()
    return users


def _client_info(evidence: Path) -> list[dict]:
    """The Generic.Client.Info rows of this acquisition's live response, or []."""
    for base in (evidence, evidence.parent, evidence.parent.parent):
        results = base / _LR_RESULTS
        if not results.is_dir():
            continue
        for f in results.glob("*.json"):
            name = f.name.removesuffix(".json").replace("%2F", "/").rsplit("/", 1)[-1]
            if name != "Generic.Client.Info":
                continue
            rows = []
            try:
                for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    try:
                        rec = json.loads(line) if line.strip() else None
                    except json.JSONDecodeError:
                        continue
                    if isinstance(rec, dict):
                        rows.append(rec)
            except OSError:
                return []
            return rows
    return []


def _epoch_utc(value) -> str:
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        return str(value) if value not in (None, "") else ""


def _dicts(value) -> list[dict]:
    """A sub-select's value: one dict, a list of them, or nothing."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _live(rows: list[dict]) -> dict:
    """What Generic.Client.Info adds, in machine_info's own shape."""
    out: dict = {}
    interfaces: dict[str, dict] = {}
    accounts: dict[str, dict] = {}
    for r in rows:
        if r.get("Hostname"):
            for src, dst in (("Fqdn", "fqdn"), ("Architecture", "architecture"),
                             ("KernelVersion", "kernel_version")):
                if r.get(src):
                    out[dst] = r[src]
            macs = [m for m in (r.get("MACAddresses") or []) if m]
            if macs:
                out["mac_addresses"] = macs
        elif r.get("Param") in _LR_PARAMS and r.get("Value") not in (None, ""):
            key = _LR_PARAMS[r["Param"]]
            out[key] = _epoch_utc(r["Value"]) if key == "boot_time_utc" else r["Value"]
        elif "Computer Info" in r or "Network Info" in r:
            for ci in _dicts(r.get("Computer Info")):
                if ci.get("Domain"):
                    out["domain"] = ci["Domain"]
                if ci.get("DomainRole"):
                    out["domain_role"] = ci["DomainRole"]
                if ci.get("TotalPhysicalMemory"):
                    out["memory_bytes"] = ci["TotalPhysicalMemory"]
            # one dict per adapter, or a list of them when the host has several
            for ni in _dicts(r.get("Network Info")):
                name = ni.get("Caption") or ni.get("Name") or f"if{len(interfaces) + 1}"
                ent = {k: v for k, v in (
                    ("ips", ni.get("IPAddresses")), ("subnet", ni.get("IPSubnet")),
                    ("gateway", ni.get("DefaultIPGateway")),
                    ("dns_servers", ni.get("DNSServerSearchOrder")),
                    ("mac", ni.get("MACAddress"))) if v not in (None, "", [])}
                if ent:
                    interfaces.setdefault(str(name), {}).update(ent)
        elif r.get("Name") and ("LastLogin" in r or "Description" in r):
            accounts[str(r["Name"])] = {k: v for k, v in (
                ("description", r.get("Description")), ("last_login", r.get("LastLogin")))
                if v not in (None, "")}
    if interfaces:
        out["interfaces"] = interfaces
    if accounts:
        out["local_accounts"] = accounts
    return out


def _write_csv(path: Path, info: dict) -> None:
    rows: list[tuple[str, str]] = []

    def flat(prefix: str, val) -> None:
        if isinstance(val, dict):
            for k, v in val.items():
                flat(f"{prefix}{k}.", v)
        elif isinstance(val, list):
            rows.append((prefix.rstrip("."), ", ".join(str(x) for x in val)))
        else:
            rows.append((prefix.rstrip("."), "" if val is None else str(val)))

    flat("", info)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["key", "value"])
        w.writerows(rows)


def run(ctx) -> None:
    cfg = ctx.evidence / "Windows" / "System32" / "config"
    info: dict = {"volume": ctx.volume}

    software = _open(cfg / "SOFTWARE")
    system = _open(cfg / "SYSTEM")
    if software:
        info.update(_os_info(software))
        info["users"] = _users(software)
    if system:
        info["machine_name"] = _computer_name(system)
        info.update(_domain(system))
        info["IPs"] = _ips(system)
    # live state is the host's now, not a snapshot's
    if not str(ctx.volume).upper().startswith("VSS"):
        for key, value in _live(_client_info(Path(ctx.evidence))).items():
            info.setdefault(key, value)

    ctx.out.mkdir(parents=True, exist_ok=True)
    (ctx.out / "art_machine_info.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    _write_csv(ctx.out / "art_machine_info.csv", info)
