"""Handler: machine information from the hives (SYSTEM/SOFTWARE).

Extracts hostname, OS version, IPs and users and writes them to machine_info.json
(+ .csv) to enrich the report and the consolidation. Tolerates missing or corrupt
hives (each section runs in its own try).
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from Registry.Registry import Registry

_CONTROL_SETS = ("ControlSet001", "ControlSet002", "CurrentControlSet")


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

    ctx.out.mkdir(parents=True, exist_ok=True)
    (ctx.out / "machine_info.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    _write_csv(ctx.out / "machine_info.csv", info)
