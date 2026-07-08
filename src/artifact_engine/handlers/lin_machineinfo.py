"""Handler: machine identity for Linux/UAC. Builds machine_info.json (same keys
the report reader expects, so report.txt is enriched for Linux too) plus a flat
machineinfo.csv. Sources: hostnamectl, /etc/os-release, ip addr, /etc/passwd.
"""

from __future__ import annotations

import json
import re

from artifact_engine.handlers._lincommon import live_response, read_lines, read_text, root, write_csv

_IP_RE = re.compile(r"inet6?\s+([0-9a-fA-F:.]+)")
# Shells that mean "no interactive login" -> not a real user account.
_NOLOGIN = ("nologin", "/false", "/sync", "/shutdown", "/halt")


def _hostnamectl(lr) -> dict:
    info = {}
    if not lr:
        return info
    for ln in read_lines(lr / "network" / "hostnamectl.txt"):
        k, sep, v = ln.partition(":")
        if sep:
            info[k.strip()] = v.strip()
    return info


def _ips(lr) -> list[str]:
    ips: list[str] = []
    if not lr:
        return ips
    for fname in ("ip_addr_show.txt", "ifconfig_-a.txt"):
        for ln in read_lines(lr / "network" / fname):
            for ip in _IP_RE.findall(ln):
                base = ip.split("/")[0]
                # drop loopback and IPv6 link-local (not useful for attribution)
                if base in ("127.0.0.1", "::1") or base.lower().startswith("fe80"):
                    continue
                if base not in ips:
                    ips.append(base)
        if ips:
            break
    return ips


def _users(base) -> list[str]:
    users: list[str] = []
    for ln in read_lines(base / "etc" / "passwd"):
        p = ln.split(":")
        if len(p) < 7 or not p[0] or p[0][0] in "+-":  # skip blank / NIS (+/-) entries
            continue
        if not any(p[6].endswith(s) or s in p[6] for s in _NOLOGIN):
            users.append(p[0])
    return sorted(set(users))


def _kv(lr, rel: str) -> dict:
    """Parse a 'Key:  Value' command-output file into a dict."""
    out = {}
    if not lr:
        return out
    for ln in read_lines(lr / rel):
        k, sep, v = ln.partition(":")
        if sep:
            out[k.strip()] = v.strip()
    return out


def _timezone(lr, base) -> str:
    tz = read_text(base / "etc" / "timezone").strip()
    if tz:
        return tz
    # fall back to the abbreviation in `date` output: "Tue May 26 16:12:19 CEST 2026"
    parts = read_text(lr / "system" / "date.txt").split() if lr else []
    return parts[-2] if len(parts) >= 2 else ""


def _memory(lr) -> str:
    for ln in read_lines(lr / "system" / "free.txt") if lr else []:
        if ln.startswith("Mem:"):
            kb = ln.split()
            if len(kb) >= 2 and kb[1].isdigit():
                return f"{int(kb[1]) / 1024 / 1024:.1f} GiB"
    return ""


def _boot_time(lr) -> str:
    for ln in read_lines(lr / "system" / "last.txt") if lr else []:
        if ln.startswith("reboot"):
            m = re.search(r"([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2})", ln)
            return m.group(1) if m else ""
    return ""


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    base = root(ctx.evidence)
    hc = _hostnamectl(lr)

    os_rel = {}
    for ln in read_lines(base / "etc" / "os-release"):
        k, sep, v = ln.partition("=")
        if sep:
            os_rel[k.strip()] = v.strip().strip('"')

    hostname = (hc.get("Static hostname")
                or read_text(base / "etc" / "hostname").strip()
                or ctx.evidence.name)
    lscpu = _kv(lr, "hardware/lscpu.txt")
    info = {
        "machine_name": hostname,
        "product_name": hc.get("Operating System") or os_rel.get("PRETTY_NAME", ""),
        "build": hc.get("Kernel", ""),
        "machine_id": hc.get("Machine ID", ""),
        "timezone": _timezone(lr, base),
        "boot_time": _boot_time(lr),
        "virtualization": hc.get("Virtualization", ""),
        "architecture": hc.get("Architecture", ""),
        "cpu": lscpu.get("Model name", ""),
        "cpu_count": lscpu.get("CPU(s)", ""),
        "memory": _memory(lr),
        "hardware": " ".join(x for x in (hc.get("Hardware Vendor"), hc.get("Hardware Model")) if x),
        "IPs": _ips(lr),
        "users": _users(base),
    }
    rows = [[k, ", ".join(v) if isinstance(v, list) else v] for k, v in info.items()]
    write_csv(ctx.out, "machineinfo.csv", ["field", "value"], rows)  # creates ctx.out

    with open(ctx.out / "machine_info.json", "w", encoding="utf-8") as fh:
        json.dump(info, fh, ensure_ascii=False, indent=2)
