"""Handler: software install/remove timeline. Output: pkg_history.csv

Reconstructs WHEN packages were installed/removed/upgraded across the supported
package managers so software changes can be lined up against the incident
window (attacker tooling, or a malicious .deb/.rpm dropped directly). Sources:
  - apt/history.log (+ .gz)  : Debian/Ubuntu transactions (commandline/actor)
  - dpkg.log (+ rotations)   : per-package actions, incl. direct `dpkg -i`
  - zypp/history             : SUSE (pipe-delimited)
  - dnf.rpm.log / yum.log    : RHEL/CentOS/Fedora

The `suspicious` column flags offensive/recon/tunnelling tools rarely present
on a clean server (nmap, socat, chisel, sqlmap, ...). It does not assert
maliciousness. Rows are chronological.
"""

from __future__ import annotations

import re

from artifact_engine.handlers._lincommon import iter_log_lines, root, write_csv

# Offensive / recon / tunnelling tooling -- notable when installed on a server.
_HACK = re.compile(
    r"(?<![a-z0-9])("
    r"nmap|masscan|zmap|rustscan|netcat|ncat|socat|hydra|medusa|john|hashcat|"
    r"hping3?|ettercap|bettercap|responder|proxychains(?:-ng)?|torsocks|tor|"
    r"chisel|frpc?|frps|sshuttle|sliver|nikto|sqlmap|gobuster|dirbuster|ffuf|"
    r"wfuzz|crackmapexec|impacket|metasploit|nuclei|enum4linux|smbmap|"
    r"evil-winrm|kerbrute|mimipenguin|linpeas|pspy|aircrack-?ng"
    r")(?![a-z])", re.I)


def _flag(pkg: str) -> str:
    return "yes" if _HACK.search(pkg) else ""


def _files(d, stem: str):
    if not d.is_dir():
        return []
    return sorted(f for f in d.iterdir() if f.is_file() and f.name.startswith(stem))


def _lines(files) -> list[str]:
    out: list[str] = []
    for f in files:
        out.extend(iter_log_lines(f))   # transparent .gz/.xz
    return out


_APT_ACTIONS = ("Install", "Reinstall", "Upgrade", "Downgrade", "Remove", "Purge")
_PKG_RE = re.compile(r"([^\s,]+) \(([^)]*)\)")


def _parse_apt(lines, rows) -> None:
    block: dict[str, str] = {}

    def flush():
        if not block:
            return
        t = block.get("Start-Date", "").replace("  ", " ")
        actor = block.get("Requested-By") or block.get("Commandline", "")
        for act in _APT_ACTIONS:
            if act in block:
                for name_arch, ver in _PKG_RE.findall(block[act]):
                    name = name_arch.split(":")[0]
                    rows.append([t, act.lower(), name, ver, actor, "apt_history", _flag(name)])

    for ln in lines:
        if not ln.strip():
            flush()
            block = {}
        elif ":" in ln:
            k, _, v = ln.partition(":")
            block[k.strip()] = v.strip()
    flush()


_DPKG_ACTS = {"install", "remove", "purge", "upgrade", "downgrade"}


def _parse_dpkg(lines, rows) -> None:
    for ln in lines:
        p = ln.split()
        if len(p) < 5 or p[2] not in _DPKG_ACTS:
            continue
        pkg = p[3].split(":")[0]
        ver = p[5] if len(p) > 5 and p[5] != "<none>" else p[4]
        rows.append([f"{p[0]} {p[1]}", p[2], pkg, "" if ver == "<none>" else ver,
                     "", "dpkg", _flag(pkg)])


def _parse_zypp(lines, rows) -> None:
    for ln in lines:
        if "|" not in ln:
            continue
        p = ln.split("|")
        if len(p) < 4 or p[1].strip() not in ("install", "remove"):
            continue
        actor = p[5].strip() if len(p) > 5 else ""
        rows.append([p[0].strip(), p[1].strip(), p[2].strip(), p[3].strip(),
                     actor, "zypp", _flag(p[2])])


_DNF_RE = re.compile(r"^(\S+)\s+SUBDEBUG\s+(\w+):\s+(.+)$")
_DNF_MAP = {"Installed": "install", "Erased": "remove", "Upgraded": "upgrade",
            "Downgraded": "downgrade", "Obsoleted": "obsolete", "Reinstalled": "reinstall"}


def _parse_dnf(lines, rows) -> None:
    for ln in lines:
        m = _DNF_RE.match(ln)
        if not m:
            continue
        act = _DNF_MAP.get(m.group(2))
        if act:
            nvra = m.group(3).strip()
            rows.append([m.group(1), act, nvra, "", "", "dnf_rpm", _flag(nvra)])


_YUM_RE = re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\w+):\s+(.+)$")


def _parse_yum(lines, rows) -> None:
    for ln in lines:
        m = _YUM_RE.match(ln)
        if m and m.group(2) in ("Installed", "Erased", "Updated"):
            act = {"Installed": "install", "Erased": "remove", "Updated": "upgrade"}[m.group(2)]
            rows.append([m.group(1), act, m.group(3).strip(), "", "", "yum", _flag(m.group(3))])


def run(ctx) -> None:
    base = root(ctx.evidence)
    log = base / "var" / "log"
    rows: list[list] = []
    _parse_apt(_lines(_files(log / "apt", "history.log")), rows)
    _parse_dpkg(_lines(_files(log, "dpkg.log")), rows)
    _parse_zypp(_lines(_files(log / "zypp", "history")), rows)
    _parse_dnf(_lines(_files(log, "dnf.rpm.log")), rows)
    _parse_yum(_lines(_files(log, "yum.log")), rows)
    rows.sort(key=lambda r: r[0])
    write_csv(ctx.out, "pkg_history.csv",
              ["time_local", "action", "package", "version", "actor", "source", "suspicious"], rows)
