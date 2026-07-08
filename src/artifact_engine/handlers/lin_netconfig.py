"""Handler: host/DNS/network access config. Output: netconfig.csv

Surfaces tampering of name resolution and TCP-wrapper access control (SANS
Linux hunt 'Networking'):
- /etc/hosts          : static name->IP overrides. Flags sinkholes (0.0.0.0 /
                        127.* mapping of a real FQDN) and FQDN redirects to a
                        public IP -- the classic update/AV-domain hijack.
- /etc/resolv.conf    : DNS servers / search domains (listed; rogue resolver).
- /etc/hosts.allow    : TCP-wrapper allow rules. Flags blanket 'ALL: ALL'.
- /etc/hosts.deny     : TCP-wrapper deny rules (listed).
"""

from __future__ import annotations

import re

from artifact_engine.handlers._lincommon import read_lines, root, write_csv

_LOOPBACK = re.compile(r"^(127\.|::1$|0\.0\.0\.0$|::$)")
_FQDN = re.compile(r"[a-zA-Z]")   # a name with letters (not a bare reverse PTR)
# Update / AV / OS-repo domains an attacker hijacks via /etc/hosts (block or
# redirect). A static hosts entry for any of these is almost always tampering.
_SENSITIVE = re.compile(
    r"\b(update|security|repo|mirror|archive)\.|"
    r"\.(ubuntu|debian|centos|redhat|microsoft|windowsupdate|clamav|sophos)\.|"
    r"defender|crowdstrike|mcafee|kaspersky|sentinelone|virustotal", re.I)


def _is_localhost(name: str) -> bool:
    n = name.lower()
    return n.startswith(("localhost", "ip6-")) or "localdomain" in n


def _hosts(rows: list[list], lines: list[str]) -> None:
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        ip, names = parts[0], parts[1:]
        # Real external hostnames (have a dot + letters, not localhost-family).
        fqdns = [n for n in names if "." in n and _FQDN.search(n) and not _is_localhost(n)]
        susp = ""
        if fqdns and _LOOPBACK.match(ip):
            susp = "yes"                         # sinkhole: blocking a real domain
        elif any(_SENSITIVE.search(n) for n in fqdns):
            susp = "yes"                         # hijack of an update/AV/repo domain
        rows.append(["hosts", s, susp])


def run(ctx) -> None:
    base = root(ctx.evidence)
    rows: list[list] = []

    _hosts(rows, read_lines(base / "etc" / "hosts"))

    for ln in read_lines(base / "etc" / "resolv.conf"):
        s = ln.strip()
        if s and not s.startswith("#"):
            rows.append(["resolv.conf", s, ""])

    for ln in read_lines(base / "etc" / "hosts.allow"):
        s = ln.strip()
        if s and not s.startswith("#"):
            susp = "yes" if re.match(r"ALL\s*:\s*ALL\b", s, re.I) else ""
            rows.append(["hosts.allow", s, susp])

    for ln in read_lines(base / "etc" / "hosts.deny"):
        s = ln.strip()
        if s and not s.startswith("#"):
            rows.append(["hosts.deny", s, ""])

    rows.sort(key=lambda r: (r[2] != "yes", r[0]))
    write_csv(ctx.out, "netconfig.csv", ["file", "entry", "suspicious"], rows)
