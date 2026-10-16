"""Shared reading of auditd's audit.log, for `auditd_events` and `sigma`.

A record is `type=X msg=audit(<epoch>:<serial>): key=value ...`. Records with the
same serial (in one file) are one event: a SYSCALL and its PROCTITLE, EXECVE, CWD
and PATH records. Values may be quoted, or hex when they hold spaces or
non-printable bytes. RHEL 8+ (`log_format = ENRICHED`) appends a `\\x1d` and the
same ids resolved to names in UPPERCASE keys (`AUID="jdoe"`).
"""

from __future__ import annotations

import re

# auditd record: "type=X msg=audit(<ts>:<serial>): <rest>"
AUDIT = re.compile(r"^type=(\S+)\s+msg=audit\(([\d.]+):(\d+)\):\s*(.*)$")
_KV = re.compile(r"(\w+)=(?:\"([^\"]*)\"|'([^']*)'|(\S+))")
_HEX = re.compile(r"^[0-9A-Fa-f]+$")

# x86-64 syscall numbers -> names (the security-relevant subset Sigma rules use).
SYSCALLS = {
    "0": "read", "1": "write", "2": "open", "41": "socket", "42": "connect",
    "43": "accept", "49": "bind", "56": "clone", "57": "fork", "58": "vfork",
    "59": "execve", "62": "kill", "82": "rename", "84": "rmdir", "86": "link",
    "87": "unlink", "90": "chmod", "92": "chown", "101": "ptrace", "105": "setuid",
    "106": "setgid", "155": "pivot_root", "165": "mount", "166": "umount2",
    "175": "init_module", "176": "delete_module", "200": "tkill",
    "279": "memfd_create", "319": "memfd_create", "322": "execveat",
}


def unhex(v: str) -> str:
    """Decode an auditd hex-encoded argument; return as-is if not hex."""
    if len(v) >= 2 and len(v) % 2 == 0 and _HEX.match(v):
        try:
            return bytes.fromhex(v).decode("utf-8", "replace")
        except ValueError:
            return v
    return v


def kv(rest: str) -> dict:
    d = {}
    for m in _KV.finditer(rest):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
        d[key] = val
    return d
