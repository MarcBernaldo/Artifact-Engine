"""Handler: SSH known_hosts -> outbound lateral-movement map. Output: known_hosts.csv

authorized_keys (lin_ssh) records inbound trust -- who may log into this host.
known_hosts is the other half: the hosts this account has SSH'd *out* to, i.e.
where an operator (or an attacker using these credentials) pivoted from here.
Read per account from ~/.ssh/known_hosts (+ /etc/ssh/ssh_known_hosts).

Entries are emitted as reference for correlation, not flagged: many sites
(this one included) use public IPs internally, so a public-target rule would
fire on legitimate infrastructure. The value is the per-account target list.

Two on-disk forms are handled:
- plaintext: "<host>[,<ip>] <keytype> <key>" -- the target is readable and is
  deduplicated, collapsing the per-keytype duplicate lines.
- hashed (HashKnownHosts): "|1|<salt>|<hash> <keytype> <key>" -- the target is
  not recoverable and each line is salted differently, so these are summarised
  as a single per-account count.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.handlers._lincommon import read_lines, root, write_csv

_MARKERS = ("@cert-authority", "@revoked")


def _accounts(base: Path) -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    home_dir = base / "home"
    if home_dir.is_dir():
        out += [(d.name, d / ".ssh" / "known_hosts") for d in home_dir.iterdir() if d.is_dir()]
    if (base / "root").is_dir():
        out.append(("root", base / "root" / ".ssh" / "known_hosts"))
    out.append(("system", base / "etc" / "ssh" / "ssh_known_hosts"))
    return out


def _parse(lines: list[str]):
    # target -> (set of keytypes, marker); plus a count of hashed entries.
    targets: dict[str, tuple[set, str]] = {}
    hashed: set = set()
    hashed_n = 0
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        p = s.split()
        marker = ""
        if p and p[0] in _MARKERS:
            marker, p = p[0], p[1:]
        if len(p) < 2:
            continue
        hostspec, ktype = p[0], p[1]
        if hostspec.startswith("|1|"):
            hashed_n += 1
            hashed.add(ktype)
            continue
        kt, _ = targets.setdefault(hostspec, (set(), marker))
        kt.add(ktype)
    return targets, hashed, hashed_n


def run(ctx) -> None:
    base = root(ctx.evidence)
    rows: list[list] = []
    for account, kh in _accounts(base):
        targets, hashed, hashed_n = _parse(read_lines(kh))
        for target in sorted(targets):
            ktypes, marker = targets[target]
            rows.append([account, target, ",".join(sorted(ktypes)), marker, ""])
        if hashed_n:
            rows.append([account, "(hashed)", ",".join(sorted(hashed)), f"{hashed_n} entries", ""])
    write_csv(ctx.out, "known_hosts.csv", ["account", "target", "key_types", "note", "suspicious"], rows)
