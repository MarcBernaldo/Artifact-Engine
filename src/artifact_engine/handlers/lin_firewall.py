"""Handler: firewall rules, routes and the neighbour cache of a Linux host.
Outputs: firewall_rules.csv, routes.csv, arp_cache.csv

`process_network` reads sockets (ss/netstat) -- what was connected. This reads the
rules that decided what COULD connect, where traffic was sent, and which hosts
this one had just talked to at layer 2 (backlog §41). Sources, all from UAC
`live_response/network`: `iptables -L -v -n` and its `-t nat` twin,
`nft list ruleset`, `ip route show`, `ip neighbor show` (or `arp -a`).

Flagged: a rule that REDIRECTS traffic -- DNAT, REDIRECT or TPROXY -- in a
chain the host's own administrator wrote. Container runtimes and Kubernetes
write hundreds of DNAT rules into chains of their own (DOCKER, KUBE-*, CNI-*,
NETAVARK*...); those are plumbing, kept as rows and not flagged, or every
container host would drown in its own port mappings. Nothing else is flagged:
whether an ACCEPT of an inbound port is odd depends on what the host is for,
which a rule cannot say.

The neighbour cache is the one place a host lists the machines it reached at
layer 2 without any of them writing a log line -- lateral candidates the logon
graph has no other way to see. STALE and FAILED entries are kept: a FAILED one
is an address this host TRIED to reach.
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

RULE_HEADER = ["tool", "table", "chain", "target", "proto", "in", "out", "source",
               "destination", "extra", "packets", "bytes", "suspicious", "note"]
ROUTE_HEADER = ["destination", "gateway", "device", "proto", "scope", "src", "metric"]
ARP_HEADER = ["ip", "mac", "device", "state"]

# Chains a container runtime, an orchestrator or a ban tool writes on its own.
_RUNTIME_CHAIN = re.compile(
    r"^(DOCKER|KUBE-|CNI-|NETAVARK|cali-|FLANNEL|CILIUM|LIBVIRT|f2b-|PODMAN|K3S|"
    r"WEAVE|ISTIO|LXD|sshguard)", re.IGNORECASE)
_REDIRECT = {"DNAT", "REDIRECT", "TPROXY"}
_CHAIN = re.compile(r"^Chain (?P<name>\S+)(?: \(policy (?P<policy>\S+))?")
_OPTS = {"--", "-f", "!f"}


def _flag(chain: str, target: str) -> tuple[str, str]:
    """(suspicious, note) for one rule."""
    if target.upper() in _REDIRECT and not _RUNTIME_CHAIN.match(chain):
        where = "outbound" if chain.upper() == "OUTPUT" else "incoming"
        return "yes", f"redirects {where} traffic ({target.upper()}) outside any runtime's chains"
    return "", ""


def _iptables(path: Path, table: str) -> list[list]:
    rows: list[list] = []
    chain = ""
    for raw in read_lines(path):
        line = raw.strip()
        if not line:
            continue
        m = _CHAIN.match(line)
        if m:
            chain = m["name"]
            if m["policy"]:
                rows.append(["iptables", table, chain, m["policy"], "", "", "", "", "",
                             "chain policy", "", "", "", ""])
            continue
        if line.startswith("pkts ") or not chain:
            continue
        parts = line.split()
        # pkts bytes target prot opt in out source destination [extra...]; a rule
        # with no -j has no target column, so everything after `bytes` shifts left.
        if len(parts) >= 9 and parts[4] in _OPTS:
            target, cols = parts[2], parts[3:]
        elif len(parts) >= 8 and parts[3] in _OPTS:
            target, cols = "", parts[2:]
        else:
            continue
        proto, _opt, i, o, src, dst = cols[:6]
        suspicious, note = _flag(chain, target)
        rows.append(["iptables", table, chain, target, proto, i, o, src, dst,
                     " ".join(cols[6:]), parts[0], parts[1], suspicious, note])
    return rows


_NFT_VERDICT = re.compile(
    r"\b(accept|drop|reject|queue|continue|return|masquerade|"
    r"(?:dnat|snat|redirect|tproxy)\b[^;]*|(?:jump|goto)\s+\S+)\s*;?\s*$")


def _nft(path: Path) -> list[list]:
    """`nft list ruleset`: `table <family> <name> {`, `chain <name> {`, one
    statement per line. The verdict is the rule's last word; the whole rule is
    kept in `extra`, since nft's grammar is too open to split into columns."""
    rows: list[list] = []
    table = chain = ""
    depth = 0           # inside a set/map/flowtable block: not rules
    for raw in read_lines(path):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if depth:
            depth += line.count("{") - line.count("}")
            continue
        if table and not chain and line.endswith("{") and not line.startswith("chain "):
            depth = 1
            continue
        if line.startswith("table "):
            table, chain = " ".join(line.split()[1:3]).rstrip("{").strip(), ""
            continue
        if line.startswith("chain "):
            chain = line.split()[1]
            continue
        if line == "}":
            if chain:
                chain = ""
            else:
                table = ""
            continue
        if not chain:
            continue
        if line.startswith("type ") and "policy" in line:
            policy = line.split("policy", 1)[1].strip(" ;").upper()   # as iptables
            rows.append(["nft", table, chain, policy, "", "", "", "", "",
                         "chain policy: " + line.rstrip(";"), "", "", "", ""])
            continue
        m = _NFT_VERDICT.search(line)
        target = m.group(1).split()[0].upper() if m else ""
        suspicious, note = _flag(chain, target)
        rows.append(["nft", table, chain, target, "", "", "", "", "", line, "", "", suspicious,
                     note])
    return rows


def _routes(path: Path) -> list[list]:
    """`ip route show`: `<dst> [via <gw>] dev <dev> [proto x] [scope y] [src z]
    [metric n]` -- keyword/value pairs after the destination."""
    rows = []
    for raw in read_lines(path):
        parts = raw.split()
        if not parts:
            continue
        kv = {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1)
              if parts[i] in ("via", "dev", "proto", "scope", "src", "metric")}
        rows.append([parts[0], kv.get("via", ""), kv.get("dev", ""), kv.get("proto", ""),
                     kv.get("scope", ""), kv.get("src", ""), kv.get("metric", "")])
    return rows


_ARP_A = re.compile(r"^\S+ \((?P<ip>[^)]+)\) at (?P<mac>\S+)(?: \[\w+\])?(?: on (?P<dev>\S+))?")


def _neighbours(lr: Path) -> list[list]:
    rows = []
    for raw in read_lines(lr / "network" / "ip_neighbor_show.txt"):
        parts = raw.split()
        if not parts:
            continue
        kv = {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1)
              if parts[i] in ("dev", "lladdr")}
        state = parts[-1] if parts[-1].isupper() else ""
        rows.append([parts[0], kv.get("lladdr", ""), kv.get("dev", ""), state])
    if rows:
        return rows
    for raw in read_lines(lr / "network" / "arp_-a.txt"):     # older hosts: net-tools
        m = _ARP_A.match(raw.strip())
        if m:
            mac = m["mac"] if ":" in m["mac"] else ""        # `<incomplete>`
            rows.append([m["ip"], mac, m["dev"] or "", "" if mac else "INCOMPLETE"])
    return rows


def run(ctx) -> None:
    lr = live_response(Path(ctx.evidence))
    if lr is None:
        return
    net = lr / "network"
    rules = (_iptables(net / "iptables_-L_-v_-n.txt", "filter")
             + _iptables(net / "iptables_-t_nat_-L_-v_-n.txt", "nat")
             + _nft(net / "nft_list_ruleset.txt"))
    write_csv(ctx.out, "firewall_rules.csv", RULE_HEADER, rules)
    write_csv(ctx.out, "routes.csv", ROUTE_HEADER, _routes(net / "ip_route_show.txt"))
    write_csv(ctx.out, "arp_cache.csv", ARP_HEADER, _neighbours(lr))
