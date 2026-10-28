"""v0.7.135: art_firewall_rules.csv / art_routes.csv / art_arp_cache.csv from UAC
live_response/network. Synthetic outputs: documentation addresses only."""
from __future__ import annotations

import csv
from pathlib import Path
from types import SimpleNamespace

from artifact_engine.handlers import lin_firewall

FILTER = """\
Chain INPUT (policy DROP 10 packets, 600 bytes)
 pkts bytes target     prot opt in     out     source               destination
  100  6000 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
    5   300            all  --  eth0   *       192.0.2.7            0.0.0.0/0

Chain DOCKER (1 references)
 pkts bytes target     prot opt in     out     source               destination
"""
NAT = """\
Chain PREROUTING (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    1    60 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443 to:198.51.100.9:8443

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    2   120 REDIRECT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 redir ports 3128

Chain DOCKER (2 references)
 pkts bytes target     prot opt in     out     source               destination
    3   180 DNAT       tcp  --  !docker0 *     0.0.0.0/0            0.0.0.0/0            tcp dpt:8080 to:172.17.0.2:80
"""
NFT = """\
table inet filter {
	set blocked {
		type ipv4_addr
		elements = { 203.0.113.1, 203.0.113.2 }
	}
	chain input {
		type filter hook input priority filter; policy drop;
		ip saddr @blocked drop
		tcp dport 22 accept
	}
}
table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		tcp dport 25 dnat to 198.51.100.20:2525
	}
}
"""
ROUTES = """\
default via 192.0.2.1 dev eth0 proto dhcp metric 100
192.0.2.0/24 dev eth0 proto kernel scope link src 192.0.2.10
"""
NEIGH = """\
192.0.2.1 dev eth0 lladdr 00:00:5e:00:53:01 REACHABLE
192.0.2.44 dev eth0 FAILED
"""
ARP_A = """\
? (192.0.2.1) at 00:00:5e:00:53:01 [ether] on eth0
? (192.0.2.55) at <incomplete> on eth0
"""


def _run(tmp_path: Path, files: dict[str, str]) -> Path:
    net = tmp_path / "ev" / "live_response" / "network"
    net.mkdir(parents=True)
    for name, text in files.items():
        (net / name).write_text(text, encoding="utf-8")
    out = tmp_path / "out"
    lin_firewall.run(SimpleNamespace(evidence=tmp_path / "ev", out=out))
    return out


def _read(out: Path, name: str) -> list[dict]:
    with open(out / name, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _all(tmp_path):
    return _run(tmp_path, {"iptables_-L_-v_-n.txt": FILTER, "iptables_-t_nat_-L_-v_-n.txt": NAT,
                           "nft_list_ruleset.txt": NFT, "ip_route_show.txt": ROUTES,
                           "ip_neighbor_show.txt": NEIGH})


def test_iptables_rules_and_policies(tmp_path):
    rules = [r for r in _read(_all(tmp_path), "art_firewall_rules.csv") if r["tool"] == "iptables"]
    policy = next(r for r in rules if r["chain"] == "INPUT" and r["extra"] == "chain policy")
    assert policy["target"] == "DROP"
    ssh = next(r for r in rules if r["extra"] == "tcp dpt:22")
    assert (ssh["target"], ssh["proto"], ssh["packets"]) == ("ACCEPT", "tcp", "100")
    counter = next(r for r in rules if r["source"] == "192.0.2.7")
    assert counter["target"] == "" and counter["in"] == "eth0"     # a rule with no -j


def test_a_redirect_outside_runtime_chains_is_flagged(tmp_path):
    rules = _read(_all(tmp_path), "art_firewall_rules.csv")
    dnat = next(r for r in rules if r["tool"] == "iptables" and r["chain"] == "PREROUTING"
                and r["target"] == "DNAT")
    assert dnat["suspicious"] == "yes" and "incoming" in dnat["note"]
    redirect = next(r for r in rules if r["target"] == "REDIRECT")
    assert redirect["suspicious"] == "yes" and "outbound" in redirect["note"]
    docker = next(r for r in rules if r["chain"] == "DOCKER" and r["target"] == "DNAT")
    assert docker["suspicious"] == ""


def test_nft_rules_verdicts_and_sets(tmp_path):
    rules = [r for r in _read(_all(tmp_path), "art_firewall_rules.csv") if r["tool"] == "nft"]
    assert {(r["table"], r["chain"], r["target"]) for r in rules} == {
        ("inet filter", "input", "DROP"), ("inet filter", "input", "ACCEPT"),
        ("ip nat", "prerouting", "ACCEPT"), ("ip nat", "prerouting", "DNAT")}
    assert len(rules) == 5
    assert not any("elements" in r["extra"] for r in rules)          # a set is not a rule
    dnat = next(r for r in rules if r["target"] == "DNAT")
    assert dnat["suspicious"] == "yes"


def test_routes(tmp_path):
    routes = _read(_all(tmp_path), "art_routes.csv")
    assert routes[0] == {"destination": "default", "gateway": "192.0.2.1", "device": "eth0",
                         "proto": "dhcp", "scope": "", "src": "", "metric": "100"}
    assert routes[1]["src"] == "192.0.2.10" and routes[1]["scope"] == "link"


def test_neighbours_keep_failed_entries(tmp_path):
    arp = _read(_all(tmp_path), "art_arp_cache.csv")
    assert arp == [{"ip": "192.0.2.1", "mac": "00:00:5e:00:53:01", "device": "eth0",
                    "state": "REACHABLE"},
                   {"ip": "192.0.2.44", "mac": "", "device": "eth0", "state": "FAILED"}]


def test_arp_a_when_there_is_no_ip_neighbor(tmp_path):
    arp = _read(_run(tmp_path, {"arp_-a.txt": ARP_A}), "art_arp_cache.csv")
    assert [(r["ip"], r["mac"], r["state"]) for r in arp] == [
        ("192.0.2.1", "00:00:5e:00:53:01", ""), ("192.0.2.55", "", "INCOMPLETE")]
