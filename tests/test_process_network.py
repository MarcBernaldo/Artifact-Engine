"""process_network: one row per socket with its process, the same from every source.

All values are synthetic (documentation addresses, invented names)."""

import csv
import json
import logging
from pathlib import Path

from artifact_engine.core import netclass
from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import _procnet

PUBLIC = "45.66.0.11"


def _ctx(evidence: Path, out: Path, internal=()) -> ParserContext:
    return ParserContext(evidence=evidence, out=out, tools=evidence, assets=evidence,
                         machine_name="HOST-01", volume="live",
                         log=logging.getLogger("aeng.test"), internal_networks=internal)


def _read(out: Path) -> list[dict]:
    with open(out / _procnet.TABLE, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_rows_join_parent_and_rank_public_first():
    procs = {10: {"process": "parent.exe", "cmdline": "parent.exe -x"},
             20: {"process": "child.exe", "ppid": 10, "path": "C:\\t\\child.exe"}}
    conns = [{"pid": 20, "proto": "tcp", "state": "LISTEN", "local_addr": "0.0.0.0",
              "local_port": 80, "remote_addr": "0.0.0.0", "remote_port": 0},
             {"pid": 20, "proto": "tcp", "state": "ESTABLISHED", "remote_addr": PUBLIC,
              "remote_port": 443},
             {"pid": 99, "owner": "gone.exe", "proto": "tcp", "remote_addr": "10.0.0.5"},
             {"pid": 20, "proto": "tcp", "remote_addr": "10.1.2.3"}]
    nc = netclass.parse(["10.1.0.0/16"])
    rows = [dict(zip(_procnet.HEADER, r)) for r in _procnet.rows(procs, conns, "t", nc)]
    assert [r["remote_scope"] for r in rows] == ["public", "internal", "private", ""]
    top = rows[0]
    assert (top["pid"], top["process"], top["parent"], top["parent_cmdline"]) == \
        ("20", "child.exe", "parent.exe", "parent.exe -x")
    # a socket whose owner is in no process table is kept
    orphan = next(r for r in rows if r["pid"] == "99")
    # named by the socket table itself, the rest unknown
    assert (orphan["process"], orphan["path"], orphan["remote_scope"]) ==         ("gone.exe", "", "private")


def _write_lr(results: Path, artifact: str, records: list[dict]) -> None:
    results.mkdir(parents=True, exist_ok=True)
    f = results / f"Eiffel.LiveResponse.Windows%2F{artifact}.json"
    f.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")


def test_velociraptor(tmp_path):
    from artifact_engine.handlers import win_process_network as W
    res = tmp_path / "Velociraptor" / "LiveResponse" / "results"
    _write_lr(res, "Windows.System.Pslist", [
        {"Pid": 400, "Ppid": 4, "Name": "svchost.exe", "CommandLine": "svchost -k x"},
        {"Pid": 1000, "Ppid": 400, "Name": "p.exe", "Exe": "C:\\Users\\Public\\p.exe",
         "CommandLine": "p.exe -c", "Username": "EXAMPLE\\jdoe",
         "CreateTime": "2024-01-02T03:04:05Z",
         "Hash": {"MD5": "m" * 32, "SHA1": "s" * 40, "SHA256": "a" * 64}}])
    _write_lr(res, "Windows.Network.Netstat", [
        {"Pid": 1000, "Family": "IPv4", "Type": "TCP", "Status": "ESTAB",
         "Laddr.IP": "10.0.0.5", "Laddr.Port": 50000, "Raddr.IP": PUBLIC, "Raddr.Port": 443},
        {"Pid": 400, "Family": "IPv6", "Type": "UDP", "Status": "",
         "Laddr.IP": "::", "Laddr.Port": 53, "Raddr.IP": "::", "Raddr.Port": 0}])
    out = tmp_path / "out"
    W.run(_ctx(tmp_path, out))
    rows = _read(out)
    assert [(r["pid"], r["proto"]) for r in rows] == [("1000", "tcp"), ("400", "udp6")]
    r = rows[0]
    assert (r["process"], r["user"], r["sha256"], r["started_utc"], r["parent"],
            r["parent_cmdline"], r["remote_scope"], r["source"]) == \
        ("p.exe", "EXAMPLE\\jdoe", "a" * 64, "2024-01-02T03:04:05Z", "svchost.exe",
         "svchost -k x", "public", "velociraptor/netstat")


def test_uac(tmp_path):
    from artifact_engine.handlers import lin_process_network as L
    lr = tmp_path / "live_response"
    (lr / "network").mkdir(parents=True)
    proc = lr / "process"
    (proc / "proc" / "42").mkdir(parents=True)
    (proc / "proc" / "1").mkdir(parents=True)
    (lr / "network" / "ss_-tanp.txt").write_text(
        "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
        f'ESTAB  0 0 10.0.0.5:40000 {PUBLIC}:443 users:(("curl",pid=42,fd=3),("sh",pid=1,fd=4))\n'
        'LISTEN 0 5 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=77,fd=3))\n'
        'LISTEN 0 5 0.0.0.0:8080 0.0.0.0:* users:(("srv",pid=88,fd=3),("wrk",pid=89,fd=3))\n',
        encoding="utf-8")
    (proc / "ps_-axo_pid_user_lstart_args.txt").write_text(
        "  PID USER STARTED COMMAND\n"
        "    1 root Tue May 26 16:07:00 2026 /sbin/init\n"
        f"   42 jdoe Tue May 26 16:08:00 2026 curl -s https://{PUBLIC}/x\n", encoding="utf-8")
    (proc / "proc" / "42" / "status.txt").write_text("Name:\tcurl\nPPid:\t1\n", encoding="utf-8")
    (proc / "proc" / "1" / "status.txt").write_text("Name:\tsystemd\nPPid:\t0\n",
                                                    encoding="utf-8")
    (proc / "running_processes_full_paths.txt").write_text(
        "lrwxrwxrwx 1 jdoe jdoe 0 May 26 16:08 /proc/42/exe -> /usr/bin/curl\n",
        encoding="utf-8")
    (tmp_path / "hash_executables").mkdir()
    (tmp_path / "hash_executables" / "hash_executables.md5").write_text(
        f"{'d' * 32}  /usr/bin/curl\n", encoding="utf-8")
    out = tmp_path / "out"
    L.run(_ctx(tmp_path, out))
    rows = _read(out)
    # one socket held by two processes: one row each
    assert sorted(r["pid"] for r in rows) == ["1", "42", "77", "88", "89"]
    named = {r["pid"]: r["process"] for r in rows}
    # not in `ps`: the socket's one owner is named by `ss`; a shared socket's
    # single name belongs to only one of its processes, so neither gets it
    assert (named["77"], named["88"], named["89"]) == ("nc", "", "")
    r = next(x for x in rows if x["pid"] == "42")
    assert (r["process"], r["user"], r["path"], r["md5"], r["started_local"], r["parent"],
            r["remote_scope"], r["source"]) == \
        ("curl", "jdoe", "/usr/bin/curl", "d" * 32, "Tue May 26 16:08:00 2026", "systemd",
         "public", "uac/ss")


def test_memory(tmp_path):
    from artifact_engine.handlers import mem_process_network as M
    mem = tmp_path / "HOST-01_memory" / "CSVs" / "Memory"
    mem.mkdir(parents=True)

    def table(name, header, rows):
        with open(mem / f"{name}.csv", "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)

    t0 = "2024-01-02 03:04:05.000000 UTC"
    table("mem_pslist", ["TreeDepth", "PID", "PPID", "ImageFileName", "Offset(V)", "Threads",
                         "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime"],
          [[0, 600, 4, "svchost.exe", "0x1", 1, 1, 0, "False", t0, "N/A"],
           [0, 700, 600, "beacon.exe", "0x2", 1, 1, 1, "False", t0, "N/A"]])
    table("mem_cmdline", ["TreeDepth", "PID", "Process", "Args"],
          [[0, 700, "beacon.exe", "beacon.exe --quiet"]])
    table("mem_netscan", ["TreeDepth", "Offset", "Proto", "LocalAddr", "LocalPort",
                          "ForeignAddr", "ForeignPort", "State", "PID", "Owner", "Created"],
          [[0, "0x9", "TCPv4", "10.0.0.5", 50000, PUBLIC, 443, "ESTABLISHED", 700,
            "beacon.exe", t0],
           [0, "0xa", "UDPv6", "::", 500, "*", 0, "", 600, "svchost.exe", t0]])
    out = tmp_path / "out"
    M.run(_ctx(tmp_path / "HOST-01_memory", out))
    rows = _read(out)
    assert [(r["pid"], r["proto"]) for r in rows] == [("700", "tcp"), ("600", "udp6")]
    r = rows[0]
    assert (r["process"], r["cmdline"], r["parent"], r["started_utc"], r["remote_scope"],
            r["source"]) == ("beacon.exe", "beacon.exe --quiet", "svchost.exe", t0, "public",
                             "memory/netscan")
    assert rows[1]["remote_scope"] == ""            # a listener has no peer


def test_one_table_name_and_header_everywhere():
    """The point of the table: the same name and columns from every source."""
    import yaml

    from artifact_engine.config import DATA_DIR
    ids = {}
    for f in (DATA_DIR / "parsers").rglob("*.yaml"):
        m = yaml.safe_load(f.read_text(encoding="utf-8"))
        if "process_network_csv" in (m.get("provides") or []):
            ids[m["id"]] = m["handler"]
    assert sorted(ids) == ["lr_process_network", "mem_process_network", "process_network"]
    for handler in ids.values():
        src = (Path(__file__).resolve().parents[1] / "src" / "artifact_engine" / "handlers"
               / (handler.split(":")[0].rsplit(".", 1)[1] + ".py")).read_text(encoding="utf-8")
        assert "_procnet.TABLE, _procnet.HEADER" in src
