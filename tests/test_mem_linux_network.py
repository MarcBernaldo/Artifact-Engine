"""process_network from a Linux memory image (v0.7.116). Tables synthesised;
names and addresses invented."""
from __future__ import annotations

import csv
import logging
from pathlib import Path

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.handlers import _procnet
from artifact_engine.handlers import mem_linux_network as N
from artifact_engine.registry import load_parsers

_HEADERS = {
    "pslist": ["TreeDepth", "OFFSET (V)", "PID", "TID", "PPID", "COMM", "UID", "GID", "EUID",
               "EGID", "CREATION TIME", "File output"],
    "psaux": ["TreeDepth", "PID", "PPID", "COMM", "ARGS"],
    "process_spoofing": ["TreeDepth", "PID", "PPID", "Exe_Path", "Cmdline_Basename", "Comm",
                         "Cmdline_Spoofed", "Comm_Spoofed", "Exe_Deleted"],
    "sockstat": ["TreeDepth", "NetNS", "Process Name", "PID", "TID", "FD", "Sock Offset",
                 "Family", "Type", "Proto", "Source Addr", "Source Port", "Destination Addr",
                 "Destination Port", "State", "Filter"],
}


def _write(unit: Path, table: str, rows: list[dict]) -> None:
    d = unit / "CSVs" / "Memory"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / f"linmem_{table}.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_HEADERS[table], restval="-")
        w.writeheader()
        for r in rows:
            w.writerow({"TreeDepth": 0, **r})


def _sock(pid, tid, fd, family="AF_INET", proto="TCP", dst="8.8.8.8", state="ESTABLISHED",
          offset="0xaa", name="agent"):
    return {"Process Name": name, "PID": pid, "TID": tid, "FD": fd, "Sock Offset": offset,
            "Family": family, "Proto": proto, "Source Addr": "10.0.0.5", "Source Port": 40000,
            "Destination Addr": dst, "Destination Port": 443, "State": state}


@pytest.fixture
def unit(tmp_path):
    u = tmp_path / "HOST-01_memory"
    _write(u, "pslist", [
        {"PID": 1, "TID": 1, "PPID": 0, "COMM": "systemd", "UID": 0,
         "CREATION TIME": "2024-01-01 10:00:00.000000 UTC"},
        {"PID": 900, "TID": 900, "PPID": 1, "COMM": "agent", "UID": 1000,
         "CREATION TIME": "2024-01-01 11:00:00.000000 UTC"}])
    _write(u, "psaux", [{"PID": 1, "PPID": 0, "COMM": "systemd", "ARGS": "/sbin/init"},
                        {"PID": 900, "PPID": 1, "COMM": "agent",
                         "ARGS": "/opt/agent/agent --serve"}])
    _write(u, "process_spoofing", [{"PID": 900, "PPID": 1, "Exe_Path": "/opt/agent/agent"}])
    return u


def _run(unit: Path, tmp_path) -> list[dict]:
    out = tmp_path / "out"
    ctx = ParserContext(evidence=unit, out=out, tools=unit, assets=DATA_DIR / "assets",
                        machine_name="HOST-01", volume=unit.name,
                        log=logging.getLogger("aeng.test"))
    N.run(ctx)
    return list(csv.DictReader((out / _procnet.TABLE).open(encoding="utf-8")))


def test_one_row_per_socket_not_per_thread_and_no_unix_sockets(unit, tmp_path):
    _write(unit, "sockstat", [
        _sock(900, 900, 5), _sock(900, 901, 5), _sock(900, 902, 5),   # 3 threads, 1 socket
        _sock(900, 900, 6, family="AF_INET6", proto="UDP", dst="-", state="UNCONNECTED",
              offset="0xbb"),
        _sock(900, 900, 7, family="AF_UNIX", proto="-", dst="/run/x.sock", offset="0xcc")])
    rows = _run(unit, tmp_path)
    assert [(r["proto"], r["remote_addr"]) for r in rows] == [("tcp", "8.8.8.8"), ("udp6", "")]


def test_each_socket_carries_its_process_and_parent(unit, tmp_path):
    _write(unit, "sockstat", [_sock(900, 900, 5)])
    [r] = _run(unit, tmp_path)
    assert r["process"] == "agent" and r["path"] == "/opt/agent/agent"
    assert r["cmdline"] == "/opt/agent/agent --serve" and r["user"] == "uid 1000"
    assert r["started_utc"] == "2024-01-01 11:00:00.000000 UTC"
    assert (r["ppid"], r["parent"], r["parent_cmdline"]) == ("1", "systemd", "/sbin/init")
    assert r["remote_scope"] == "public" and r["source"] == "memory/sockstat"


def test_a_socket_whose_process_is_in_no_list_is_kept(unit, tmp_path):
    _write(unit, "sockstat", [_sock(4242, 4242, 3, name="hidden", offset="0xdd")])
    [r] = _run(unit, tmp_path)
    assert (r["pid"], r["process"], r["path"]) == ("4242", "hidden", "")


def test_no_socket_table_is_a_skip(unit, tmp_path):
    with pytest.raises(HandlerSkip, match="linmem_sockstat"):
        _run(unit, tmp_path)


def test_the_parser_is_a_linux_memory_one_after_its_tables():
    [p] = [p for p in load_parsers([DATA_DIR / "parsers"]) if p.id == "linmem_process_network"]
    assert p.os == "linux" and "memory.image" in p.requires
    assert set(p.depends_on) == {"linmem_pslist", "linmem_psaux", "linmem_process_spoofing",
                                 "linmem_sockstat"}
