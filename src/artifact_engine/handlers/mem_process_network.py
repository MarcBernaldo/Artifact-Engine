"""Handler: the processes in a memory image, each with the sockets it holds.
Output: process_network.csv (see `_procnet`); a process with no socket is one
row of its own.

Built from the unit's Volatility tables, never from the image: the processes
as mem_findings assembles them (pslist + psscan, paths from pstree with the
image's own drive letters, command lines, the account from getsids) and the
sockets from netscan -- which carves closed ones too -- or, without it, netstat.
A memory image holds no file hashes, so those columns stay empty here.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core import netclass
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _procnet
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers._webcommon import Geo
from artifact_engine.handlers.mem_findings import _TABLES, _processes, _read

_SOCKETS = ("mem_netscan", "mem_netstat")


def _proto(raw: str) -> str:
    """`TCPv4`/`UDPv6` as the other sources spell it: `tcp`, `udp6`."""
    p = (raw or "").strip().lower()
    return p.replace("v4", "").replace("v6", "6")


def run(ctx) -> None:
    base = Path(ctx.evidence) / "CSVs"
    t = {name: _read(base, name) for name in (*_TABLES, *_SOCKETS)}
    sockets = t["mem_netscan"] or t["mem_netstat"] or []
    procs = {}
    for pid, p in _processes(t).items():
        procs[pid] = {"process": p["process"], "path": p["path"], "cmdline": p["cmdline"],
                      "user": p["user"], "ppid": p["ppid"],
                      # Volatility writes "YYYY-MM-DD HH:MM:SS.ffffff UTC"
                      "started_utc": p["create_time"]}
    conns = [{"pid": r.get("PID"), "owner": r.get("Owner", ""),
              "proto": _proto(r.get("Proto", "")),
              "state": r.get("State", ""), "local_addr": r.get("LocalAddr", ""),
              "local_port": r.get("LocalPort", ""), "remote_addr": r.get("ForeignAddr", ""),
              "remote_port": r.get("ForeignPort", ""),
              # "YYYY-MM-DD HH:MM:SS.ffffff UTC"; empty where Volatility wrote N/A
              "socket_created_utc": r.get("Created", "")} for r in sockets]
    if not procs and not conns:
        raise HandlerSkip("no process or socket table from the memory image")
    nc = netclass.parse(getattr(ctx, "internal_networks", ()) or ())
    source = "netscan" if t["mem_netscan"] else "netstat" if t["mem_netstat"] else "pslist"
    write_csv(ctx.out, _procnet.TABLE, _procnet.HEADER,
              _procnet.rows(procs, conns, f"memory/{source}", nc, Geo(Path(ctx.assets))))
