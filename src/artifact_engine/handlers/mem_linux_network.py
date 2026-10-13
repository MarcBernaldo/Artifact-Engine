"""Handler: each network socket in a LINUX memory image with the process that
holds it (v0.7.116). Output: process_network.csv (see `_procnet`).

The Linux counterpart of `mem_process_network`, from the unit's `linmem_*`
tables, never the image: processes from `linmem_pslist` (start time, uid), their
command lines from `linmem_psaux` and binaries from `linmem_process_spoofing`;
sockets from `linmem_sockstat`. Only IPv4/IPv6 sockets: the UNIX ones are tens of
thousands on a desktop image (over nine rows in ten) and name no peer.

`sockstat` lists a socket once per THREAD of the process that holds it (a socket
belongs to the file table, which the threads share): one row per process, file
descriptor and socket here. The account is the numeric uid -- memory holds no
passwd file to name it -- and a memory image holds no file hashes.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core import netclass
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _procnet
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers._webcommon import Geo
from artifact_engine.handlers.mem_findings import _int, _read

_INET = {"AF_INET": "", "AF_INET6": "6"}


def _processes(t: dict) -> dict[int, dict]:
    procs: dict[int, dict] = {}
    for r in t.get("linmem_pslist") or []:
        pid = _int(r.get("PID"))
        if pid is None or pid in procs:
            continue
        uid = (r.get("UID") or "").strip()
        procs[pid] = {"process": r.get("COMM", ""), "ppid": _int(r.get("PPID")),
                      "user": f"uid {uid}" if uid else "", "path": "", "cmdline": "",
                      # Volatility writes "YYYY-MM-DD HH:MM:SS.ffffff UTC"
                      "started_utc": (r.get("CREATION TIME") or "").strip()}
    for r in t.get("linmem_psaux") or []:
        p = procs.get(_int(r.get("PID")))
        if p is not None:
            p["cmdline"] = (r.get("ARGS") or "").strip()
    for r in t.get("linmem_process_spoofing") or []:
        p = procs.get(_int(r.get("PID")))
        if p is not None:
            p["path"] = (r.get("Exe_Path") or "").strip()
    return procs


def _sockets(rows: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    conns = []
    for r in rows:
        family = (r.get("Family") or "").strip()
        if family not in _INET:
            continue
        key = (r.get("PID"), r.get("FD"), r.get("Sock Offset"))
        if key in seen:
            continue
        seen.add(key)
        conns.append({"pid": r.get("PID"), "owner": r.get("Process Name", ""),
                      "proto": (r.get("Proto") or "").strip().lower() + _INET[family],
                      "state": r.get("State", ""),
                      "local_addr": r.get("Source Addr", ""),
                      "local_port": r.get("Source Port", ""),
                      "remote_addr": r.get("Destination Addr", ""),
                      "remote_port": r.get("Destination Port", "")})
    return conns


def run(ctx) -> None:
    base = Path(ctx.evidence) / "CSVs"
    t = {name: _read(base, name) for name in ("linmem_pslist", "linmem_psaux",
                                              "linmem_process_spoofing", "linmem_sockstat")}
    if not t["linmem_sockstat"]:
        raise HandlerSkip("no socket table from the memory image (linmem_sockstat)")
    conns = _sockets(t["linmem_sockstat"])
    nc = netclass.parse(getattr(ctx, "internal_networks", ()) or ())
    write_csv(ctx.out, _procnet.TABLE, _procnet.HEADER,
              _procnet.rows(_processes(t), conns, "memory/sockstat", nc, Geo(Path(ctx.assets))))
