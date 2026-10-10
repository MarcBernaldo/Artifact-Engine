"""One row per (process, socket): who holds a connection, and where it came from.

Every source that sees live sockets -- Velociraptor's LiveResponse, UAC's live
response, a memory image -- writes its connections and its processes in two
tables that the analyst then joins by PID in their head, per row. This module
is the join, written once: each socket with the owning process's path, command
line, user and hashes, its parent's name and command line, and the remote
address's scope and origin. The same columns from every source, so one table
name (`process_network`) reads the same on a Windows host, a Linux host and a
memory image (v0.7.98).

A socket whose PID is in no process table is kept: an exited owner, or a hidden
one, is itself worth seeing. Its `process` is then the name the socket table
itself gives (`owner`), when it gives one; the other process columns stay empty.

Callers give `procs` as {pid: {...}} with any of the keys in _PROC_KEYS and
`conns` as dicts with the keys in _CONN_KEYS plus `pid` and, optionally,
`owner` (the process name the socket table carries).
"""

from __future__ import annotations

from artifact_engine.core import netclass

TABLE = "process_network.csv"

_PROC_KEYS = ("process", "path", "cmdline", "user", "md5", "sha1", "sha256",
              "started_utc", "started_local")
_CONN_KEYS = ("proto", "state", "local_addr", "local_port", "remote_addr", "remote_port")

HEADER = ["pid", *_PROC_KEYS, "ppid", "parent", "parent_cmdline", *_CONN_KEYS,
          "remote_scope", "country", "origin", "asn", "source"]

# Addresses that name no peer: a listener's wildcard, or an unconnected socket.
_NO_PEER = {"", "*", "0.0.0.0", "::", "[::]", "0:0:0:0:0:0:0:0"}

# Most interesting first: what talks to the internet, then the organisation's
# own ranges, then the rest.
_SCOPE_ORDER = {netclass.PUBLIC: 0, netclass.INTERNAL: 1, netclass.PRIVATE: 2, "": 3}


def _pid(v) -> str:
    try:
        return str(int(str(v).strip()))
    except (TypeError, ValueError):
        return ""


def rows(procs: dict, conns: list[dict], source: str, nc=netclass.EMPTY,
         geo=None) -> list[list]:
    """The joined rows, most interesting first."""
    by_pid = {_pid(k): v for k, v in procs.items() if _pid(k)}
    out: list[tuple] = []
    for c in conns:
        pid = _pid(c.get("pid"))
        p = by_pid.get(pid) or {}
        ppid = _pid(p.get("ppid"))
        parent = by_pid.get(ppid) or {}
        remote = str(c.get("remote_addr") or "").strip()
        peer = remote not in _NO_PEER
        scope = nc.scope(remote) if peer else ""
        country = origin = asn = ""
        if peer and scope == netclass.PUBLIC and geo is not None:
            country, origin, asn = geo.lookup(remote)
        p = {**p, "process": p.get("process") or c.get("owner") or ""}
        row = [pid, *(p.get(k, "") or "" for k in _PROC_KEYS), ppid,
               parent.get("process", "") or "", parent.get("cmdline", "") or "",
               *(c.get(k, "") if c.get(k) is not None else "" for k in _CONN_KEYS),
               scope, country, origin, asn, source]
        out.append((_SCOPE_ORDER.get(scope, 3), int(pid) if pid else -1, row))
    out.sort(key=lambda x: (x[0], x[1]))
    return [r for _, _, r in out]
