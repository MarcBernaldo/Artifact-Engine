"""Handler: the processes of a Linux host, each with the live sockets it holds.
Output: art_process_network.csv (see `_procnet`).

From UAC's live response, joined by PID: sockets from `ss` (or `netstat`
without it) -- a socket shared by several processes is one row per process --,
user, start time and command line from `ps` (the start in UTC too when the
acquisition names the host's zone), parent and exe from
`/proc/<pid>/`, and the exe's MD5/SHA1 from `hash_executables`. A process with
no socket is one row of its own, so this is the host's process table too: the
`processes` and `network_connections` tables it replaced are gone (v0.7.162).
The same table and columns as from Velociraptor or a memory image.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from artifact_engine.core import netclass
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _procnet
from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv
from artifact_engine.handlers._syslogtime import host_zone
from artifact_engine.handlers._webcommon import Geo
from artifact_engine.handlers.lin_hashes import _load as load_hashes
from artifact_engine.handlers.lin_proc_identity import exe_by_pid, pid_dirs, read_status

_DELETED = " (deleted)"

# users:(("mariadbd",pid=1557,fd=111),("x",pid=2,fd=3))
_PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')

# `ps -axo pid,user,lstart,args`: lstart is a fixed 5-token date,
#   PID USER  Www Mmm DD HH:MM:SS YYYY  COMMAND...
_LSTART_TOKENS = 5


def lstart_utc(started: str, zone: ZoneInfo | None) -> str:
    """`ps` lstart (`Thu Jun 18 10:00:00 2026`, host-local) in UTC, or '' without
    a zone or a date that parses."""
    if zone is None:
        return ""
    try:
        # read as UTC only to get an aware value; the zone replaces it next
        wall = datetime.strptime(" ".join(started.split()) + " +0000", "%a %b %d %H:%M:%S %Y %z")
    except ValueError:
        return ""
    return wall.replace(tzinfo=zone).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_ps_lstart(lines: list[str], rows: list[list]) -> None:
    for ln in lines:
        parts = ln.split()
        if len(parts) < _LSTART_TOKENS + 3 or not parts[0].isdigit():
            continue  # skips the header (PID is non-numeric there)
        pid, user = parts[0], parts[1]
        started = " ".join(parts[2:2 + _LSTART_TOKENS])
        command = " ".join(parts[2 + _LSTART_TOKENS:])
        rows.append([pid, user, started, command])


def _split_host_port(token: str) -> tuple[str, str]:
    """Split an ss/netstat 'addr:port' endpoint (IPv6-safe). Port is after the
    last ':'. Strips an interface scope like '%lo'."""
    if ":" not in token:
        return token, ""
    host, port = token.rsplit(":", 1)
    return host.split("%", 1)[0], port


def _parse_ss(lines: list[str], proto: str, rows: list[list]) -> None:
    for ln in lines:
        if not ln.strip() or ln.lstrip().startswith("State"):  # header
            continue
        parts = ln.split(maxsplit=5)
        if len(parts) < 5:
            continue
        state, _rq, _sq, local, peer = parts[:5]
        proc_field = parts[5] if len(parts) > 5 else ""
        la, lp = _split_host_port(local)
        pa, pp = _split_host_port(peer)
        procs = _PROC_RE.findall(proc_field)
        name = procs[0][0] if procs else ""
        pids = ";".join(p[1] for p in procs)
        rows.append([proto, state, la, lp, pa, pp, name, pids])


def _parse_netstat(lines: list[str], rows: list[list]) -> None:
    # netstat -anp: Proto Recv-Q Send-Q Local Foreign State PID/Program
    for ln in lines:
        parts = ln.split()
        if len(parts) < 6 or parts[0] not in ("tcp", "tcp6", "udp", "udp6"):
            continue
        proto, _rq, _sq, local, peer = parts[:5]
        # UDP rows have no State column; the program is always last.
        is_udp = proto.startswith("udp")
        state = "" if is_udp else parts[5]
        prog = parts[-1] if "/" in parts[-1] else ""
        pid, _, name = prog.partition("/")
        la, lp = _split_host_port(local)
        pa, pp = _split_host_port(peer)
        rows.append([proto, state, la, lp, pa, pp, name, pid if pid.isdigit() else ""])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    if not lr:
        raise HandlerSkip("no UAC live_response")
    net = lr / "network"
    raw: list[list] = []
    ss_tcp, ss_udp = net / "ss_-tanp.txt", net / "ss_-uanp.txt"
    if ss_tcp.is_file() or ss_udp.is_file():
        _parse_ss(read_lines(ss_tcp), "tcp", raw)
        _parse_ss(read_lines(ss_udp), "udp", raw)
        kind = "ss"
    else:
        _parse_netstat(read_lines(net / "netstat_-anp.txt"), raw)
        kind = "netstat" if raw else "ps"

    ps: list[list] = []
    _parse_ps_lstart(read_lines(lr / "process" / "ps_-axo_pid_user_lstart_args.txt"), ps)
    exes = exe_by_pid(lr)
    hashes = Path(ctx.evidence) / "hash_executables"
    md5 = load_hashes(hashes / "hash_executables.md5")
    sha1 = load_hashes(hashes / "hash_executables.sha1")

    zone = host_zone(Path(ctx.evidence))
    procs: dict[str, dict] = {}
    for pid, user, started, command in ps:
        procs[pid] = {"user": user, "started_local": started,
                      "started_utc": lstart_utc(started, zone), "cmdline": command,
                      "process": Path(command.split(" ", 1)[0]).name if command else ""}
    for d in pid_dirs(lr / "process" / "proc"):
        st = read_status(d / "status.txt")
        p = procs.setdefault(d.name, {})
        p["ppid"] = st.get("PPid", "")
        p["process"] = st.get("Name") or p.get("process", "")
    for pid, exe in exes.items():
        path = exe.removesuffix(_DELETED).strip()
        p = procs.setdefault(pid, {})
        p["path"] = exe
        p["md5"], p["sha1"] = md5.get(path, ""), sha1.get(path, "")
    if not raw and not procs:
        raise HandlerSkip("no processes or sockets in live_response (ps, /proc, ss, netstat)")

    conns = []
    for proto, state, la, lp, pa, pp, name, pids in raw:
        many = pids.split(";") if pids else [""]
        # `ss` names only the first of several processes sharing a socket, so the
        # name stands in for an unknown PID only when it is the socket's one owner.
        owner = name if len(many) == 1 else ""
        for pid in many:
            conns.append({"pid": pid, "owner": owner, "proto": proto, "state": state,
                          "local_addr": la, "local_port": lp, "remote_addr": pa,
                          "remote_port": pp})
    nc = netclass.parse(getattr(ctx, "internal_networks", ()) or ())
    write_csv(ctx.out, _procnet.TABLE, _procnet.HEADER,
              _procnet.rows(procs, conns, f"uac/{kind}", nc, Geo(Path(ctx.assets))))
