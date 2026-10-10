"""Handler: each live socket of a Linux host with the process that holds it.
Output: process_network.csv (see `_procnet`).

From UAC's live response, joined by PID: sockets from `ss` (or `netstat`
without it) -- a socket shared by several processes is one row per process --,
user, start time and command line from `ps`, parent and exe from
`/proc/<pid>/`, and the exe's MD5/SHA1 from `hash_executables`. The same table
and columns as from Velociraptor or a memory image.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core import netclass
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _procnet
from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv
from artifact_engine.handlers._webcommon import Geo
from artifact_engine.handlers.lin_hashes import _load as load_hashes
from artifact_engine.handlers.lin_network import _parse_netstat, _parse_ss
from artifact_engine.handlers.lin_proc_identity import exe_by_pid, pid_dirs, read_status
from artifact_engine.handlers.lin_processes import _parse_ps_lstart

_DELETED = " (deleted)"


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
        kind = "netstat"
    if not raw:
        raise HandlerSkip("no sockets in live_response/network (ss / netstat)")

    ps: list[list] = []
    _parse_ps_lstart(read_lines(lr / "process" / "ps_-axo_pid_user_lstart_args.txt"), ps)
    exes = exe_by_pid(lr)
    hashes = Path(ctx.evidence) / "hash_executables"
    md5 = load_hashes(hashes / "hash_executables.md5")
    sha1 = load_hashes(hashes / "hash_executables.sha1")

    procs: dict[str, dict] = {}
    for pid, user, started, command in ps:
        procs[pid] = {"user": user, "started_local": started, "cmdline": command,
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
