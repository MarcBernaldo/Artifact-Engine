"""Handler: network connections and listening sockets (Linux/UAC).

Primary source is `ss` (present on modern systems); falls back to `netstat`.
Output: network_connections.csv  (state LISTEN rows are the listening sockets).
"""

from __future__ import annotations

import re

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

# users:(("mariadbd",pid=1557,fd=111),("x",pid=2,fd=3))
_PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


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
    rows: list[list] = []
    if lr:
        net = lr / "network"
        ss_tcp = net / "ss_-tanp.txt"
        ss_udp = net / "ss_-uanp.txt"
        if ss_tcp.is_file() or ss_udp.is_file():
            _parse_ss(read_lines(ss_tcp), "tcp", rows)
            _parse_ss(read_lines(ss_udp), "udp", rows)
        else:
            _parse_netstat(read_lines(net / "netstat_-anp.txt"), rows)
    write_csv(
        ctx.out, "network_connections.csv",
        ["proto", "state", "local_addr", "local_port", "peer_addr", "peer_port", "process", "pids"],
        rows,
    )
