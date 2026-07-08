"""Handler: running processes captured by UAC live response (Linux). Outputs:
  processes.csv    - pid, user, start time (lstart) and full command line
  hidden_pids.csv  - PIDs present in /proc but hidden from `ps` (rootkit signal)
"""

from __future__ import annotations

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

# `ps -axo pid,user,lstart,args`: lstart is a fixed 5-token date,
#   PID USER  Www Mmm DD HH:MM:SS YYYY  COMMAND...
_LSTART_TOKENS = 5


def _parse_ps_lstart(lines: list[str], rows: list[list]) -> None:
    for ln in lines:
        parts = ln.split()
        if len(parts) < _LSTART_TOKENS + 3 or not parts[0].isdigit():
            continue  # skips the header (PID is non-numeric there)
        pid, user = parts[0], parts[1]
        started = " ".join(parts[2:2 + _LSTART_TOKENS])
        command = " ".join(parts[2 + _LSTART_TOKENS:])
        rows.append([pid, user, started, command])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    procs: list[list] = []
    hidden: list[list] = []
    if lr:
        proc = lr / "process"
        _parse_ps_lstart(read_lines(proc / "ps_-axo_pid_user_lstart_args.txt"), procs)
        for ln in read_lines(proc / "hidden_pids_for_ps_command.txt"):
            s = ln.strip()
            if s.isdigit():
                hidden.append([s])
    write_csv(ctx.out, "processes.csv", ["pid", "user", "started_local", "command"], procs)
    write_csv(ctx.out, "hidden_pids.csv", ["pid"], hidden)
