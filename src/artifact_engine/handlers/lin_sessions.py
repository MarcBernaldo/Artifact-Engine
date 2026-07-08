"""Handler: active sessions + unix sockets in temp dirs. Output: sessions.csv

A runtime snapshot from live_response (login *history* is already covered by
the wtmp/btmp/logins parsers, so last_-i / last_-a / loginctl are not re-read):
- who -T          : who was interactively logged in at acquisition time, and
                    from where. Emitted as reference (user, tty, source). Not
                    flagged: in this environment hosts use public source IPs
                    legitimately, so a public-IP rule would fire on everyone --
                    the value is the user/source list for correlation.
- socket_files    : unix domain sockets on disk. Only those under a
                    world-writable temp dir (/tmp, /var/tmp, /dev/shm) are
                    emitted, and flagged: a daemon almost never puts its socket
                    there, but an implant/backdoor's IPC endpoint does. The
                    standard X11/ICE socket dirs under /tmp are excluded.

Self-gating: hosts with neither file are skipped.
"""

from __future__ import annotations

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

# Implant-favoured socket locations. Anchored on the path prefix, not a
# substring: legitimate apps nest a "tmp" dir elsewhere (e.g. Elastic Agent's
# /opt/Elastic/Agent/data/tmp/*.sock) which must not match.
_TMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
# X11/ICE/font sockets live under /tmp by design.
_TMP_OK = ("/tmp/.X11-unix/", "/tmp/.ICE-unix/", "/tmp/.XIM-unix/", "/tmp/.font-unix/")


def _sockets(lines: list[str], rows: list[list]) -> None:
    for ln in lines:
        p = ln.strip()
        if p.startswith(_TMP_DIRS) and not p.startswith(_TMP_OK):
            rows.append(["socket", p, "unix socket in world-writable temp dir", "yes"])


def _sessions(lines: list[str], rows: list[list]) -> None:
    # who -T:  user  <+/-/?>  tty  Mon Day HH:MM  (host)
    # Plain who has no message-status column, so detect it rather than assume.
    for ln in lines:
        t = ln.split()
        if len(t) < 5:
            continue
        user = t[0]
        i = 2 if t[1] in ("+", "-", "?") else 1   # skip the message-status flag
        tty = t[i]
        when = " ".join(t[i + 1:i + 4])
        host = t[i + 4].strip("()") if len(t) > i + 4 else ""
        rows.append(["session", user, f"{tty} from {host or 'local'} at {when}", ""])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    sysd = (lr / "system") if lr else None
    who_f = sysd / "who_-T.txt" if sysd else None
    sock_f = sysd / "socket_files.txt" if sysd else None
    if not sysd or not ((who_f and who_f.exists()) or (sock_f and sock_f.exists())):
        raise HandlerSkip("no session/socket data collected")

    rows: list[list] = []
    _sockets(read_lines(sock_f), rows)
    _sessions(read_lines(who_f), rows)
    # Flagged sockets first, then sessions.
    rows.sort(key=lambda r: (r[3] != "yes", r[0], r[1]))
    write_csv(ctx.out, "sessions.csv", ["kind", "name", "detail", "suspicious"], rows)
