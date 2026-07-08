"""Handler: sudo command log (/var/log/sudo.log). Output: sudo_log.csv

When sudoers has `logfile=`, every sudo invocation lands here: who ran what
as which user, from which TTY/cwd - and every DENIAL ("command not allowed",
"user NOT in sudoers", "N incorrect password attempts"). On a compromised
server this is the "what was done as root" record that auth.log only hints
at. Rotations (.gz/.xz) are read too.

Line format (year included, host-local time):
  Sep 25 09:20:31 2024 : user : HOST=h ; TTY=pts/0 ; PWD=/home/u ; USER=root ; COMMAND=/bin/su - root
  Sep 23 17:35:57 2024 : user : command not allowed ; HOST=h ; PWD=... ; USER=root ; COMMAND=...

The COMMAND value may itself contain " ; " (e.g. Ansible become wrappers),
so the line is split at the first "COMMAND=" and only the head is parsed as
fields. `suspicious` flags sudo execution out of a staging dir and the
password-failure / not-in-sudoers denials (privilege probing); the routine
"command not allowed" policy denials stay unflagged (service-account noise)
but are visible in `status`.
"""

from __future__ import annotations

import re

from artifact_engine.handlers._lincommon import iter_log_lines, root, write_csv

_LINE = re.compile(r"^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\d{4}) : (\S+) : (.*)$")
_MONTHS = {m: f"{i:02d}" for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

_STAGING = ("/tmp/", "/var/tmp/", "/dev/shm/")
_PROBE = re.compile(r"incorrect password|NOT in sudoers|not in sudoers", re.IGNORECASE)


def _susp(status: str, command: str) -> str:
    if _PROBE.search(status):
        return "yes"                      # password guessing / privilege probing
    exe = command.split(None, 1)[0] if command else ""
    if exe.startswith(_STAGING):
        return "yes"                      # sudo'ing a binary out of a staging dir
    return ""


def _parse(lines, rows: list[list]) -> None:
    for ln in lines:
        m = _LINE.match(ln)
        if not m:
            continue                      # wrapped continuation or garbage
        mon, day, hms, year, user, rest = m.groups()
        ts = f"{year}-{_MONTHS.get(mon, '00')}-{int(day):02d} {hms}"
        idx = rest.find("COMMAND=")
        command = rest[idx + 8:].strip() if idx >= 0 else ""
        head = rest[:idx] if idx >= 0 else rest
        fields: dict[str, str] = {}
        status: list[str] = []
        for part in head.split(" ; "):
            part = part.strip().rstrip(";").strip()
            if not part:
                continue
            k, sep, v = part.partition("=")
            if sep and k.isupper():
                fields[k] = v
            else:
                status.append(part)
        st = "; ".join(status)
        rows.append([ts, user, fields.get("USER", ""), fields.get("TTY", ""),
                     fields.get("PWD", ""), st, command, _susp(st, command)])


def run(ctx) -> None:
    log_dir = root(ctx.evidence) / "var" / "log"
    rows: list[list] = []
    for f in sorted(log_dir.glob("sudo.log*")) if log_dir.is_dir() else []:
        if f.is_file():
            _parse(iter_log_lines(f), rows)
    rows.sort(key=lambda r: r[0])         # ISO timestamps -> chronological
    write_csv(ctx.out, "sudo_log.csv",
              ["time_local", "user", "runas", "tty", "pwd", "status",
               "command", "suspicious"], rows)
