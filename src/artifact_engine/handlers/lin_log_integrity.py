"""Handler: log integrity / anti-forensics check. Output: log_integrity.csv

Post-mortem tampering signals from /var/log (SANS 'suspicious log data'):
- a key security log present but EMPTY (wiped), and
- a binary login log (wtmp/btmp/lastlog/utmp) whose size is not a whole number
  of fixed-size records (truncated / corrupted).

Also gives a coverage overview (which key logs are present/missing). Filesystem
mtimes are NOT used (extracted UAC times are extraction time, unreliable).
Missing logs are informational only -- a distro or collection profile may
simply lack them; only emptied security logs and truncated binaries are flagged.
"""

from __future__ import annotations

from artifact_engine.handlers._lincommon import root, write_csv

# Text security logs to check (relative to /var/log). Only one of each
# distro-specific pair (auth.log/secure, syslog/messages) exists per host; the
# other shows as 'missing', which is not flagged.
_TEXT = ["auth.log", "secure", "messages", "syslog", "kern.log", "cron", "audit/audit.log"]

# Binary login logs and their fixed record size (utmp layout = 384, lastlog = 292).
_BINARY = [("wtmp", 384), ("btmp", 384), ("utmp", 384), ("lastlog", 292)]

# Logs whose emptiness is itself suspicious (a live host normally has content);
# btmp/lastlog/utmp/kern.log/cron/audit can legitimately be empty.
_EMPTY_SUSPICIOUS = {"auth.log", "secure", "messages", "syslog", "wtmp"}


def run(ctx) -> None:
    log = root(ctx.evidence) / "var" / "log"
    rows: list[list] = []

    def check(name: str, rec: int | None = None) -> None:
        path = log / name
        if not path.is_file():
            rows.append([name, "missing", "", ""])
            return
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size == 0:
            rows.append([name, "empty", "0 bytes",
                         "yes" if name in _EMPTY_SUSPICIOUS else ""])
        elif rec and size % rec != 0:
            rows.append([name, "truncated", f"{size} bytes (not a multiple of {rec})", "yes"])
        else:
            detail = f"{size} bytes" + (f" ({size // rec} records)" if rec else "")
            rows.append([name, "present", detail, ""])

    for n in _TEXT:
        check(n)
    for n, rec in _BINARY:
        check(n, rec)

    rows.sort(key=lambda r: (r[3] != "yes", r[0]))
    write_csv(ctx.out, "log_integrity.csv",
              ["artifact", "status", "detail", "suspicious"], rows)
