"""Handler: every syslog line on the host. Output: syslog.csv

All the files under /var/log written in syslog format -- messages, syslog,
secure, auth.log, warn, mail*, maillog, cron, kern.log, daemon.log and any
other name a host's rsyslog config gives them (`_varlog` decides on content) --
every rotation, oldest first, one row per line. No filtering, no flags: auth,
cron_log and sudo_log are the classified views over a part of the same lines.

A host writing the same event to two files (SUSE: messages and warn) has it
twice here, once per `source`. A line that is not a syslog line (a stack trace's
continuation) keeps only `message`.

`time_local` is as logged; `time_utc` comes from `_syslogtime` -- the host's zone
and, for a yearless classic line, the year bounded by the archive's dateext name
or the acquisition. Empty when the acquisition does not say.
"""

from __future__ import annotations

import csv

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import iter_log_lines
from artifact_engine.handlers._syslogtime import Clock
from artifact_engine.handlers._varlog import SYSLOG_LINE, log_files

_HEADER = ["time_local", "time_utc", "host", "program", "pid", "message", "source"]


def run(ctx) -> None:
    files = list(log_files(ctx.evidence, "syslog"))
    if not files:
        raise HandlerSkip("no syslog-format logs under /var/log")
    clock = Clock(ctx.evidence)
    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "syslog.csv"
    rows = 0
    try:
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(_HEADER)
            for f in files:
                src = str(f.relative_to(ctx.evidence))
                bound = clock.bound(f)
                for line in iter_log_lines(f):
                    line = line.rstrip("\r")
                    if not line.strip():
                        continue
                    m = SYSLOG_LINE.match(line)
                    if m:
                        ts = m.group("ts")
                        w.writerow([ts, clock.utc(ts, bound), m.group("host"), m.group("program"),
                                    m.group("pid") or "", m.group("message"), src])
                    else:
                        w.writerow(["", "", "", "", "", line, src])
                    rows += 1
    except BaseException:
        out.unlink(missing_ok=True)          # a prefix is not a shorter table
        raise
    if rows == 0:
        out.unlink(missing_ok=True)
    if ctx.log:
        ctx.log.debug(f"syslog: {rows} line(s) from {len(files)} file(s)")
