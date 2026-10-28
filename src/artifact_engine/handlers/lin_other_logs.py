"""Handler: every other text log under /var/log. Output: art_log_other.csv

Every text file `_varlog` does not take for `syslog`, outside the directories
it leaves out: application and tool logs (sssd, snapper, anaconda, YaST2,
cloud-init, tuned, rhsm, vmware-tools, letsencrypt, salt, a database's error
log, ...), and as raw lines the package logs `art_log_pkg` also reads. One row
per line, every rotation, oldest first. No filtering, no flags.

`timestamp` is the time a line starts with when it is one of the common forms
(ISO 8601, `YYYY/MM/DD hh:mm:ss`, ctime `Wed Oct 11 14:32:52 2026`, each maybe
in brackets), exactly as written -- these logs do not say which zone they
write in, so nothing is converted -- and `message` is the rest. A line that
does not start with one keeps it all in `message`.

Left out as not logs: sysstat's daily reports (`sa/`).
"""

from __future__ import annotations

import csv
import re

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import iter_log_lines
from artifact_engine.handlers._varlog import log_files

_HEADER = ["timestamp", "message", "source"]
_NOT_LOGS = {"sa"}
_STAMP = re.compile(
    r"^\[?(?P<ts>"
    r"\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|\s?[+-]\d\d:?\d\d)?"
    r"|\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(?:\.\d+)?"
    r"|(?:[A-Z][a-z]{2} )?[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d(?:\.\d+)? \d{4}"
    r")\]?[\s:,|-]*")


def run(ctx) -> None:
    files = [f for f in log_files(ctx.evidence, "text") if _owner_dir(f) not in _NOT_LOGS]
    if not files:
        raise HandlerSkip("no other text logs under /var/log")
    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "art_log_other.csv"
    rows = 0
    try:
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(_HEADER)
            for f in files:
                src = str(f.relative_to(ctx.evidence))
                for line in iter_log_lines(f):
                    line = line.rstrip("\r")
                    if not line.strip():
                        continue
                    m = _STAMP.match(line)
                    if m:
                        w.writerow([m.group("ts"), line[m.end():], src])
                    else:
                        w.writerow(["", line, src])
                    rows += 1
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    if rows == 0:
        out.unlink(missing_ok=True)
    if ctx.log:
        ctx.log.debug(f"art_log_other: {rows} line(s) from {len(files)} file(s)")


def _owner_dir(f) -> str:
    """The first directory below /var/log a file sits in ('' at the top)."""
    parts = f.as_posix().split("/var/log/", 1)[-1].split("/")
    return parts[0] if len(parts) > 1 else ""
