"""Handler: full web access-log timeline. Output: web_access.csv

Parses EVERY Apache/nginx access log on the host (current + rotated .gz + per
-vhost) into one clean, sortable timeline. No filtering, no flags -- this is the
raw record the analyst pivots through; `huntweb` is the attack-only view over the
same data. Streams to CSV so a multi-hundred-MB log set never loads whole.
"""

from __future__ import annotations

import csv

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import iter_log_lines
from artifact_engine.handlers._webcommon import iter_access_files, parse

_HEADER = ["time", "ip", "edge_ip", "method", "status", "size", "path", "query",
           "referer", "ua", "source"]


def run(ctx) -> None:
    files = list(iter_access_files(ctx.evidence))
    if not files:
        raise HandlerSkip("no apache/nginx access logs")

    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "web_access.csv"
    rows = 0
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(_HEADER)
        for f in files:
            try:
                src = str(f.relative_to(ctx.evidence))  # for traceability
            except ValueError:
                src = f.name
            for line in iter_log_lines(f):
                rec = parse(line)
                if rec is None:
                    continue
                w.writerow([rec.time, rec.ip, rec.edge_ip, rec.method, rec.status,
                            rec.size, rec.path, rec.query, rec.referer, rec.ua, src])
                rows += 1
    if rows == 0:
        out.unlink(missing_ok=True)  # access_log present but empty -> no CSV
    if ctx.log:
        ctx.log.debug(f"web_access: {rows} request(s) from {len(files)} file(s)")
