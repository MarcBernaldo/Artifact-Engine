"""Handler: systemd runtime services. Output: services.csv

Runtime counterpart to the persistence handler (which reads unit *files* on
disk). This reads what systemd actually has loaded at acquisition time:
- list-units  : the loaded .service inventory and their active/sub state. A
                LOAD=not-found service is referenced but its file is gone
                (masked/deleted unit) -- that is flagged.

The runtime timer list (`list-timers`) is read by lin_tasks since v0.7.168, into
the row of each timer in `tasks.csv`.

service_--status-all is intentionally not used: it is a SysV wrapper whose
output some hosts override with custom scripts, so it is unreliable.

Only not-found services are flagged. Failed services are surfaced (sorted near
the top) but not asserted malicious -- they are common and usually benign.
"""

from __future__ import annotations

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv


def _services(lines: list[str], rows: list[list]) -> None:
    # Columns: UNIT LOAD ACTIVE SUB DESCRIPTION. Lines start with two spaces, or
    # "* " when systemd marks the unit (failed/degraded). DESCRIPTION may hold
    # the word "failed", so the ACTIVE column is parsed -- never the raw line.
    for raw in lines:
        s = raw.strip()
        if s.startswith("*"):
            s = s[1:].strip()
        if not s or s.startswith("UNIT "):           # header
            continue
        p = s.split(None, 4)
        if len(p) < 4 or not p[0].endswith(".service"):
            continue
        unit, load, active, sub = p[0], p[1], p[2], p[3]
        desc = p[4] if len(p) > 4 else ""
        susp = "yes" if load == "not-found" else ""
        rows.append(["service", unit, f"{active}/{sub}", desc, susp])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    rows: list[list] = []
    if lr:
        sysd = lr / "system"
        _services(read_lines(sysd / "systemctl_list-units.txt"), rows)
    # Flagged first, then failed services, then everything by kind/name.
    rows.sort(key=lambda r: (r[4] != "yes", "failed" not in r[2], r[0], r[1]))
    write_csv(ctx.out, "services.csv", ["kind", "name", "state", "detail", "suspicious"], rows)
