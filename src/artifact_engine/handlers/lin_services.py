"""Handler: systemd runtime services + timers. Output: services.csv

Runtime counterpart to the persistence handler (which reads unit *files* on
disk). This reads what systemd actually has loaded at acquisition time:
- list-units  : the loaded .service inventory and their active/sub state. A
                LOAD=not-found service is referenced but its file is gone
                (masked/deleted unit) -- that is flagged.
- list-timers : every timer and the unit it activates. Timers are an
                alternative to cron for scheduled persistence, so the full
                timer->service mapping is surfaced alongside the cron output.

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


def _timers(lines: list[str], rows: list[list]) -> None:
    # Header: NEXT LEFT LAST PASSED UNIT ACTIVATES. NEXT/LAST are datetime
    # strings with embedded spaces and LEFT is right-aligned, so neither
    # split() nor header-column slicing is reliable. Two stable anchors instead:
    # NEXT is always the first 4 tokens (weekday date time tz) or "n/a"; the
    # unit is the ".timer" token and ACTIVATES is whatever follows it.
    for raw in lines[1:]:
        toks = raw.split()
        if not toks:
            continue
        idx = next((i for i, t in enumerate(toks) if t.endswith(".timer")), -1)
        if idx < 0:
            continue
        unit = toks[idx]
        activates = " ".join(toks[idx + 1:])
        next_run = "n/a" if toks[0].lower() == "n/a" else " ".join(toks[:4])
        detail = f"activates={activates}" if activates else ""
        rows.append(["timer", unit, next_run, detail, ""])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    rows: list[list] = []
    if lr:
        sysd = lr / "system"
        _services(read_lines(sysd / "systemctl_list-units.txt"), rows)
        _timers(read_lines(sysd / "systemctl_list-timers_--all.txt"), rows)
    # Flagged first, then failed services, then everything by kind/name.
    rows.sort(key=lambda r: (r[4] != "yes", "failed" not in r[2], r[0], r[1]))
    write_csv(ctx.out, "services.csv", ["kind", "name", "state", "detail", "suspicious"], rows)
