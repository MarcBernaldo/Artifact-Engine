"""Handler: SigmaHQ's process_creation rules over the processes in memory (v0.7.94).

Every process a memory image still holds becomes one row of an in-memory SQLite
table named the way the Sigma taxonomy names a process-creation event --
`Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`,
`ParentUser`, `ProcessId`, `ParentProcessId` -- built from the unit's
Volatility tables (pslist/psscan for the processes, pstree for the paths,
cmdline for the command lines, getsids for the accounts). Each compiled rule
(core/sigma_windows.py) is a query against it; a rule asking for a field memory
does not give gets that column added as NULL and still runs its other branches.

Output `alert_mem_sigma`: one row per process and rule, with the rule's level, id and
tags beside what it matched on. mem_findings turns each into an alert.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.core.sigma_windows import TABLE, load_process_rules
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.lin_sigma import _run_rule
from artifact_engine.handlers.mem_findings import _int, _processes, _read

_COLS = ("ProcessId", "ParentProcessId", "Image", "CommandLine", "ParentImage",
         "ParentCommandLine", "User", "ParentUser")
_HEADER = ["pid", "process", "rule", "level", "rule_id", "tags", "image", "command_line",
           "parent_image"]

# How Sysmon and 4688 spell the service accounts, which is what the rules match.
_WELL_KNOWN = {"S-1-5-18": "NT AUTHORITY\\SYSTEM", "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
               "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE"}


def _accounts(rows: list[dict] | None) -> dict[int, str]:
    """pid -> the account the process runs as, spelled as the rules expect."""
    out: dict[int, str] = {}
    for r in rows or []:
        pid = _int(r.get("PID"))
        sid = (r.get("SID") or "").strip()
        if pid is None or pid in out:
            continue
        if sid in _WELL_KNOWN:
            out[pid] = _WELL_KNOWN[sid]
        elif sid.startswith("S-1-5-21-"):
            out[pid] = (r.get("Name") or sid).strip()
    return out


def run(ctx) -> None:
    base = Path(ctx.evidence) / "CSVs"
    t = {n: _read(base, n) for n in ("art_mem_pslist", "art_mem_psscan", "art_mem_pstree",
                                     "art_mem_cmdline", "art_mem_getsids", "art_mem_symlinkscan",
                                     "art_mem_info")}
    if not t["art_mem_pslist"] and not t["art_mem_psscan"]:
        raise HandlerSkip("no process table from the memory image (pslist/psscan)")
    rules = load_process_rules()
    if not rules:
        raise HandlerSkip("no Sigma process_creation rule compiled")
    procs = _processes(t)
    users = _accounts(t["art_mem_getsids"])

    conn = sqlite3.connect(":memory:")
    conn.execute(f"CREATE TABLE {TABLE} ({', '.join(chr(34) + c + chr(34) for c in _COLS)})")
    for pid, p in procs.items():
        parent = procs.get(p["ppid"]) if p["ppid"] is not None else None
        conn.execute(f"INSERT INTO {TABLE} VALUES ({', '.join('?' * len(_COLS))})", (
            pid, p["ppid"], p["path"] or None, p["cmdline"] or None,
            (parent or {}).get("path") or None, (parent or {}).get("cmdline") or None,
            users.get(pid), users.get(p["ppid"]) if p["ppid"] is not None else None))

    rows: list[list] = []
    for rule in rules:
        cols, hits = _run_rule(conn, rule.sql)
        if not hits or "ProcessId" not in cols:
            continue
        at = cols.index("ProcessId")
        for hit in hits:
            p = procs.get(hit[at])
            if p is None:
                continue
            parent = procs.get(p["ppid"]) if p["ppid"] is not None else None
            rows.append([p["pid"], p["process"], rule.title, rule.level, rule.rule_id,
                         rule.tags, p["path"], p["cmdline"][:500],
                         (parent or {}).get("path", "")])
    conn.close()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rows.sort(key=lambda r: (order.get(r[3], 5), r[0], r[2]))
    write_csv(ctx.out, "alert_mem_sigma.csv", _HEADER, rows)
