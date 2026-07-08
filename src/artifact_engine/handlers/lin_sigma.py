"""Handler: run the bundled SigmaHQ Linux ruleset over the raw UAC logs.

Reads the acquisition's own logs (NOT the consolidated .db):
  - auditd  ([root]/var/log/audit/audit.log*)  -> flattened "auditd" table
  - syslog  (auth.log/syslog/messages/secure*) -> "syslog" table (full line)

Each Sigma rule is compiled to a SQLite query (see core.sigma_engine) and run
against its table; matches become rows in sigma_detections.csv. auditd EXECVE
records are enriched with synthesised Image/CommandLine/User so process_creation
rules match; the raw line (plus decoded cmdline) is kept in `message` for the
keyword rules.
"""

from __future__ import annotations

import re
import sqlite3

from artifact_engine.core.sigma_engine import load_rules
from artifact_engine.handlers._lincommon import iter_log_lines, root, tail_lines, write_csv

# auditd record: "type=X msg=audit(<ts>:<serial>): <rest>"
_AUDIT = re.compile(r"^type=(\S+)\s+msg=audit\(([\d.]+):(\d+)\):\s*(.*)$")
_KV = re.compile(r"(\w+)=(?:\"([^\"]*)\"|'([^']*)'|(\S+))")
# syslog: "<ts> <host> <proc>[pid]: <msg>"
_SYS = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.+\-]+|[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_SYSLOG_GLOBS = ("auth.log*", "syslog*", "messages*", "secure*")
# Skip dated deep archives (e.g. messages-20260331.xz): scanning every rotation
# means millions of lines per host. Sigma over syslog targets recent activity;
# the base file + .1/.gz rotations are kept, dated archives are not.
_ARCHIVE = re.compile(r"-\d{8}")
# Keep the most RECENT N syslog lines (read from EOF). Small files (auth/secure)
# are taken whole first so a multi-GB `messages` can't crowd out the auth log.
_SYSLOG_MAX_LINES = 500_000

# x86-64 syscall numbers -> names (the security-relevant subset Sigma rules use).
_SYSCALLS = {
    "0": "read", "1": "write", "2": "open", "41": "socket", "42": "connect",
    "43": "accept", "49": "bind", "56": "clone", "57": "fork", "58": "vfork",
    "59": "execve", "62": "kill", "82": "rename", "84": "rmdir", "86": "link",
    "87": "unlink", "90": "chmod", "92": "chown", "101": "ptrace", "105": "setuid",
    "106": "setgid", "155": "pivot_root", "165": "mount", "166": "umount2",
    "175": "init_module", "176": "delete_module", "200": "tkill",
    "279": "memfd_create", "319": "memfd_create", "322": "execveat",
}
_HEX = re.compile(r"^[0-9A-Fa-f]+$")


def _unhex(v: str) -> str:
    """Decode an auditd hex-encoded argument; return as-is if not hex."""
    if len(v) >= 2 and len(v) % 2 == 0 and _HEX.match(v):
        try:
            return bytes.fromhex(v).decode("utf-8", "replace")
        except ValueError:
            return v
    return v


def _kv(rest: str) -> dict:
    d = {}
    for m in _KV.finditer(rest):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
        d[key] = val
    return d


def _parse_auditd(lines) -> list[dict]:
    """Group records by audit serial, synthesise process fields, one row/record."""
    groups: dict[str, list[dict]] = {}
    order: list[str] = []
    for ln in lines:
        m = _AUDIT.match(ln)
        if not m:
            continue
        rtype, ts, serial, rest = m.groups()
        rec = _kv(rest)
        rec["type"], rec["_ts"], rec["_serial"], rec["message"] = rtype, ts, serial, ln
        if serial not in groups:
            groups[serial] = []
            order.append(serial)
        groups[serial].append(rec)

    rows: list[dict] = []
    for serial in order:
        recs = groups[serial]
        exe = cmdline = cwd = user = ""
        for r in recs:
            if r["type"] == "SYSCALL":
                exe = r.get("exe", "")
                user = r.get("uid", r.get("auid", ""))
                num = r.pop("syscall", None)   # replace number with name (Sigma uses SYSCALL)
                if num is not None:
                    r["SYSCALL"] = _SYSCALLS.get(num, num)
            elif r["type"] == "EXECVE":
                try:
                    n = int(r.get("argc", "0"))
                except ValueError:
                    n = 0
                cmdline = " ".join(_unhex(r[f"a{i}"]) for i in range(n) if f"a{i}" in r)
            elif r["type"] == "CWD":
                cwd = r.get("cwd", "")
        for r in recs:
            r.setdefault("Image", exe)
            r["CommandLine"] = cmdline
            r["CurrentDirectory"] = cwd
            r.setdefault("User", user)
            if cmdline:                       # make decoded args keyword-searchable
                r["message"] = f"{r['message']} {cmdline}"
            rows.append(r)
    return rows


def _syslog_row(ln: str) -> dict:
    m = _SYS.match(ln)
    if m:
        return {"message": ln, "timestamp": m.group("ts"),
                "host": m.group("host"), "proc": m.group("proc")}
    return {"message": ln, "timestamp": "", "host": "", "proc": ""}


def _load_table(conn: sqlite3.Connection, table: str, rows: list[dict]) -> bool:
    if not rows:
        return False
    # Dedupe columns case-insensitively (SQLite column names ignore case).
    cols: list[str] = []
    seen: set[str] = set()
    for r in rows:
        for k in r:
            lk = k.lower()
            if lk not in seen:
                seen.add(lk)
                cols.append(k)
    q = lambda c: '"' + c.replace('"', '') + '"'  # noqa: E731
    conn.execute(f"CREATE TABLE {table} ({', '.join(q(c) for c in cols)})")
    conn.executemany(
        f"INSERT INTO {table} ({', '.join(q(c) for c in cols)}) VALUES ({', '.join(['?'] * len(cols))})",
        [[r.get(c) for c in cols] for r in rows],
    )
    return True


_MISSING_COL = re.compile(r"no such column: (\S+)")


def _run_rule(conn: sqlite3.Connection, sql: str) -> tuple[list[str], list[tuple]]:
    """Run a rule; if it references a column the data lacks, add it (NULL) and
    retry so other OR-branches can still match. Returns (columns, matching rows)."""
    for _ in range(40):
        try:
            cur = conn.execute(sql)
            return [d[0] for d in cur.description], cur.fetchall()
        except sqlite3.OperationalError as e:
            m = _MISSING_COL.search(str(e))
            if not m:
                return [], []
            col = m.group(1).split(".")[-1].strip('"')
            table = sql.split(" FROM ", 1)[1].split()[0]
            try:
                conn.execute(f'ALTER TABLE {table} ADD COLUMN "{col}"')
            except sqlite3.OperationalError:
                return [], []
    return [], []


def run(ctx) -> None:
    base = root(ctx.evidence)
    logdir = base / "var" / "log"
    auditd_rows = _parse_auditd(iter_log_lines(logdir / "audit" / "audit.log")) if logdir.is_dir() else []
    syslog_files = {f for g in _SYSLOG_GLOBS for f in logdir.glob(g)
                    if f.is_file() and f.suffix.lower() != ".xz" and not _ARCHIVE.search(f.name)} \
        if logdir.is_dir() else set()
    # Smallest first: auth.log/secure are read whole; the giant `messages` only
    # gets whatever budget is left (as its tail = most recent lines).
    syslog_rows: list[dict] = []
    for f in sorted(syslog_files, key=lambda p: p.stat().st_size):
        budget = _SYSLOG_MAX_LINES - len(syslog_rows)
        if budget <= 0:
            break
        for ln in tail_lines(f, budget):
            if ln.strip():
                syslog_rows.append(_syslog_row(ln))

    detections: list[list] = []
    if auditd_rows or syslog_rows:
        conn = sqlite3.connect(":memory:")
        try:
            have_auditd = _load_table(conn, "auditd", auditd_rows)
            have_syslog = _load_table(conn, "syslog", syslog_rows)
            for r in load_rules():
                if (r.table == "auditd" and not have_auditd) or (r.table == "syslog" and not have_syslog):
                    continue
                cols, matches = _run_rule(conn, r.sql)
                for row in matches:
                    rec = dict(zip(cols, row))
                    ts = rec.get("_ts") or rec.get("timestamp") or ""
                    summary = (rec.get("CommandLine") or rec.get("message") or "")[:300]
                    detections.append([r.level, r.title, r.table, r.tags, ts, summary, r.rule_id])
        finally:
            conn.close()
    # most severe first
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    detections.sort(key=lambda d: _order.get(d[0], 9))
    write_csv(ctx.out, "sigma_detections.csv",
              ["level", "rule", "source", "mitre", "timestamp", "match", "rule_id"], detections)
