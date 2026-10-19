"""Handler: run the bundled SigmaHQ Linux ruleset over the raw UAC logs.

Reads the acquisition's own sources (NOT the consolidated .db):
  - auditd  ([root]/var/log/audit/audit.log*)  -> flattened "auditd" table
  - syslog  (auth.log/syslog/messages/secure*) -> "syslog" table (full line)
  - shell histories and live_response `ps`     -> "process" table (v0.7.166)

Each Sigma rule is compiled to a SQLite query (see core.sigma_engine) and run
against its table; matches become rows in log_sigma.csv. auditd EXECVE
records are enriched with synthesised Image/CommandLine/User so process_creation
rules match; the raw line (plus decoded cmdline) is kept in `message` for the
keyword rules.

The `process_creation` rules -- most of the ruleset -- fired only where auditd
logged EXECVE, which the measured hosts never had. Since v0.7.166 they also run
over a `process` table of what the host DID run, with the rows marked by source:
each command of every shell history (`shell_history`; a line is split into the
commands it chains with `|`, `;`, `&&`, `||`) and each process UAC's `ps`
captured (`processes`, with its parent from `/proc`). Only those rules read that
table: the keyword and auditd-record rules never see a typed command -- nor do
the `informational` ones, which SigmaHQ marks as context, not alerts: on a
four-host UAC case they were 95 of 167 new rows, every `rm` a "File Deletion". A history
says which command was typed, not which binary ran, so a bare name is written
`Image` = `/name`, the form `Image|endswith: '/curl'` rules expect.

One row per distinct match, not per line: a rule that fires on the same message
over and over (root's crontab REPLACEd by a job every few minutes was 1,400 rows
of "Modifying Crontab" on one host) is one row with its `count` and the first
and last `timestamp`. Distinct means same rule and same text once the line's
own time and pid are taken out.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime

from artifact_engine.core.sigma_engine import _retable, load_rules
from artifact_engine.handlers._lincommon import (
    live_response,
    read_lines,
    root,
    sort_rotations,
    tail_lines,
    write_csv,
)
from artifact_engine.handlers.lin_bash import iter_history_timed
from artifact_engine.handlers.lin_proc_identity import exe_by_pid, pid_dirs, read_status
from artifact_engine.handlers.lin_process_network import _parse_ps_lstart

# auditd record: "type=X msg=audit(<ts>:<serial>): <rest>"
_AUDIT = re.compile(r"^type=(\S+)\s+msg=audit\(([\d.]+):(\d+)\):\s*(.*)$")
_KV = re.compile(r"(\w+)=(?:\"([^\"]*)\"|'([^']*)'|(\S+))")
# syslog: "<ts> <host> <proc>[pid]: <msg>"
_SYS = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.+\-]+|[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_SYSLOG_GLOBS = ("auth.log*", "syslog*", "messages*", "secure*")
# Dated archives (messages-20260331.xz) stay OUT here, deliberately, and this is
# the one handler where that is still right. `lin_auth` reads every rotation
# because it streams and emits only classified lines; this one loads rows into an
# in-memory SQLite table for the rules to query, so its cost is the row count, and
# it spends a fixed budget from the NEWEST line backwards. Handing it a year of
# archive would not widen the window -- the budget would still be spent on the
# most recent lines, only after paying to decompress everything behind them.
#
# Widening this needs a time window (--since), not a wider pattern: with one, the
# budget can be spent inside the window instead of at the end of the file. Until
# then, `auth_log.csv` is where the deep history lives and this is the recent view.
_ARCHIVE = re.compile(r"-\d{8}")
# Keep the most RECENT N syslog lines (read from EOF). Small files (auth/secure)
# are taken whole first so a multi-GB `messages` can't crowd out the auth log.
_SYSLOG_MAX_LINES = 500_000
# The same ceiling for auditd, and for the same reason: a host with audit rules
# loaded writes hundreds of MB of audit.log, every line of which would become a
# dict, then a row, then an in-memory SQLite row. Newest rotation first, so the
# budget buys recent activity.
_AUDITD_MAX_LINES = 500_000

_PID = re.compile(r"\[\d+\]")

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


_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_DELETED = " (deleted)"


def _scan(line: str) -> tuple[list[str], list[str]]:
    """One pass over a shell line: (the commands it chains at the top level, the
    bodies of its `$(...)`, backquotes and `(...)`). Separators are `|`, `;`, `&`,
    `&&`, `||`, `|&` outside quotes and groups; `2>&1`, `&>` and `>|` are
    redirections; an unquoted `#` starting a word ends the line (a comment);
    `$((...))` is arithmetic, not a command."""
    out: list[str] = []
    bodies: list[str] = []
    cur: list[str] = []
    stack: list[tuple[str, int]] = []      # open groups: (closer, body start)
    quote = ""
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if quote:
            cur.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                cur.append(line[i + 1])
                i += 1
            elif c == quote:
                quote = ""
                if c == "`" and stack and stack[-1][0] == "`":
                    _, start = stack.pop()
                    bodies.append(line[start:i])
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            cur.extend(line[i:i + 2])
            i += 2
            continue
        if c == "#" and (i == 0 or line[i - 1].isspace()) and not stack:
            break
        if c in "'\"":
            quote = c
        elif c == "`":
            quote = c
            stack.append(("`", i + 1))
        elif line.startswith("$((", i):
            stack.append(("))", -1))           # arithmetic: tracked, not a command
            cur.append("$((")
            i += 3
            continue
        elif c == "(":
            stack.append((")", i + 1))
        elif c == ")" and stack:
            closer, start = stack.pop()
            if closer == "))" and line.startswith("))", i):
                cur.append("))")
                i += 2
                continue
            if start >= 0:
                bodies.append(line[start:i])
        elif not stack and c in "|;&" \
                and not (c == "&" and (line[i - 1:i] in ("<", ">") or line[i + 1:i + 2] == ">")) \
                and not (c == "|" and line[i - 1:i] == ">"):
            # `&&`, `||` and `|&` are one separator
            if line[i + 1:i + 2] == c or (c == "|" and line[i + 1:i + 2] == "&"):
                i += 1
            out.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    out.append("".join(cur).strip())
    return [c for c in out if c], bodies


def _commands(line: str, _depth: int = 0) -> list[str]:
    """The commands one shell line runs: those it chains (`_scan`), then those
    inside its `$(...)`, backquotes and `(...)`, which run too -- the `curl` in
    `out=$(curl -s http://x)` is a process, though the line's first word is an
    assignment."""
    top, bodies = _scan(line)
    # a bare subshell `( ... )` runs nothing but its commands, listed below
    top = [c for c in top if not (c.startswith("(") and c.endswith(")"))]
    if _depth < 8:
        for body in bodies:
            top.extend(_commands(body, _depth + 1))
    return top


def _words(command: str) -> list[str]:
    """`command` split on the whitespace outside quotes and groups."""
    words: list[str] = []
    cur: list[str] = []
    quote = ""
    depth = 0
    for c in command:
        if quote:
            cur.append(c)
            if c == quote:
                quote = ""
        elif c in "'\"`":
            quote = c
            cur.append(c)
        elif c == "(":
            depth += 1
            cur.append(c)
        elif c == ")":
            depth = max(0, depth - 1)
            cur.append(c)
        elif c.isspace() and not depth:
            if cur:
                words.append("".join(cur))
                cur = []
        else:
            cur.append(c)
    if cur:
        words.append("".join(cur))
    return words


def _image(command: str) -> str:
    """The program a command runs, as a path -- `/name` for a bare name (see the
    module docstring): its first word after any `VAR=value`; for a subshell
    `(...)` or a `{ ...; }` group, its first command's."""
    for word in _words(command):
        if _ASSIGN.match(word):
            continue
        if word.startswith(("(", "{")):
            inner = _commands(command.strip()[1:].rstrip(")} "))
            return _image(inner[0]) if inner else ""
        word = word.strip("'\"")
        return word if "/" in word else "/" + word
    return ""


def _lstart(value: str) -> str:
    """`ps` lstart (`Tue Nov 14 22:13:20 2023`, the host's local time) as
    `2023-11-14 22:13:20`, so it sorts; the text as it was if it is not one."""
    try:
        # the host's local time, kept local: only its format changes
        return datetime.strptime(value, "%a %b %d %H:%M:%S %Y").strftime(  # noqa: DTZ007
            "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


def _process_rows(base, evidence) -> list[dict]:
    """The `process` table: shell-history commands and the processes `ps` saw."""
    rows: list[dict] = []
    for user, _shell, _seq, when, line in iter_history_timed(base):
        for command in _commands(line):
            rows.append({"_src": "shell_history", "timestamp": when, "User": user,
                         "Image": _image(command), "CommandLine": command,
                         "ParentImage": "", "ParentCommandLine": "", "message": line})
    lr = live_response(evidence)
    if lr is None:
        return rows
    ps: list[list] = []
    _parse_ps_lstart(read_lines(lr / "process" / "ps_-axo_pid_user_lstart_args.txt"), ps)
    exes = {pid: exe.removesuffix(_DELETED).strip() for pid, exe in exe_by_pid(lr).items()}
    ppid = {d.name: read_status(d / "status.txt").get("PPid", "")
            for d in pid_dirs(lr / "process" / "proc")}
    cmd = {pid: command for pid, _user, _started, command in ps}
    for pid, user, started, command in ps:
        parent = ppid.get(pid, "")
        rows.append({"_src": "processes", "timestamp": _lstart(started), "User": user,
                     "Image": exes.get(pid) or _image(command), "CommandLine": command,
                     "ParentImage": exes.get(parent) or _image(cmd.get(parent, "")),
                     "ParentCommandLine": cmd.get(parent, ""), "message": command})
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
    q = lambda c: '"' + c.replace('"', '') + '"'
    conn.execute(f"CREATE TABLE {table} ({', '.join(q(c) for c in cols)})")
    conn.executemany(                          # generator: don't copy every row again
        f"INSERT INTO {table} ({', '.join(q(c) for c in cols)}) VALUES ({', '.join(['?'] * len(cols))})",
        ([r.get(c) for c in cols] for r in rows),
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
    # auditd: newest rotation first, each file's tail, until the budget is spent.
    # Parsed per file because the audit serial that groups an event's records is
    # only unique within one file.
    audit_dir = logdir / "audit"
    auditd_rows: list[dict] = []
    audit_files = sort_rotations(f for f in audit_dir.glob("audit.log*") if f.is_file()) \
        if audit_dir.is_dir() else []
    for f in reversed(audit_files):
        budget = _AUDITD_MAX_LINES - len(auditd_rows)
        if budget <= 0:
            break
        auditd_rows.extend(_parse_auditd(tail_lines(f, budget)))
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

    process_rows = _process_rows(base, ctx.evidence)

    # (rule_id, source, text) -> [level, title, source, tags, first, last, count, match, rule_id]
    detections: dict[tuple[str, str], list] = {}
    if auditd_rows or syslog_rows or process_rows:
        conn = sqlite3.connect(":memory:")
        try:
            have = {"auditd": _load_table(conn, "auditd", auditd_rows),
                    "syslog": _load_table(conn, "syslog", syslog_rows),
                    "process": _load_table(conn, "process", process_rows)}
            for r in load_rules():
                runs = [(r.table, r.sql)] if have.get(r.table) else []
                if (r.category == "process_creation" and have["process"]
                        and r.level != "informational"):
                    runs.append(("process", _retable(r.sql, "process")))
                for table, sql in runs:
                    cols, matches = _run_rule(conn, sql)
                    for row in matches:
                        rec = dict(zip(cols, row))
                        ts = rec.get("_ts") or rec.get("timestamp") or ""
                        summary = (rec.get("CommandLine") or rec.get("message") or "")[:300]
                        source = rec.get("_src") or table
                        # per source: a typed command and a running process are two
                        # facts, and their times are not on the same basis
                        key = (r.rule_id, source,
                               _PID.sub("", summary.replace(ts, "", 1) if ts else summary))
                        d = detections.get(key)
                        if d is None:
                            detections[key] = [r.level, r.title, source, r.tags,
                                               ts, ts, 1, summary, r.rule_id]
                        elif table == "process":
                            # rows come user by user, then by PID: not in time
                            # order, so first and last are the earliest and latest
                            if ts:
                                d[4] = min(d[4], ts) if d[4] else ts
                                d[5] = max(d[5], ts) if d[5] else ts
                            d[6] += 1
                        else:
                            d[5] = ts or d[5]
                            d[6] += 1
        finally:
            conn.close()
    # most severe first
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rows = sorted(detections.values(), key=lambda d: _order.get(d[0], 9))
    write_csv(ctx.out, "log_sigma.csv",
              ["level", "rule", "source", "mitre", "timestamp", "last_timestamp", "count",
               "match", "rule_id"], rows)
