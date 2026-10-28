"""Handler: auditd's own record of who did what. Output: art_log_auditd.csv

Five of six real Linux hosts kept audit.log and only `alert_log_sigma` read it, and only
its newest 500,000 lines. What it holds and nothing else does:

  auid      the LOGIN uid. It is set at login and survives `su` and `sudo`, so a
            command run as root still names the person behind it -- auth.log
            names root.
  USER_CMD  every sudo command, decoded, with that auid.
  USER_LOGIN / USER_AUTH  logins and authentications, success or failure, with
            the source address, from every PAM service -- not only sshd.
  ADD_USER / DEL_USER / USER_MGMT / USER_CHAUTHTOK  account changes.
  CONFIG_CHANGE / DAEMON_*  the audit system itself being changed or stopped.
  SYSCALL   a rule's hit (`key` names the rule), with the process's command
            line from PROCTITLE / EXECVE and its cwd.
  TTY / USER_TTY  keystrokes, where pam_tty_audit is on.
  AVC       an SELinux/AppArmor denial.
  ANOM_*    the kernel's own anomaly reports (promiscuous mode, crashes).

Service start/stop, credential refresh and session bookkeeping are left out:
they are most of the file and say nothing about a person.

One row per event (the records of one serial joined), every rotation, oldest
first. `suspicious` marks two things only: the audit system weakened (a rule
removed, auditing disabled, the daemon aborted -- not a DAEMON_END, which every
clean shutdown writes), and a sudo command run from a staging directory.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.handlers._auditd import AUDIT, SYSCALLS, kv, unhex
from artifact_engine.handlers._lincommon import iter_log_lines, read_lines, root, sort_rotations, stream_csv

HEADER = ["time_utc", "serial", "type", "auid", "uid", "account", "exe", "command",
          "terminal", "addr", "result", "key", "detail", "suspicious"]

_PEOPLE = {"USER_LOGIN", "USER_AUTH", "USER_CMD", "USER_LOGOUT", "ADD_USER", "DEL_USER",
           "ADD_GROUP", "DEL_GROUP", "USER_MGMT", "GRP_MGMT", "USER_CHAUTHTOK",
           "GRP_CHAUTHTOK", "USER_ROLE_CHANGE", "ROLE_ASSIGN", "ROLE_REMOVE",
           "CONFIG_CHANGE", "DAEMON_START", "DAEMON_END", "DAEMON_ABORT",
           "DAEMON_CONFIG", "TTY", "USER_TTY", "AVC", "USER_AVC", "SYSCALL"}
_STAGING = ("/tmp/", "/var/tmp/", "/dev/shm/")
_UNSET = "4294967295"


def _passwd(base: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in read_lines(base / "etc" / "passwd"):
        parts = line.split(":")
        if len(parts) >= 3 and parts[2].isdigit():
            out[parts[2]] = parts[0]
    return out


def _name(uid: str, enriched: str, users: dict[str, str]) -> str:
    """`1000 (jdoe)`, `unset`, or the bare number when nobody is known."""
    if not uid or uid in ("-1", _UNSET):
        return "unset" if uid else ""
    who = enriched or users.get(uid, "")
    return f"{uid} ({who})" if who else uid


def _tampering(rtype: str, f: dict) -> bool:
    """The audit system itself weakened: a rule removed, auditing switched off,
    the daemon aborted. A DAEMON_END is every clean shutdown, so it is context."""
    if rtype == "DAEMON_ABORT":
        return True
    return rtype == "CONFIG_CHANGE" and ("remove" in f.get("op", "")
                                         or f.get("audit_enabled") == "0")


def _record(rest: str) -> tuple[dict, dict]:
    """(fields, enriched names) of one record; a user-space record's `msg='...'`
    is opened into the same dict."""
    body, _, enr = rest.partition("\x1d")
    fields = kv(body)
    inner = fields.pop("msg", None)
    if inner:
        fields.update(kv(inner))
    return fields, kv(enr) if enr else {}


def _event(recs: list[tuple[str, dict, dict]], users: dict[str, str]) -> list | None:
    types = [t for t, _, _ in recs]
    head = next(((t, f, e) for t, f, e in recs if t in _PEOPLE or t.startswith("ANOM_")), None)
    if head is None:
        return None
    rtype, f, e = head
    command = ""
    if "PROCTITLE" in types:
        raw = next(fx for t, fx, _ in recs if t == "PROCTITLE").get("proctitle", "")
        command = unhex(raw).replace("\x00", " ").strip()
    if "EXECVE" in types and not command:
        ex = next(fx for t, fx, _ in recs if t == "EXECVE")
        try:
            argc = int(ex.get("argc", "0"))
        except ValueError:
            argc = 0
        command = " ".join(unhex(ex[f"a{i}"]) for i in range(argc) if f"a{i}" in ex)
    if rtype == "USER_CMD":
        command = unhex(f.get("cmd", ""))
    elif rtype in ("TTY", "USER_TTY"):
        command = unhex(f.get("data", ""))

    detail = []
    if rtype == "SYSCALL":
        num = f.get("syscall", "")
        detail.append(f"syscall={SYSCALLS.get(num, num)}")
        if f.get("success"):
            detail.append(f"success={f['success']}")
        cwd = next((fx.get("cwd", "") for t, fx, _ in recs if t == "CWD"), "")
        if cwd:
            detail.append(f"cwd={unhex(cwd)}")
        paths = [unhex(fx.get("name", "")) for t, fx, _ in recs if t == "PATH" and fx.get("name")]
        if paths:
            detail.append("path=" + ",".join(paths[:4]))
    for k in ("op", "list", "audit_enabled", "old", "operation", "profile", "name",
              "denied_mask", "requested_mask", "info", "dev", "prom", "old_prom"):
        if k in f and not (rtype == "SYSCALL" and k == "name"):
            detail.append(f"{k}={unhex(f[k]) if k == 'name' else f[k]}")

    result = f.get("res", "")
    if rtype == "SYSCALL" and not result:
        result = "success" if f.get("success") == "yes" else ("failed" if f.get("success") else "")
    sus = "yes" if _tampering(rtype, f) or (
        rtype == "USER_CMD" and command.split(" ", 1)[0].startswith(_STAGING)) else ""
    return [
        "", "", rtype,
        _name(f.get("auid", ""), e.get("AUID", ""), users),
        _name(f.get("uid", ""), e.get("UID", ""), users),
        unhex(f.get("acct", "")), unhex(f.get("exe", "") or f.get("comm", "")),
        command[:500], f.get("terminal", "") or f.get("tty", ""),
        f.get("addr", "") if f.get("addr", "") not in ("?", "") else "",
        result, unhex(f.get("key", "")) if f.get("key", "") not in ("(null)", "") else "",
        " ".join(detail), sus,
    ]


def _file_events(path: Path, users: dict[str, str]):
    """Events of one audit.log, in order. Serials are unique only within a file."""
    groups: dict[str, list] = {}
    when: dict[str, str] = {}
    order: list[str] = []
    for ln in iter_log_lines(path):
        m = AUDIT.match(ln)
        if not m:
            continue
        rtype, ts, serial, rest = m.groups()
        fields, enriched = _record(rest)
        if serial not in groups:
            groups[serial] = []
            when[serial] = ts
            order.append(serial)
        groups[serial].append((rtype, fields, enriched))
    for serial in order:
        row = _event(groups.pop(serial), users)
        if row is None:
            continue
        row[0] = datetime.fromtimestamp(float(when[serial]), timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S")
        row[1] = serial
        yield row


def run(ctx) -> None:
    base = root(ctx.evidence)
    d = base / "var" / "log" / "audit"
    files = sort_rotations(f for f in d.glob("audit.log*") if f.is_file()) if d.is_dir() else []
    if not files:
        return
    users = _passwd(base)
    with stream_csv(ctx.out, "art_log_auditd.csv", HEADER) as emit:
        for f in files:
            for row in _file_events(f, users):
                emit(row)
