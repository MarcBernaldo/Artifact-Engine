"""Handler: security-relevant authentication events (Linux). Output: auth.csv

Scans the syslog-style auth logs for SSH logins (ok/failed/invalid user), sudo,
su and account creation. Only the first existing distro family is read -
auth.log (Debian/Ubuntu) -> secure (RHEL) -> messages (SUSE) - so the general
`messages` syslog (gigabytes on a log host) is never scanned when a dedicated
auth log exists.

EVERY rotation of that family is read, in both logrotate conventions. Dated
archives (`messages-20260519.xz`) used to be skipped as "deep archives", which
on a dateext distro is every archive there is: the parser saw the hours since
the last rotation and nothing else, so a case worked a week after the intrusion
had an auth.csv that started after it. The window is the point of the artifact.

What that costs is time, not memory: the file set streams, and only classified
lines (sshd/sudo/su/useradd) become rows, so three months of syslog is a few
thousand rows and a few minutes of decompression. A file set large enough for
that to be noticeable says so on the console rather than looking hung.
"""

from __future__ import annotations

import re
from collections import deque

from artifact_engine.handlers._lincommon import (
    iter_log_lines,
    root,
    sort_rotations,
    stream_csv,
)

# How many recent rows are remembered to drop the repeats an overlapping rotation
# (logrotate `copytruncate`) leaves behind. Files are read oldest-first, so those
# repeats sit next to each other and a window catches them; remembering every
# event instead would grow with the log, and the log grows at the attacker's
# pace - one line per failed SSH attempt. Past the window a repeat of the exact
# same second/user/source can slip through as a second row, which is the cheap
# side of the trade.
_DEDUPE_WINDOW = 100_000

# syslog line: "<ts> <host> <proc>[pid]: <msg>". ts is ISO8601 or legacy "Mon DD HH:MM:SS".
_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.+\-]+|[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
# Auth log family by distro, in priority order: only the first that exists is
# scanned. On RHEL/SUSE `messages` is the general syslog (can be gigabytes on a
# log host) - auth events there live in `secure`, so we never scan `messages`
# when `auth.log`/`secure` exist. Within the family that does exist, every
# rotation is read: both `.1/.2.gz` and `-YYYYMMDD.xz`.
_LOG_FAMILIES = ("auth.log*", "secure*", "messages*")

# Reading every rotation is the point (see the module docstring), but on a host
# that kept a year of `messages` it is also the difference between seconds and
# minutes. Past this much the run says so, once. It does NOT read less: a cap
# here would have to guess which end of the archive the incident is in, and it
# would guess the recent end -- which is the end the analyst already has.
_LOUD_BYTES = 200_000_000

_SSH_OK = re.compile(r"Accepted (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)")
_SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)")
_SSH_INVALID = re.compile(r"Invalid user (\S+) from (\S+)")
_SUDO = re.compile(r"^(\S+)\s+:.*COMMAND=(.*)$")
_SU = re.compile(r"(?:session opened for user|FAILED su for|to) (\S+)")
_USERADD = re.compile(r"new user: name=(\S+?),")
_GROUPADD = re.compile(r"new group: name=(\S+?),")


def _user(tok: str) -> str:
    """Drop a trailing '(uid=0)' / '(uid=1000)' decoration from a user token."""
    return tok.split("(", 1)[0]


def _classify(proc: str, msg: str) -> tuple[str, str, str, str] | None:
    """Return (event, user, source, detail) for an interesting line, else None.

    Dispatch by program: each daemon only tests its own patterns so a generic
    pam_unix 'session opened' from sshd/cron isn't misread as su/sudo.
    """
    if proc == "sshd":
        m = _SSH_OK.search(msg)
        if m:
            return "ssh_accepted", m.group(2), m.group(3), f"{m.group(1)} port {m.group(4)}"
        m = _SSH_FAIL.search(msg)
        if m:
            return "ssh_failed", m.group(1), m.group(2), f"port {m.group(3)}"
        m = _SSH_INVALID.search(msg)
        if m:
            return "ssh_invalid_user", m.group(1), m.group(2), ""
        return None
    if proc == "sudo":
        m = _SUDO.search(msg)
        return ("sudo", m.group(1), "", m.group(2).strip()) if m else None
    if proc == "su":
        m = _SU.search(msg)
        if m:
            return ("su_failed" if "FAILED" in msg else "su"), _user(m.group(1)), "", ""
        return None
    if proc == "useradd":
        m = _USERADD.search(msg)
        return ("user_add", m.group(1), "", "") if m else None
    if proc == "groupadd":
        m = _GROUPADD.search(msg)
        return ("group_add", m.group(1), "", "") if m else None
    return None


def _auth_files(logdir):
    """First existing log family (auth.log -> secure -> messages), every rotation
    of it, oldest first."""
    for fam in _LOG_FAMILIES:
        fs = [f for f in logdir.glob(fam) if f.is_file()]
        if fs:
            return sort_rotations(fs)
    return []


def _total_bytes(files) -> int:
    """Size of the file set on disk, 0 for anything that will not stat."""
    total = 0
    for f in files:
        try:
            total += f.stat().st_size
        except OSError:
            continue
    return total


def run(ctx) -> None:
    logdir = root(ctx.evidence) / "var" / "log"
    files = _auth_files(logdir) if logdir.is_dir() else []
    if not files:
        return
    size = _total_bytes(files)
    if size >= _LOUD_BYTES:
        ctx.log.info(f"    auth: reading {len(files)} log file(s), "
                     f"{size / 1e6:.0f} MB on disk - this takes a few minutes")
    seen: set = set()             # de-duplicate across overlapping rotated files,
    recent: deque = deque()       # bounded: see _DEDUPE_WINDOW
    with stream_csv(ctx.out, "auth.csv",
                    ["timestamp", "host", "event", "user", "source", "detail"]) as emit:
        for f in files:
            for ln in iter_log_lines(f):
                m = _LINE.match(ln)
                if not m:
                    continue
                res = _classify(m.group("proc"), m.group("msg"))
                if not res:
                    continue
                event, user, source, detail = res
                key = (m.group("ts"), event, user, source, detail)
                if key in seen:
                    continue
                seen.add(key)
                recent.append(key)
                if len(recent) > _DEDUPE_WINDOW:
                    seen.discard(recent.popleft())
                emit([m.group("ts"), m.group("host"), event, user, source, detail])
