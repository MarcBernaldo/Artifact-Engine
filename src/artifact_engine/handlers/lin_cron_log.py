"""Handler: cron execution log (/var/log/cron). Output: cron_log.csv

The `cron` parser reads the CONFIG (what is scheduled); this reads the RHEL
/var/log/cron execution log (+rotations): what actually ran and when, plus
the moments a crontab was modified - the timeline that ties a persistence
entry to its installation and executions. Three row kinds:

  exec              CROND/CRON "(user) CMD (command)" - every job execution
  crontab_<action>  crontab "(user) ACTION (target)" - REPLACE is the moment
                    persistence was (re)installed; EDIT/DELETE/LIST kept too
  reload            crond "(user) RELOAD (path)" - the spool file changed

run-parts/anacron start/finish chatter is dropped (the CROND row already
records the execution). `suspicious` flags jobs executing out of a staging
dir; crontab modifications are routine admin work, so they are surfaced by
kind, not flagged. Timestamp is as-logged (syslog, host-local, no year).
"""

from __future__ import annotations

import re

from artifact_engine.handlers._lincommon import iter_log_lines, root, write_csv

_SYSLOG = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\S+T\S+)\s+\S+\s+"
    r"([\w./-]+)(?:\[\d+\])?:\s+(.*)$"
)
_CMD = re.compile(r"^\((\S+)\) CMD \((.*)\)\s*$")
_TAB = re.compile(r"^\((\S+)\) (?:BEGIN )?(EDIT|REPLACE|DELETE|LIST) \((\S+)\)\s*$")
_RELOAD = re.compile(r"^\((\S+)\) RELOAD \((.*)\)\s*$")

_STAGING = ("/tmp/", "/var/tmp/", "/dev/shm/")


def _susp_exec(command: str) -> str:
    exe = command.strip().split(None, 1)[0] if command.strip() else ""
    return "yes" if exe.startswith(_STAGING) else ""


def _parse(lines, rows: list[list]) -> None:
    for ln in lines:
        m = _SYSLOG.match(ln)
        if not m:
            continue
        ts, tag, msg = m.groups()
        tag_l = tag.lower()
        if "crontab" in tag_l:
            t = _TAB.match(msg)
            if t:
                user, action, target = t.groups()
                rows.append([ts, f"crontab_{action.lower()}", user, target, ""])
        elif "cron" in tag_l:                      # CROND / crond / /USR/SBIN/CRON
            c = _CMD.match(msg)
            if c:
                user, command = c.groups()
                rows.append([ts, "exec", user, command.strip(), _susp_exec(command)])
                continue
            r = _RELOAD.match(msg)
            if r:
                user, path = r.groups()
                rows.append([ts, "reload", user, path, ""])
        # anything else (run-parts/anacron chatter, daemon start) is noise


def run(ctx) -> None:
    log_dir = root(ctx.evidence) / "var" / "log"
    files = [f for f in sorted(log_dir.glob("cron*")) if f.is_file()] if log_dir.is_dir() else []
    if not files and log_dir.is_dir():
        # Debian has no /var/log/cron: cron logs to syslog (the tag filter in
        # _parse keeps only cron lines). RHEL routes cron.* away from messages,
        # so the two sources never overlap; SUSE's `messages` is skipped on
        # purpose (log hosts carry GBs of rotations for a handful of cron lines).
        files = [f for f in sorted(log_dir.glob("syslog*")) if f.is_file()]
    rows: list[list] = []
    for f in files:
        _parse(iter_log_lines(f), rows)
    write_csv(ctx.out, "cron_log.csv",
              ["timestamp", "kind", "user", "detail", "suspicious"], rows)
