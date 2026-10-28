"""Handler: cron execution log (/var/log/cron, syslog or the journal). Output: art_log_cron.csv

The `tasks` parser reads the CONFIG (what is scheduled); this reads the RHEL
/var/log/cron execution log (+rotations), Debian's syslog, or the journal on a
host with neither (see below): what actually ran and when, plus
the moments a crontab was modified - the timeline that ties a persistence
entry to its installation and executions. Three row kinds:

  exec              CROND/CRON "(user) CMD (command)" - every job execution
  crontab_<action>  crontab "(user) ACTION (target)" - REPLACE is the moment
                    persistence was (re)installed; EDIT/DELETE/LIST kept too
  reload            crond "(user) RELOAD (path)" - the spool file changed

run-parts/anacron start/finish chatter is dropped (the CROND row already
records the execution). `suspicious` flags jobs executing out of a staging
dir; crontab modifications are routine admin work, so they are surfaced by
kind, not flagged. Timestamp is as-logged: host-local with no year from the
text logs, UTC with the offset written from the journal. `time_utc` (v0.7.147)
is the same moment in UTC for both (`_syslogtime`), empty when the host's zone
is unknown or a yearless line has no year bound (dateext name or `uac.log`).

No cron file and no syslog (Debian 12, cloud images, and hosts whose cron only
reaches `messages`): the journal's cron entries are read instead, timestamped
in UTC with the offset written (`_journal`).
"""

from __future__ import annotations

import re

from artifact_engine.handlers import _journal
from artifact_engine.handlers._lincommon import (
    iter_log_lines,
    root,
    sort_rotations,
    stream_csv,
)
from artifact_engine.handlers._syslogtime import Clock

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


def _parse(lines, emit) -> None:
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
                emit([ts, f"crontab_{action.lower()}", user, target, ""])
        elif "cron" in tag_l:                      # CROND / crond / /USR/SBIN/CRON
            c = _CMD.match(msg)
            if c:
                user, command = c.groups()
                emit([ts, "exec", user, command.strip(), _susp_exec(command)])
                continue
            r = _RELOAD.match(msg)
            if r:
                user, path = r.groups()
                emit([ts, "reload", user, path, ""])
        # anything else (run-parts/anacron chatter, daemon start) is noise


def _cron_program(ident: str) -> bool:
    """CRON (Debian), crond/CROND (RHEL), crontab -- the tags `_parse` keeps."""
    return "cron" in ident.lower()


def run(ctx) -> None:
    base = root(ctx.evidence)
    log_dir = base / "var" / "log"
    files = sort_rotations(f for f in log_dir.glob("cron*") if f.is_file()) \
        if log_dir.is_dir() else []
    if not files and log_dir.is_dir():
        # Debian has no /var/log/cron: cron logs to syslog (the tag filter in
        # _parse keeps only cron lines). RHEL routes cron.* away from messages,
        # so the two sources never overlap; SUSE's `messages` is skipped on
        # purpose (log hosts carry GBs of rotations for a handful of cron lines).
        files = sort_rotations(f for f in log_dir.glob("syslog*") if f.is_file())
    header = ["timestamp", "time_utc", "kind", "user", "detail", "suspicious"]
    clock = Clock(ctx.evidence)

    def timed(emit, bound):
        return lambda row: emit([row[0], clock.utc(row[0], bound), *row[1:]])

    if not files:
        with stream_csv(ctx.out, "art_log_cron.csv", header) as emit:   # no rows, no file
            _parse(_journal.syslog_lines(base, _cron_program), timed(emit, clock.bound(None)))
        return
    # Streamed, not buffered: one row per cron execution, times every rotation a
    # long-lived host kept - the row count follows the log, not the machine.
    with stream_csv(ctx.out, "art_log_cron.csv", header) as emit:
        for f in files:
            _parse(iter_log_lines(f), timed(emit, clock.bound(f)))
