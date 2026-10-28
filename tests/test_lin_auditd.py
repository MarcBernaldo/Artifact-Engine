"""v0.7.148: art_log_auditd.csv -- auditd's record of who did what. Synthetic
audit.log lines; users, hosts and addresses are invented."""
from __future__ import annotations

import csv
import logging
from pathlib import Path
from types import SimpleNamespace

from artifact_engine.handlers import lin_auditd

PASSWD = "root:x:0:0:root:/root:/bin/bash\njdoe:x:1000:1000::/home/jdoe:/bin/bash\n"


def _hex(s: str) -> str:
    return s.encode().hex().upper()


OLD = (
    # a session-bookkeeping record: left out
    "type=SERVICE_START msg=audit(1700000000.100:10): pid=1 uid=0 auid=4294967295 "
    "ses=4294967295 msg='unit=cron comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" res=success'\n"
    # an ssh login failure with its source address
    "type=USER_LOGIN msg=audit(1700000001.200:11): pid=900 uid=0 auid=4294967295 "
    "ses=4294967295 msg='op=login acct=\"admin\" exe=\"/usr/sbin/sshd\" hostname=? "
    "addr=10.0.0.7 terminal=sshd res=failed'\n"
)
NEW = (
    # sudo by jdoe of a script in /tmp; cmd is hex because it holds a space
    "type=USER_CMD msg=audit(1700000100.000:20): pid=1200 uid=1000 auid=1000 ses=3 "
    f"msg='cwd=\"/home/jdoe\" cmd={_hex('/tmp/.x/run.sh -q')} exe=\"/usr/bin/sudo\" "
    "terminal=pts/0 res=success'\n"
    # a rule hit: SYSCALL + PROCTITLE + CWD + PATH of one serial, enriched names
    "type=SYSCALL msg=audit(1700000200.000:21): arch=c000003e syscall=59 success=yes "
    "exit=0 a0=1 a1=2 a2=3 a3=4 items=1 ppid=1 pid=1300 auid=1001 uid=0 gid=0 euid=0 "
    "tty=pts/0 ses=3 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"shadow_read\"\x1dARCH=x86_64 "
    "SYSCALL=execve AUID=\"asmith\" UID=\"root\"\n"
    "type=CWD msg=audit(1700000200.000:21): cwd=\"/root\"\n"
    "type=PATH msg=audit(1700000200.000:21): item=0 name=\"/etc/shadow\" inode=1 nametype=NORMAL\n"
    f"type=PROCTITLE msg=audit(1700000200.000:21): proctitle={_hex('cat' + chr(0) + '/etc/shadow')}\n"
    # an audit rule removed: tampering
    "type=CONFIG_CHANGE msg=audit(1700000300.000:22): auid=1000 ses=3 op=remove_rule "
    "key=\"shadow_read\" list=4 res=1\n"
    # a clean shutdown: context, not a finding
    "type=DAEMON_END msg=audit(1700000400.000:23): op=terminate auid=0 pid=1 res=success\n"
    "type=DAEMON_ABORT msg=audit(1700000500.000:24): op=abort auid=0 pid=1 res=failed\n"
)


def _rows(tmp_path: Path) -> list[dict]:
    ev = tmp_path / "ev"
    audit = ev / "[root]" / "var" / "log" / "audit"
    audit.mkdir(parents=True)
    (ev / "[root]" / "etc").mkdir(parents=True)
    (ev / "[root]" / "etc" / "passwd").write_text(PASSWD, encoding="utf-8")
    # serial 21 also exists in the rotated file: serials are per file
    (audit / "audit.log.1").write_text(
        OLD + "type=USER_AUTH msg=audit(1700000002.000:21): pid=900 uid=0 auid=4294967295 "
        "ses=4294967295 msg='op=PAM:authentication acct=\"admin\" exe=\"/usr/sbin/sshd\" "
        "addr=10.0.0.7 terminal=ssh res=failed'\n", encoding="utf-8")
    (audit / "audit.log").write_text(NEW, encoding="utf-8")
    lin_auditd.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=logging.getLogger("t")))
    with open(tmp_path / "out" / "art_log_auditd.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_events_in_time_order_with_bookkeeping_left_out(tmp_path):
    rows = _rows(tmp_path)
    assert [(r["time_utc"], r["serial"], r["type"]) for r in rows] == [
        ("2023-11-14 22:13:21", "11", "USER_LOGIN"),
        ("2023-11-14 22:13:22", "21", "USER_AUTH"),
        ("2023-11-14 22:15:00", "20", "USER_CMD"),
        ("2023-11-14 22:16:40", "21", "SYSCALL"),
        ("2023-11-14 22:18:20", "22", "CONFIG_CHANGE"),
        ("2023-11-14 22:20:00", "23", "DAEMON_END"),
        ("2023-11-14 22:21:40", "24", "DAEMON_ABORT"),
    ]


def test_a_login_failure_keeps_account_address_and_result(tmp_path):
    r = _rows(tmp_path)[0]
    assert (r["auid"], r["account"], r["exe"], r["addr"], r["terminal"], r["result"]) == (
        "unset", "admin", "/usr/sbin/sshd", "10.0.0.7", "sshd", "failed")


def test_sudo_names_the_person_and_decodes_the_command(tmp_path):
    r = [r for r in _rows(tmp_path) if r["type"] == "USER_CMD"][0]
    assert (r["auid"], r["uid"], r["command"], r["suspicious"]) == (
        "1000 (jdoe)", "1000 (jdoe)", "/tmp/.x/run.sh -q", "yes")


def test_a_rule_hit_joins_its_records_and_uses_the_enriched_names(tmp_path):
    """uid 1001 is in no passwd here: only the enriched AUID can name it."""
    r = [r for r in _rows(tmp_path) if r["type"] == "SYSCALL"][0]
    assert (r["auid"], r["uid"], r["exe"], r["command"], r["key"], r["result"]) == (
        "1001 (asmith)", "0 (root)", "/usr/bin/cat", "cat /etc/shadow", "shadow_read", "success")
    assert r["detail"] == "syscall=execve success=yes cwd=/root path=/etc/shadow"


def test_only_a_weakened_audit_system_is_suspicious(tmp_path):
    got = {r["type"]: r["suspicious"] for r in _rows(tmp_path)}
    assert got["CONFIG_CHANGE"] == "yes" and got["DAEMON_ABORT"] == "yes"
    assert got["DAEMON_END"] == "" and got["USER_LOGIN"] == "" and got["SYSCALL"] == ""


def test_no_audit_log_writes_nothing(tmp_path):
    ev = tmp_path / "ev"
    (ev / "[root]" / "var" / "log").mkdir(parents=True)
    lin_auditd.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=logging.getLogger("t")))
    assert not (tmp_path / "out" / "art_log_auditd.csv").exists()

def test_an_interface_put_into_promiscuous_mode_is_suspicious(tmp_path):
    """A sniffer, unless the interface is a bridge port or a container's veth --
    the kernel puts those there itself. Leaving promiscuous mode (`prom=0`) is not."""
    ev = tmp_path / "ev"
    audit = ev / "[root]" / "var" / "log" / "audit"
    audit.mkdir(parents=True)
    line = ("type=ANOM_PROMISCUOUS msg=audit(1700000{}.000:{}): dev={} prom={} old_prom={} "
            "auid=1000 uid=0 gid=0 ses=3\n")
    (audit / "audit.log").write_text(
        line.format(600, 30, "ens192", 256, 0) + line.format(601, 31, "ens192", 0, 256)
        + line.format(602, 32, "veth1a2b3c", 256, 0) + line.format(603, 33, "docker0", 256, 0),
        encoding="utf-8")
    lin_auditd.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=logging.getLogger("t")))
    with open(tmp_path / "out" / "art_log_auditd.csv", encoding="utf-8", newline="") as fh:
        got = [(r["serial"], r["suspicious"]) for r in csv.DictReader(fh)]
    assert got == [("30", "yes"), ("31", ""), ("32", ""), ("33", "")]
