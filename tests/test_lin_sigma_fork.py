"""v0.7.208: the Linux Sigma rules from the analyst's fork, and the file and network
rules over the engine's own tables (the bodyfile, the live response's sockets).
Values are invented: HOST-01, jdoe, 10.0.0.5, 203.0.113.7."""
from __future__ import annotations

import csv
import logging
import subprocess
import uuid
from pathlib import Path

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core import asset_state, downloader
from artifact_engine.core.downloader import drop_disk_sigma, sync_disk_sigma
from artifact_engine.core.runner import ParserContext
from artifact_engine.core.sigma_engine import load_rules
from artifact_engine.handlers import lin_sigma
from artifact_engine.registry import load_parsers

if not load_rules():
    pytest.skip("pysigma or the bundled Linux ruleset is not available", allow_module_level=True)


def _rule(title: str, category: str, detection: str, level: str = "high",
          rule_id: str | None = None) -> str:
    return (f"title: {title}\nid: {rule_id or uuid.uuid4()}\nstatus: test\nlevel: {level}\n"
            f"logsource:\n    product: linux\n    category: {category}\n"
            f"detection:\n{detection}    condition: sel\n")


_SUDOERS = "    sel:\n        TargetFilename|startswith: '/etc/sudoers.d/'\n"
_CALLBACK = ("    sel:\n        Initiated: 'true'\n        DestinationPort:\n"
             "            - 4444\n")


def _put(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _write(path: Path, header, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


@pytest.fixture
def fork(tmp_path):
    """assets/ with a Linux fork mirror of two rules; the rules cache is cleared."""
    assets = tmp_path / "assets"
    m = assets / "sigma_disk_linux"
    _put(m, "file_event/s.yml", _rule("Sudoers Drop", "file_event", _SUDOERS))
    _put(m, "network_connection/c.yml", _rule("Callback Port", "network_connection", _CALLBACK))
    _put(m, "file_event/x.yml", _rule("Ends In X", "file_event",
                                      "    sel:\n        TargetFilename|endswith: '/x'\n"))
    load_rules.cache_clear()
    yield assets
    load_rules.cache_clear()


def _run(tmp_path: Path, assets: Path) -> list[dict]:
    ev = tmp_path / "unit"
    (ev / "[root]").mkdir(parents=True, exist_ok=True)
    out = ev / "CSVs" / "Detections"
    lin_sigma.run(ParserContext(evidence=ev, out=out, tools=tmp_path, assets=assets,
                                machine_name="HOST-01", volume="root",
                                log=logging.getLogger("aeng.test")))
    p = out / "alert_log_sigma.csv"
    if not p.is_file():
        return []
    with open(p, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


_BODY = ["name", "inode", "mode", "uid", "gid", "size", "atime_utc", "mtime_utc",
         "ctime_utc", "crtime_utc"]


def _bodyfile(tmp_path: Path, rows) -> None:
    _write(tmp_path / "unit" / "CSVs" / "Filesystem" / "art_bodyfile.csv", _BODY, rows)


def test_a_file_rule_fires_on_the_bodyfile_once_per_rule_with_its_count(tmp_path, fork):
    _bodyfile(tmp_path, [
        ["/etc/sudoers.d/jdoe", "1", "-rw-r-----", "0", "0", "40", "", "2026-01-02 03:04:05",
         "", ""],
        ["/etc/sudoers.d/ops", "2", "-rw-r-----", "0", "0", "40", "", "2026-01-01 00:00:00",
         "", "2026-01-03 00:00:00"],
        ["/etc/sudoers.d/link -> /tmp/x", "3", "lrwxrwxrwx", "0", "0", "6", "",
         "2026-01-04 00:00:00", "", ""],
        ["/etc/sudoers.d/sub", "4", "drwxr-x---", "0", "0", "4096", "", "2026-01-05 00:00:00",
         "", ""],
        ["/etc/hosts", "5", "-rw-r--r--", "0", "0", "9", "", "2026-01-06 00:00:00", "", ""]])
    rows = _run(tmp_path, fork)
    (r,) = [r for r in rows if r["rule"] == "Sudoers Drop"]
    # three files (a directory is not one), the birth time when there is one
    assert r["source"] == "bodyfile" and r["count"] == "3"
    assert (r["first_seen"], r["last_seen"]) == ("2026-01-02 03:04:05", "2026-01-04 00:00:00")
    assert r["match"] == "/etc/sudoers.d/jdoe"
    # a link is its own path, not the "path -> target" the bodyfile writes
    assert [r for r in rows if r["rule"] == "Ends In X"] == []


def test_the_file_rules_read_the_bodyfile_in_batches(tmp_path, fork, monkeypatch):
    monkeypatch.setattr(lin_sigma, "_FILE_BATCH", 2)
    _bodyfile(tmp_path, [[f"/etc/sudoers.d/u{i}", str(i), "-rw-r-----", "0", "0", "1", "",
                          f"2026-01-0{i} 00:00:00", "", ""] for i in range(1, 6)])
    (r,) = [r for r in _run(tmp_path, fork) if r["rule"] == "Sudoers Drop"]
    assert r["count"] == "5"
    assert (r["first_seen"], r["last_seen"]) == ("2026-01-01 00:00:00", "2026-01-05 00:00:00")


_NET = ["pid", "process", "path", "command_line", "user", "start_utc", "proto", "state",
        "local_ip", "local_port", "remote_ip", "remote_port", "socket_created_utc"]


def test_a_network_rule_fires_on_an_outbound_socket_only(tmp_path, fork):
    _write(tmp_path / "unit" / "CSVs" / "Network" / "art_process_network.csv", _NET, [
        # out to 4444: fires
        ["10", "bash", "/usr/bin/bash", "bash -i", "jdoe", "2026-01-01 10:00:00", "tcp",
         "ESTAB", "10.0.0.5", "50000", "203.0.113.7", "4444", ""],
        # a server listening on 4444 and the connection it accepted: in, not out
        ["20", "srv", "/opt/srv", "srv", "jdoe", "2026-01-01 09:00:00", "tcp", "LISTEN",
         "0.0.0.0", "4444", "0.0.0.0", "*", ""],
        ["20", "srv", "/opt/srv", "srv", "jdoe", "2026-01-01 09:00:00", "tcp", "ESTAB",
         "10.0.0.5", "4444", "203.0.113.7", "4444", ""],
        ["30", "idle", "/opt/idle", "idle", "jdoe", "2026-01-01 08:00:00", "", "", "", "",
         "", "", ""]])
    (r,) = [r for r in _run(tmp_path, fork) if r["rule"] == "Callback Port"]
    assert r["source"] == "network" and r["count"] == "1"
    assert r["match"] == "Image=/usr/bin/bash DestinationIp=203.0.113.7 DestinationPort=4444"
    assert r["first_seen"] == "2026-01-01 10:00:00"


def test_the_fork_is_read_less_its_not_adaptable_else_the_bundled_copy(tmp_path):
    fork = tmp_path / "sigma_disk_linux"
    keep, skip = str(uuid.uuid4()), str(uuid.uuid4())
    _put(fork, "file_event/a.yml", _rule("Fork Rule", "file_event", _SUDOERS, rule_id=keep))
    _put(fork, "file_event/b.yml", _rule("Not Adaptable", "file_event", _SUDOERS, rule_id=skip))
    _put(fork, "aeng/not-adaptable.txt", f"{skip}  rules/linux/file_event/b.yml  noise\n")
    load_rules.cache_clear()
    try:
        assert {r.title for r in load_rules(None, fork)} == {"Fork Rule"}
        load_rules.cache_clear()
        bundled = {r.title for r in load_rules(None, tmp_path / "empty")}
        assert bundled and "Fork Rule" not in bundled
    finally:
        load_rules.cache_clear()


def _git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.local",
                    "-C", str(repo), *args], check=True, capture_output=True)


def test_the_forks_linux_rules_are_mirrored_apart_with_their_own_not_adaptable(tmp_path):
    repo = tmp_path / "fork"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "aeng")
    _put(repo, "rules/windows/process_creation/p.yml",
         _rule("Win", "process_creation", "    sel:\n        Image|endswith: '\\x.exe'\n"))
    _put(repo, "rules/linux/file_event/s.yml", _rule("Sudoers Drop", "file_event", _SUDOERS))
    _put(repo, "aeng/not-adaptable.txt",
         "# header\nid-win  rules/windows/file/x.yml  why\n"
         "id-lin  rules/linux/file_event/y.yml  why\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "rules")
    assets = tmp_path / "assets"
    r = sync_disk_sigma(str(repo), "aeng", assets)
    assert (r.ok, r.total, r.added) == (True, 2, 2)
    lin = assets / "sigma_disk_linux"
    assert [p.relative_to(lin).as_posix() for p in lin.rglob("*.yml")] == ["file_event/s.yml"]
    assert not list((assets / "sigma_disk").rglob("s.yml"))
    # only the Linux line: a Windows entry changes nothing alert_log_sigma reads
    assert (lin / "aeng" / "not-adaptable.txt").read_text("utf-8") \
        == "id-lin  rules/linux/file_event/y.yml  why\n"
    assert drop_disk_sigma(assets) and not lin.exists()


def test_alert_log_sigma_reruns_on_the_forks_linux_rules_only():
    assert downloader.DISK_LINUX_DIR == lin_sigma.DISK_LINUX_DIR
    parsers = {p.id: p for p in load_parsers([DATA_DIR / "parsers"])}
    tokens = asset_state._tokens(parsers["alert_log_sigma"])
    assert b"sigma_disk_linux" in tokens and b"sigma_disk" not in tokens
    assert b"sigma_disk_linux" not in asset_state._tokens(parsers["alert_win_sigma"])
    assert {"art_bodyfile", "art_process_network"} <= set(parsers["alert_log_sigma"].depends_on)
