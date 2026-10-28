"""art_log_other.csv -- every text log under /var/log that no other parser reads in
full. Synthetic files; names and hosts are invented."""
from __future__ import annotations

import csv
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import lin_other_logs


def _write(base: Path, rel: str, text: str) -> None:
    f = base / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")


def _rows(tmp_path: Path) -> list[dict]:
    ev = tmp_path / "ev"
    log = ev / "[root]" / "var" / "log"
    _write(log, "zypper.log", "2026-05-21 08:10:39 <1> HOST-01(812) [zypp] main.cc(42) start\n"
                              "\n   continuation\n")
    _write(log, "sssd/sssd_example.log", "(2026-10-11 14:00:00): [be[example]] [x] (0x0400): ok\n"
                                         "[2026-10-11T14:00:01.123Z] bracketed iso\n")
    _write(log, "app/err.log", "2026/10/11 14:00:02 [error] 1#1: nginx-like\n"
                               "[Wed Oct 11 14:00:03.5 2026] [core:error] apache-like\n"
                               "Wed Oct 11 14:00:04 2026 ctime\n")
    _write(log, "messages", "Oct 11 14:00:00 HOST-01 a[1]: syslog goes elsewhere\n")
    _write(log, "sa/sar11", "Linux 5.14 (HOST-01)  10/11/2026  _x86_64_\n")
    (log / "lastlog").write_bytes(b"\x00" * 600)
    _write(log, "audit/audit.log", "type=X msg=audit(1.0:1): owned\n")
    lin_other_logs.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
    with open(tmp_path / "out" / "art_log_other.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_only_other_text_logs(tmp_path):
    srcs = {r["source"].replace("\\", "/").removeprefix("[root]/var/log/") for r in _rows(tmp_path)}
    assert srcs == {"zypper.log", "sssd/sssd_example.log", "app/err.log"}


def test_leading_timestamps_split_as_written(tmp_path):
    got = [(r["timestamp"], r["message"]) for r in _rows(tmp_path)]
    assert got == [
        ("2026-05-21 08:10:39", "<1> HOST-01(812) [zypp] main.cc(42) start"),
        ("", "   continuation"),
        ("2026/10/11 14:00:02", "[error] 1#1: nginx-like"),
        ("Wed Oct 11 14:00:03.5 2026", "[core:error] apache-like"),
        ("Wed Oct 11 14:00:04 2026", "ctime"),
        ("", "(2026-10-11 14:00:00): [be[example]] [x] (0x0400): ok"),
        ("2026-10-11T14:00:01.123Z", "bracketed iso"),
    ]


def test_no_other_logs_skips(tmp_path):
    ev = tmp_path / "ev"
    _write(ev / "[root]" / "var" / "log", "messages", "Oct 11 14:00:00 HOST-01 a[1]: x\n")
    with pytest.raises(HandlerSkip):
        lin_other_logs.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
