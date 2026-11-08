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
