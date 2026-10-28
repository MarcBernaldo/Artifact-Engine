"""One search of every execution artifact, for every catalog (v0.7.103).

All paths, users and SIDs are synthetic."""

import csv
import json
import logging
from pathlib import Path

import pytest
import yaml

from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.handlers import _execution as X
from artifact_engine.handlers import win_exec_hunt as H

_REG = ["HivePath", "KeyPath", "ValueName", "ValueData", "ValueData2", "ValueData3",
        "LastWriteTimestamp"]
_SID = "S-1-5-21-1000-2000-3000-1001"


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


def _assets(tmp_path: Path) -> Path:
    a = tmp_path / "assets"
    a.mkdir()
    (a / "rmm_tools.yaml").write_text(yaml.safe_dump({"tools": [
        {"name": "TunnelX", "files": ["tunnelx.exe"]}]}), encoding="utf-8")
    (a / "lolbas.yaml").write_text(yaml.safe_dump({"binaries": ["certutil.exe"]}),
                                   encoding="utf-8")
    return a


def _machine(tmp_path: Path, exe=r"C:\Users\jdoe\Tools\tunnelx.exe") -> Path:
    """A machine whose every execution artifact names the same program."""
    c = tmp_path / "C" / "CSVs"
    tail = exe[2:]                                           # \Users\jdoe\Tools\tunnelx.exe
    _write(c / "Execution" / "art_amcache_unassociated_files.csv",
           ["Name", "FullPath", "SHA1", "FileKeyLastWriteTimestamp"],
           [["tunnelx.exe", exe.lower(), "ab" * 20, "2026-01-05 10:00:00"]])
    _write(c / "Execution" / "art_prefetch.csv", ["ExecutableName", "RunCount", "LastRun", "FilesLoaded"],
           [["TUNNELX.EXE", "7", "2026-01-09 08:00:00",
             r"\VOLUME{01d-0a1b}\WINDOWS\SYSTEM32\NTDLL.DLL, \VOLUME{01d-0a1b}" + tail.upper()]])
    _write(c / "Execution" / "art_reg_shimcache.csv", ["Path", "LastModifiedTimeUTC", "Executed"],
           [[exe, "2020-01-01 00:00:00", ""]])           # the file's mtime: never a sighting time
    _write(c / "Registry" / "art_reg_bam.csv", _REG,
           [["SYSTEM", "ControlSet001\\Services\\bam\\State\\UserSettings\\" + _SID,
             r"\Device\HarddiskVolume3" + tail, "", "Last execution: 2026-01-08 12:00:00.1234567",
             "", "2026-01-08 12:00:00"]])
    _write(c / "Registry" / "art_reg_userassist.csv", _REG,
           [[r"C:\Cases\x\C\Users\jdoe\NTUSER.DAT", "Software\\...\\UserAssist\\{CEBFF5CD}",
             exe, exe, "Last executed: 2026-01-07 09:00:00", "Run count: 3", ""]])
    _write(c / "Execution" / "art_pca.csv", ["executable_path", "last_executed_local"],
           [[exe, "2026-01-10 23:00:00"]])               # local clock: a source, not a time
    _write(c / "Execution" / "art_srum_network_usage.csv", ["Timestamp", "ExeInfo", "UserName"],
           [["2026-01-06 11:00:00", r"\device\harddiskvolume3" + tail.lower(), "svc_sync"]] * 3)
    _write(c / "Registry" / "art_reg_services.csv", _REG,
           [["SYSTEM", "ControlSet001\\Services\\TunnelSvc", "ImagePath", f'"{exe}" --service',
             "", "", "2026-01-04 10:00:00"],
            ["SYSTEM", "ControlSet001\\Services\\TunnelSvc", "Start", "2", "", "", ""],
            ["SYSTEM", "ControlSet001\\Services\\TunnelSvc", "Description",
             r"C:\Other\tunnelx.exe", "", "", ""]])                 # not where it runs from
    _write(c / "Persistence" / "art_tasks.csv", ["task", "runas", "command"],
           [["\\Updater", "SYSTEM", f"{exe} http 8080"]])
    _write(c / "Filesystem" / "art_lnk.csv", ["LocalPath", "Arguments"], [[exe, ""]])
    _write(c / "Filesystem" / "art_jumplist_automatic.csv", ["Path"], [[exe]])
    res = tmp_path / "C" / "Velociraptor" / "LiveResponse" / "results"
    res.mkdir(parents=True)
    (res / "Eiffel.LiveResponse.Windows%2FWindows.System.Pslist.json").write_text(json.dumps(
        {"Pid": 4242, "Name": "tunnelx.exe", "Exe": exe, "Username": "HOST-01\\jdoe",
         "CreateTime": "2026-01-10T07:00:00Z"}), encoding="utf-8")
    return tmp_path / "C"


def _ctx(evidence: Path, assets: Path, volume="C") -> ParserContext:
    return ParserContext(evidence=evidence, out=evidence / "CSVs" / "Detections" / ".work_exec_hunt",
                         tools=evidence, assets=assets, machine_name="HOST-01", volume=volume,
                         log=logging.getLogger("aeng.test"))


def test_one_program_seen_by_every_artifact_is_one_row(tmp_path):
    ctx = _ctx(_machine(tmp_path), _assets(tmp_path))
    H.run(ctx)
    rows = _read(ctx.out / "alert_rmm.csv")
    assert len(rows) == 1
    r = rows[0]
    assert r["sources"].split(", ") == sorted(
        ["amcache", "prefetch", "shimcache", "bam", "userassist", "pca", "srum", "service",
         "task", "lnk", "jumplist", "process"])
    assert r["first_seen_utc"] == "2026-01-04 10:00:00"      # the service key; not shimcache's mtime
    assert r["last_seen_utc"] == "2026-01-10 07:00:00"       # the live process; not PCA's local clock
    assert r["runs"] == "7" and r["sha1"] == "ab" * 20
    assert set(r["users"].split(", ")) == {_SID, "jdoe", "svc_sync", "SYSTEM", "HOST-01\\jdoe"}
    assert r["path"] == r"c:\users\jdoe\tools\tunnelx.exe"   # Amcache's spelling wins


def test_prefetch_finds_its_path_among_the_files_it_loaded(tmp_path):
    c = _machine(tmp_path) / "CSVs"
    assert [s.path for s in X.prefetch(c)] == [r"\VOLUME{01d-0a1b}\USERS\JDOE\TOOLS\TUNNELX.EXE"]


def test_a_vss_volume_never_reads_the_live_processes(tmp_path):
    ctx = _ctx(_machine(tmp_path), _assets(tmp_path), volume="VSS2")
    H.run(ctx)
    assert "process" not in _read(ctx.out / "alert_rmm.csv")[0]["sources"]


def test_a_name_only_record_joins_its_one_path(tmp_path):
    c = tmp_path / "C" / "CSVs"
    _write(c / "Execution" / "art_prefetch.csv", ["ExecutableName", "RunCount", "LastRun", "FilesLoaded"],
           [["TUNNELX.EXE", "2", "2026-01-09 08:00:00", ""]])
    _write(c / "Execution" / "art_reg_shimcache.csv", ["Path"], [[r"C:\Temp\tunnelx.exe"]])
    ctx = _ctx(tmp_path / "C", _assets(tmp_path))
    H.run(ctx)
    assert [(r["path"], r["sources"]) for r in _read(ctx.out / "alert_rmm.csv")] == [
        (r"C:\Temp\tunnelx.exe", "prefetch, shimcache")]
    # two copies on disk: the name alone cannot say which one ran
    _write(c / "Execution" / "art_reg_shimcache.csv", ["Path"],
           [[r"C:\Temp\tunnelx.exe"], [r"D:\Other\tunnelx.exe"]])
    H.run(ctx)
    assert sorted(r["sources"] for r in _read(ctx.out / "alert_rmm.csv")) == [
        "prefetch", "shimcache", "shimcache"]


def test_lolbas_from_an_artifact_other_than_amcache(tmp_path):
    c = tmp_path / "C" / "CSVs"
    _write(c / "Registry" / "art_reg_bam.csv", _REG,
           [["SYSTEM", "...\\UserSettings\\" + _SID,
             r"\Device\HarddiskVolume3\Users\jdoe\AppData\Local\Temp\certutil.exe", "",
             "Last execution: 2026-01-08 12:00:00", "", ""],
            ["SYSTEM", "...\\UserSettings\\" + _SID,
             r"\Device\HarddiskVolume3\Windows\System32\certutil.exe", "",
             "Last execution: 2026-01-08 12:00:00", "", ""]])
    ctx = _ctx(tmp_path / "C", _assets(tmp_path))
    H.run(ctx)
    rows = _read(ctx.out / "alert_lolbas.csv")
    assert [(r["binary"], r["sources"], r["users"]) for r in rows] == [
        ("certutil.exe", "bam", _SID)]


def test_suspicious_tools_by_file_name_only(tmp_path):
    a = _assets(tmp_path)
    (a / "suspicious_tools.txt").write_text(
        "credential_theft = \\b(mimikatz|sekurlsa)\\b\n"
        "lsass_dump = \\bprocdump\\S*\\s.{0,40}lsass|\\bcreatedump\\b\n", encoding="utf-8")
    c = tmp_path / "C" / "CSVs"
    _write(c / "Execution" / "art_reg_shimcache.csv", ["Path"],
           [[r"C:\Users\jdoe\Downloads\x64\mimikatz.exe"],
            [r"C:\Users\jdoe\mimikatz-notes\editor.exe"],             # a folder, not the tool
            [r"C:\Program Files\dotnet\shared\createdump.exe"]])      # an action's word, not a tool
    _write(c / "Execution" / "art_prefetch.csv", ["ExecutableName", "RunCount", "LastRun", "FilesLoaded"],
           [["MIMIKATZ.EXE", "2", "2026-01-09 08:00:00", ""]])
    ctx = _ctx(tmp_path / "C", a)
    H.run(ctx)
    rows = _read(ctx.out / "alert_suspicious_tools.csv")
    assert [(r["category"], r["binary"], r["sources"]) for r in rows] == [
        ("credential_theft", "mimikatz.exe", "prefetch, shimcache")]


def test_a_wtfbins_program_gets_a_note_and_keeps_its_row(tmp_path):
    a = _assets(tmp_path)
    (a / "suspicious_tools.txt").write_text("ad_recon = \\b(bloodhound)\\b\n", encoding="utf-8")
    (a / "wtfbins.yaml").write_text(
        'entries:\n  - id: 13\n    title: "Bloodhound.exe"\n    binaries: ["bloodhound.exe"]\n'
        '    summary: "x"\n    url: "https://wtfbins.wtf/13"\n', encoding="utf-8")
    _write(tmp_path / "C" / "CSVs" / "Execution" / "art_reg_shimcache.csv", ["Path"],
           [[r"C:\Program Files\Ranger\Bloodhound.exe"]])
    ctx = _ctx(tmp_path / "C", a)
    H.run(ctx)
    rows = _read(ctx.out / "alert_suspicious_tools.csv")
    assert [(r["category"], r["known_benign"]) for r in rows] == [
        ("ad_recon", "WTFBins: Bloodhound.exe https://wtfbins.wtf/13")]


def test_it_skips_without_a_catalog_or_an_artifact(tmp_path):
    with pytest.raises(HandlerSkip):
        H.run(_ctx(_machine(tmp_path), tmp_path / "no-assets"))
    with pytest.raises(HandlerSkip):
        H.run(_ctx(tmp_path / "empty", _assets(tmp_path)))


def test_time_and_path_spellings():
    assert X.utc("2026-01-10T07:00:00.123Z") == "2026-01-10 07:00:00"
    assert X.utc("Last execution: 2026-01-08 12:00:00.1234567") == "2026-01-08 12:00:00"
    assert X.utc("") == ""
    one = {X.norm_path(p) for p in (r"C:\Users\jdoe\x.exe", r"\Device\HarddiskVolume3\Users\jdoe\X.EXE",
                                    r"\VOLUME{01d-0a1b}\USERS\JDOE\X.EXE", '"c:/users/jdoe/x.exe"')}
    assert one == {r"\users\jdoe\x.exe"}


def test_the_bundled_rmm_lists_name_no_generic_program_or_vendor_folder():
    from artifact_engine.config import DATA_DIR
    from artifact_engine.handlers.win_rmm import _load_rmm
    tools = _load_rmm(DATA_DIR / "assets")
    assert not any("gui.exe" in t["files"] for t in tools)
    vendor = {"\\manageengine\\", "\\solarwinds\\"}
    assert not any(vendor & set(t["paths"]) for t in tools)
