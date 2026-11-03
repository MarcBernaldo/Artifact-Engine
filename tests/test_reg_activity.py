"""What each user ran and opened, from the registry keys no other parser read,
and the installed software (win_reg_activity). RECmd is faked: it writes what the
real one writes -- the main CSV, and each plugin's detail CSV in a timestamped
folder -- from a table of hives. All users, paths and programs are synthetic."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

import pytest

from artifact_engine.core import procs
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.handlers import win_reg_activity as W

_MAIN = ["HivePath", "HiveType", "Description", "Category", "KeyPath", "ValueName", "ValueType",
         "ValueData", "ValueData2", "ValueData3", "Comment", "Recursive", "Deleted",
         "LastWriteTimestamp", "PluginDetailFile"]


def _csv(path: Path, header: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, header, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def _main(hive, desc, name, data="", lw="2026-01-05 10:00:00.1234567"):
    return {"HivePath": str(hive), "Description": desc, "ValueName": name, "ValueData": data,
            "LastWriteTimestamp": lw}


def _volume(tmp_path: Path) -> Path:
    vol = tmp_path / "C"
    for user in ("jdoe", "asmith"):
        (vol / "Users" / user).mkdir(parents=True)
        (vol / "Users" / user / "NTUSER.DAT").write_bytes(b"regf")
    uc = vol / "Users" / "jdoe" / "AppData" / "Local" / "Microsoft" / "Windows"
    uc.mkdir(parents=True)
    (uc / "UsrClass.dat").write_bytes(b"regf")
    (vol / "Windows" / "System32" / "config").mkdir(parents=True)
    (vol / "Windows" / "System32" / "config" / "SOFTWARE").write_bytes(b"regf")
    return vol


def _fake_recmd(monkeypatch, vol: Path, fail: set[str] = frozenset()):
    """Answer each RECmd call from the hive it names. Returns the calls made."""
    users = vol / "Users"
    jdoe, asmith = users / "jdoe" / "NTUSER.DAT", users / "asmith" / "NTUSER.DAT"
    uc = users / "jdoe" / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
    calls = []

    def run(cmd, timeout=None, cwd=None):
        mode, source = cmd[1], Path(cmd[2])
        out, csvf = Path(cmd[cmd.index("--csv") + 1]), cmd[cmd.index("--csvf") + 1]
        calls.append((mode, source.name))
        if source.name in fail or source.parent.name in fail:
            return 1, "", "Error: hive is corrupt"
        stem, detail = Path(csvf).stem, out / "20260101000000"
        main: list[dict] = []
        if source == jdoe:
            main = [_main(jdoe, "Compatibility Assistant Store", r"C:\Users\jdoe\Tools\tunnelx.exe"),
                    _main(jdoe, "AppCompatFlags Layers", r"C:\Tools\old.exe", "~ RUNASADMIN")]
            _csv(detail / f"{stem}_FeatureUsage.csv", ["KeyPath", "ValueName", "Count"],
                 [{"KeyPath": "AppLaunch", "ValueName": r"C:\Users\jdoe\Tools\tunnelx.exe", "Count": "4"}])
            row = {"Extension": "docx", "AbsolutePath": r"C:\Users\jdoe\report.docx",
                   "MruPosition": "0", "OpenedOn": "2026-01-06 08:00:00.0000000"}
            _csv(detail / f"{stem}_OpenSavePidlMRU.csv",
                 ["Extension", "MruPosition", "AbsolutePath", "OpenedOn"], [row])
            _csv(detail / f"{stem}_LastVisitedPidlMRU.csv",
                 ["MruPosition", "Executable", "AbsolutePath", "OpenedOn"],
                 [{"MruPosition": "0", "Executable": "tunnelx.exe",
                   "AbsolutePath": r"C:\Users\jdoe\Documents", "OpenedOn": ""}])
            doc = {"Extension": ".pdf", "TargetName": "plan.pdf", "LnkName": "plan.lnk",
                   "MruPosition": "1", "OpenedOn": ""}
            _csv(detail / f"{stem}_RecentDocs.csv",           # the root and its .pdf subkey
                 ["Extension", "TargetName", "LnkName", "MruPosition", "OpenedOn"], [doc, doc])
        elif source == asmith:
            main = [_main(asmith, "Compatibility Assistant Store", r"C:\Temp\setup.exe")]
        elif source == users:
            main = [_main(uc, "MUICache", r"C:\Users\jdoe\Tools\tunnelx.exe.FriendlyAppName", "TunnelX"),
                    _main(uc, "MUICache", r"C:\Users\jdoe\Tools\tunnelx.exe.ApplicationCompany",
                          "Example Ltd"),
                    _main(uc, "MUICache", "LangID", "09 04")]
        elif source.name == "SOFTWARE":
            head = ["Timestamp", "KeyName", "DisplayName", "DisplayVersion", "Publisher", "InstallDate",
                    "InstallSource", "InstallLocation", "UninstallString"]
            app = {"Timestamp": "2026-01-02 03:04:05.0000000", "KeyName": "TunnelX",
                   "DisplayName": "TunnelX", "DisplayVersion": "2.1", "Publisher": "Example Ltd",
                   "InstallDate": "20260102", "InstallLocation": r"C:\Program Files\TunnelX",
                   "UninstallString": r"C:\Program Files\TunnelX\uninst.exe"}
            _csv(detail / f"{stem}_UnInstall.csv", head,
                 [app, app, {"Timestamp": "2026-01-02 03:04:05", "KeyName": "KB5000001"}])
        _csv(out / csvf, _MAIN, main)
        return 0, "", ""

    monkeypatch.setattr(procs, "run", run)
    return calls


def _ctx(vol: Path, tmp_path: Path, tools: Path | None = None) -> ParserContext:
    from artifact_engine.config import DATA_DIR

    if tools is None:
        tools = tmp_path / "tools"
        (tools / "RECmd").mkdir(parents=True, exist_ok=True)
        (tools / "RECmd" / "RECmd.exe").write_bytes(b"MZ")
    return ParserContext(evidence=vol, out=tmp_path / "out", tools=tools, assets=DATA_DIR / "assets",
                         machine_name="HOST-01", volume="C", log=logging.getLogger("aeng.test"))


def _rows(out: Path, name: str) -> list[dict]:
    p = out / name
    if not p.is_file():
        return []
    with open(p, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_each_users_keys_land_under_that_user(tmp_path, monkeypatch):
    vol = _volume(tmp_path)
    _fake_recmd(monkeypatch, vol)
    ctx = _ctx(vol, tmp_path)
    W.run(ctx)

    assert _rows(ctx.out, "art_reg_compat_store.csv") == [
        {"user": "asmith", "kind": "compat_store", "path": r"C:\Temp\setup.exe", "flags": "",
         "key_last_write_utc": "2026-01-05 10:00:00"},
        {"user": "jdoe", "kind": "compat_store", "path": r"C:\Users\jdoe\Tools\tunnelx.exe",
         "flags": "", "key_last_write_utc": "2026-01-05 10:00:00"},
        {"user": "jdoe", "kind": "layers", "path": r"C:\Tools\old.exe", "flags": "~ RUNASADMIN",
         "key_last_write_utc": "2026-01-05 10:00:00"}]
    assert _rows(ctx.out, "art_reg_feature_usage.csv") == [
        {"user": "jdoe", "kind": "AppLaunch", "app": r"C:\Users\jdoe\Tools\tunnelx.exe", "count": "4"}]
    dialogs = _rows(ctx.out, "art_reg_file_dialogs.csv")
    assert [(d["kind"], d["process"], d["opened_utc"]) for d in dialogs] == [
        ("open_save", "", "2026-01-06 08:00:00"), ("last_visited", "tunnelx.exe", "")]
    assert len(_rows(ctx.out, "art_reg_recent_docs.csv")) == 1, "the repeat is dropped"


def test_muicache_joins_name_and_company_from_one_run_over_the_profiles(tmp_path, monkeypatch):
    vol = _volume(tmp_path)
    calls = _fake_recmd(monkeypatch, vol)
    ctx = _ctx(vol, tmp_path)
    W.run(ctx)

    assert _rows(ctx.out, "art_reg_muicache.csv") == [
        {"user": "jdoe", "path": r"C:\Users\jdoe\Tools\tunnelx.exe", "name": "TunnelX",
         "company": "Example Ltd"}]
    # NTUSER hive by hive (the plugins' detail files do not say whose), UsrClass once
    assert sorted(calls) == [("-d", "Users"), ("-f", "NTUSER.DAT"), ("-f", "NTUSER.DAT")]


def test_installed_software_without_a_name_is_left_out(tmp_path, monkeypatch):
    vol = _volume(tmp_path)
    _fake_recmd(monkeypatch, vol)
    ctx = _ctx(vol, tmp_path)
    W.run_installed(ctx)

    assert _rows(ctx.out, "art_reg_installed.csv") == [
        {"name": "TunnelX", "version": "2.1", "publisher": "Example Ltd", "install_date": "20260102",
         "install_location": r"C:\Program Files\TunnelX", "install_source": "",
         "uninstall": r"C:\Program Files\TunnelX\uninst.exe", "key": "TunnelX",
         "key_last_write_utc": "2026-01-02 03:04:05"}]


def test_one_unreadable_hive_costs_only_its_user(tmp_path, monkeypatch, caplog):
    vol = _volume(tmp_path)
    _fake_recmd(monkeypatch, vol, fail={"asmith"})
    ctx = _ctx(vol, tmp_path)
    with caplog.at_level("WARNING", logger="aeng.test"):
        W.run(ctx)

    assert {r["user"] for r in _rows(ctx.out, "art_reg_compat_store.csv")} == {"jdoe"}
    assert "RECmd failed on NTUSER.DAT" in caplog.text


def test_every_hive_failing_is_an_error_not_an_empty_table(tmp_path, monkeypatch):
    vol = _volume(tmp_path)
    _fake_recmd(monkeypatch, vol, fail={"jdoe", "asmith", "Users"})
    with pytest.raises(RuntimeError, match="every user hive"):
        W.run(_ctx(vol, tmp_path))


def test_without_recmd_or_hives_it_skips(tmp_path, monkeypatch):
    vol = _volume(tmp_path)
    _fake_recmd(monkeypatch, vol)
    with pytest.raises(HandlerSkip, match="RECmd not installed"):
        W.run(_ctx(vol, tmp_path, tools=tmp_path / "empty"))
    empty = tmp_path / "bare"
    (empty / "Users" / "Public").mkdir(parents=True)
    with pytest.raises(HandlerSkip, match="no user hives"):
        W.run(_ctx(empty, tmp_path))
