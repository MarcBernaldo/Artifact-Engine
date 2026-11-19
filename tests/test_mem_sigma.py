"""SigmaHQ process_creation rules over the processes in memory (v0.7.94).

Tables are invented in the shape Volatility 3 writes them; names are made up.
"""
from __future__ import annotations

import csv
import logging
import uuid
from pathlib import Path

import pytest

from artifact_engine.config import DATA_DIR, load_config
from artifact_engine.core import asset_state, sigma_windows
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.core.sigma_wincat import load_category
from artifact_engine.core.sigma_windows import load_process_rules
from artifact_engine.handlers import mem_findings as F
from artifact_engine.handlers import mem_sigma as S
from artifact_engine.handlers import win_sigma as W
from artifact_engine.registry import load_parsers

_PS = ["TreeDepth", "PID", "PPID", "ImageFileName", "Offset(V)", "Threads", "Handles",
       "SessionId", "Wow64", "CreateTime", "ExitTime"]
_TREE = [*_PS, "Audit", "Cmd", "Path"]
_T0 = "2026-01-01 10:00:00.000000 UTC"
_BS = "\\"


def _w(unit: Path, name: str, header, rows) -> None:
    d = unit / "CSVs" / "Memory"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / f"{name}.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def _unit(tmp_path, procs, links=(("C:", "\\Device\\HarddiskVolume2"),), root="C:\\Windows"):
    """procs: (pid, ppid, name, path, cmdline)."""
    unit = tmp_path / "HOST-01_memory"
    _w(unit, "art_mem_pslist", _PS,
       [[0, pid, ppid, name, "0x1", 1, 1, 1, "False", _T0, "N/A"]
        for pid, ppid, name, _p, _c in procs])
    _w(unit, "art_mem_pstree", _TREE,
       [[0, pid, ppid, name, "0x1", 1, 1, 1, "False", _T0, "N/A", path, cmd, path]
        for pid, ppid, name, path, cmd in procs])
    _w(unit, "art_mem_cmdline", ["TreeDepth", "PID", "Process", "Args"],
       [[0, pid, name, cmd] for pid, _pp, name, _p, cmd in procs])
    _w(unit, "art_mem_getsids", ["TreeDepth", "PID", "Process", "SID", "Name"],
       [[0, pid, name, "S-1-5-18", "Local System"] for pid, _pp, name, _p, _c in procs])
    _w(unit, "art_mem_symlinkscan", ["TreeDepth", "Offset", "CreateTime", "From Name", "To Name"],
       [[0, "0x1", _T0, a, b] for a, b in links])
    _w(unit, "art_mem_info", ["TreeDepth", "Variable", "Value"], [[0, "NtSystemRoot", root]])
    return unit


def _sigma(tmp_path, unit) -> list[dict]:
    out = tmp_path / "out"
    S.run(ParserContext(evidence=unit, out=out, tools=unit, assets=DATA_DIR / "assets",
                        machine_name="HOST-01", volume="x", log=logging.getLogger("aeng.test")))
    p = out / "alert_mem_sigma.csv"
    if not p.is_file():
        return []
    with open(p, encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


_SYS = (4, 0, "System", "", "")
_SH = (500, 400, "services.exe", "C:\\Windows\\System32\\services.exe", "")


def test_an_attack_command_line_fires_its_sigma_rule(tmp_path):
    vss = (900, 500, "vssadmin.exe", "C:\\Windows\\System32\\vssadmin.exe",
           "vssadmin.exe delete shadows /all /quiet")
    rows = _sigma(tmp_path, _unit(tmp_path, [_SYS, _SH, vss]))
    hit = [r for r in rows if r["rule"].startswith("Shadow Copies Deletion")]
    assert hit and hit[0]["pid"] == "900" and hit[0]["level"] == "high"
    assert hit[0]["parent_path"].endswith("services.exe")


def test_a_device_path_does_not_make_a_system_binary_look_misplaced(tmp_path):
    """Sigma expects the drive letter Sysmon logs; Volatility may give the device."""
    wer = (900, 500, "WerFault.exe", "\\Device\\HarddiskVolume2\\Windows\\SysWOW64\\WerFault.exe",
           "C:\\Windows\\SysWOW64\\WerFault.exe -u -p 1")
    rows = _sigma(tmp_path, _unit(tmp_path, [_SYS, _SH, wer]))
    assert not [r for r in rows if "Location Anomaly" in r["rule"]]


def test_the_same_binary_genuinely_misplaced_still_fires(tmp_path):
    wer = (900, 500, "WerFault.exe", "C:\\Users\\Public\\WerFault.exe", "WerFault.exe")
    rows = _sigma(tmp_path, _unit(tmp_path, [_SYS, _SH, wer]))
    assert [r for r in rows if "Location Anomaly" in r["rule"]]


def test_no_process_table_is_a_skip(tmp_path):
    with pytest.raises(HandlerSkip):
        _sigma(tmp_path, tmp_path / "empty")


# --- drive letters from the image itself -------------------------------------------

def _fix(links=(), root=""):
    t = {"art_mem_symlinkscan": [{"From Name": a, "To Name": b} for a, b in links],
         "art_mem_info": [{"Variable": "NtSystemRoot", "Value": root}] if root else []}
    return F.drive_paths(t)


def test_a_device_path_takes_the_letter_the_image_links_to_it():
    fix = _fix([("E:", "\\Device\\HarddiskVolume3"), ("C:", "\\Device\\HarddiskVolume2")])
    assert fix("\\Device\\HarddiskVolume3\\Tools\\x.exe") == "E:\\Tools\\x.exe"
    assert fix("\\Device\\HarddiskVolume2\\Windows\\x.exe") == "C:\\Windows\\x.exe"


def test_systemroot_and_the_nt_prefix_are_spelled_out():
    fix = _fix(root="C:\\Windows")
    assert fix("\\SystemRoot\\System32\\smss.exe") == "C:\\Windows\\System32\\smss.exe"
    assert fix("\\??\\C:\\Windows\\System32\\conhost.exe") == "C:\\Windows\\System32\\conhost.exe"


def test_without_a_link_only_the_system_roots_volume_is_inferred():
    fix = _fix([("D:", "\\Device\\CdRom0")], root="C:\\Windows")
    assert fix("\\Device\\HarddiskVolume2\\Windows\\SysWOW64\\a.exe") == \
        "C:\\Windows\\SysWOW64\\a.exe"
    # a path elsewhere on an unlinked volume keeps its device form: no guess
    assert fix("\\Device\\HarddiskVolume5\\Data\\b.exe") == "\\Device\\HarddiskVolume5\\Data\\b.exe"


def test_with_nothing_to_go_on_a_path_is_left_as_written():
    assert _fix()("\\Device\\HarddiskVolume2\\Windows\\a.exe") == \
        "\\Device\\HarddiskVolume2\\Windows\\a.exe"


def test_sigma_matches_reach_the_alerts_at_the_rules_level(tmp_path):
    unit = _unit(tmp_path, [_SYS, _SH])
    _w(unit, "alert_mem_sigma", S._HEADER,
       [[500, "services.exe", "Crit Rule", "critical", "", "", "", "", ""],
        [500, "services.exe", "Low Rule", "low", "", "", "", "", ""]])
    out = tmp_path / "fout"
    F.run(ParserContext(evidence=unit, out=out, tools=unit, assets=DATA_DIR / "assets",
                        machine_name="HOST-01", volume="x", log=logging.getLogger("aeng.test")))
    with open(out / "alert_mem.csv", encoding="utf-8") as fh:
        alerts = [a for a in csv.DictReader(fh) if a["rule"] == "sigma_match"]
    assert {(a["detail"].split(" [")[0], a["level"]) for a in alerts} == \
        {("Crit Rule", "high"), ("Low Rule", "low")}


def _proc_rule(title: str, image: str) -> str:
    rid = str(uuid.uuid5(uuid.NAMESPACE_DNS, title))
    return (f"title: {title}\nid: {rid}\nstatus: test\nlevel: high\n"
            f"logsource:\n    product: windows\n    category: process_creation\n"
            f"detection:\n    selection:\n        Image|endswith: '\\{image}'\n"
            f"    condition: selection\n")


def _in(assets: Path, sub: str, name: str, text: str) -> None:
    f = assets / sub / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")


@pytest.fixture
def _own_rules(tmp_path, monkeypatch):
    """A bundled snapshot of one rule, so a test sees which copy was read."""
    bundled = tmp_path / "bundled"
    bundled.mkdir()
    (bundled / "b.yml").write_text(_proc_rule("Bundled Rule", "old.exe"), encoding="utf-8")
    monkeypatch.setattr(sigma_windows, "SIGMA_PROC_DIR", bundled)
    load_process_rules.cache_clear()
    load_category.cache_clear()
    yield tmp_path / "assets"
    load_process_rules.cache_clear()
    load_category.cache_clear()


def _run_with(tmp_path, assets: Path) -> set[str]:
    unit = _unit(tmp_path, [_SYS, _SH,
                            (600, 500, "old.exe", "C:\\Tools\\old.exe", "old.exe"),
                            (601, 500, "new.exe", "C:\\Tools\\new.exe", "new.exe"),
                            (602, 500, "mine.exe", "C:\\Tools\\mine.exe", "mine.exe")])
    assets.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out"
    S.run(ParserContext(evidence=unit, out=out, tools=unit, assets=assets,
                        machine_name="HOST-01", volume="x", log=logging.getLogger("aeng.test")))
    with open(out / "alert_mem_sigma.csv", encoding="utf-8") as fh:
        return {r["rule"] for r in csv.DictReader(fh)}


def test_the_forks_process_rules_are_read_when_mirrored(tmp_path, _own_rules):
    # SigmaHQ as it is now, the copy alert_win_sigma reads, not the package's snapshot;
    # its not-adaptable list names disk duplicates, which memory does not have.
    assets = _own_rules
    _in(assets, "sigma_disk/process_creation", "n.yml", _proc_rule("Fork Rule", "new.exe"))
    _in(assets, "sigma_disk/aeng", "not-adaptable.txt",
        f"{uuid.uuid5(uuid.NAMESPACE_DNS, 'Fork Rule')}  n.yml  duplicate\n")
    _in(assets, "sigma_custom/windows/process_creation", "m.yml",
        _proc_rule("Own Rule", "mine.exe"))
    assert _run_with(tmp_path, assets) == {"Fork Rule", "Own Rule"}


def test_without_the_mirror_the_bundled_snapshot_is_read(tmp_path, _own_rules):
    assets = _own_rules
    _in(assets, "sigma_custom/windows/process_creation", "m.yml",
        _proc_rule("Own Rule", "mine.exe"))
    assert _run_with(tmp_path, assets) == {"Bundled Rule", "Own Rule"}


def test_memory_and_the_disk_name_the_same_mirror_and_a_fork_change_reruns_memory(tmp_path):
    assert S._FORK == W.DISK_SIGMA
    (tmp_path / "sigma_disk").mkdir()
    parsers = {p.id: p for p in load_parsers(load_config().all_parser_dirs)}
    assert "sigma_disk" in asset_state.used(parsers["alert_mem_sigma"], tmp_path)
