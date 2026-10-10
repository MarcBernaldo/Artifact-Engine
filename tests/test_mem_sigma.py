"""SigmaHQ process_creation rules over the processes in memory (v0.7.94).

Tables are invented in the shape Volatility 3 writes them; names are made up.
"""
from __future__ import annotations

import csv
import logging
from pathlib import Path

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.handlers import mem_findings as F
from artifact_engine.handlers import mem_sigma as S

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
    _w(unit, "mem_pslist", _PS,
       [[0, pid, ppid, name, "0x1", 1, 1, 1, "False", _T0, "N/A"]
        for pid, ppid, name, _p, _c in procs])
    _w(unit, "mem_pstree", _TREE,
       [[0, pid, ppid, name, "0x1", 1, 1, 1, "False", _T0, "N/A", path, cmd, path]
        for pid, ppid, name, path, cmd in procs])
    _w(unit, "mem_cmdline", ["TreeDepth", "PID", "Process", "Args"],
       [[0, pid, name, cmd] for pid, _pp, name, _p, cmd in procs])
    _w(unit, "mem_getsids", ["TreeDepth", "PID", "Process", "SID", "Name"],
       [[0, pid, name, "S-1-5-18", "Local System"] for pid, _pp, name, _p, _c in procs])
    _w(unit, "mem_symlinkscan", ["TreeDepth", "Offset", "CreateTime", "From Name", "To Name"],
       [[0, "0x1", _T0, a, b] for a, b in links])
    _w(unit, "mem_info", ["TreeDepth", "Variable", "Value"], [[0, "NtSystemRoot", root]])
    return unit


def _sigma(tmp_path, unit) -> list[dict]:
    out = tmp_path / "out"
    S.run(ParserContext(evidence=unit, out=out, tools=unit, assets=DATA_DIR / "assets",
                        machine_name="HOST-01", volume="x", log=logging.getLogger("aeng.test")))
    p = out / "mem_sigma.csv"
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
    assert hit[0]["parent_image"].endswith("services.exe")


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
    t = {"mem_symlinkscan": [{"From Name": a, "To Name": b} for a, b in links],
         "mem_info": [{"Variable": "NtSystemRoot", "Value": root}] if root else []}
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
    _w(unit, "mem_sigma", S._HEADER,
       [[500, "services.exe", "Crit Rule", "critical", "", "", "", "", ""],
        [500, "services.exe", "Low Rule", "low", "", "", "", "", ""]])
    out = tmp_path / "fout"
    F.run(ParserContext(evidence=unit, out=out, tools=unit, assets=DATA_DIR / "assets",
                        machine_name="HOST-01", volume="x", log=logging.getLogger("aeng.test")))
    with open(out / "mem_alerts.csv", encoding="utf-8") as fh:
        alerts = [a for a in csv.DictReader(fh) if a["rule"] == "sigma_match"]
    assert {(a["detail"].split(" [")[0], a["severity"]) for a in alerts} == \
        {("Crit Rule", "high"), ("Low Rule", "low")}
