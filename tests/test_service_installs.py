r"""Services installed, and telling remote execution from a printer driver.

Event 7045 fires for every service on the host, so the whole difficulty is
selectivity: a detector that reports installs reports the machine. These tests
pin the four independent structural questions the handler asks, and the three
places it deliberately stays quiet -- an ordinary driver, a retired service, and
the deployment tool a managed estate runs on purpose.

They also pin what the community list is allowed to change: it may add a NAME to
a row, and it may find a fixed-name tool the structure missed; it may never be
required for a detection, because it arrives with `aeng update` and a fresh
install does not have it.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _awesome
from artifact_engine.handlers import win_service_installs as S


class _Ctx:
    def __init__(self, evidence: Path, out: Path):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "C"
        self.log = None


_EVTX_COLS = ["RecordNumber", "TimeCreated", "EventId", "Channel", "Provider",
              "PayloadData1", "PayloadData2", "PayloadData3", "ExecutableInfo",
              "Payload"]


def _event(name: str, image: str, account: str = "LocalSystem",
           start: str = "demand start", when: str = "2026-05-19 11:22:33.0000000",
           mapped: bool = True) -> dict:
    """One 7045 as EvtxECmd writes it with the bundled map (mapped=True) or
    without one, where everything is in the raw Payload JSON."""
    row = {"RecordNumber": "1", "TimeCreated": when, "EventId": "7045",
           "Channel": "System", "Provider": "Service Control Manager",
           "PayloadData1": "", "PayloadData2": "", "PayloadData3": "",
           "ExecutableInfo": "", "Payload": ""}
    if mapped:
        row.update({"PayloadData1": f"Name: {name}",
                    "PayloadData2": f"StartType: {start}",
                    "PayloadData3": f"Account: {account}",
                    "ExecutableInfo": image})
    else:
        row["Payload"] = json.dumps({
            "EventData": {"Data": [{"@Name": "ServiceName", "#text": name}]},
            "ServiceName": name, "ImagePath": image,
            "AccountName": account, "StartType": start})
    return row


def _write_evtx(tmp_path: Path, events: list[dict]) -> None:
    d = tmp_path / "CSVs" / "EventLogs"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "evtx_system.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_EVTX_COLS)
        w.writeheader()
        for e in events:
            w.writerow({c: e.get(c, "") for c in _EVTX_COLS})


def _write_registry(tmp_path: Path, names: list[str]) -> None:
    d = tmp_path / "CSVs" / "Registry"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "reg_services.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["HivePath", "KeyPath", "ValueName", "ValueData"])
        for n in names:
            w.writerow(["SYSTEM", f"ControlSet001\\Services\\{n}", "ImagePath", "x"])


def _write_list(tmp_path: Path, rows: list[dict]) -> None:
    d = tmp_path / _awesome.DIR
    d.mkdir(parents=True, exist_ok=True)
    cols = ["service_name", "service_path", "metadata_tool_name",
            "metadata_tool_category", "metadata_tool_type", "metadata_severity",
            "metadata_comment", "metadata_reference"]
    with (d / S._SERVICES_LIST).open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})


def _run(tmp_path: Path, events: list[dict], registry: list[str] | None = None,
         listed: list[dict] | None = None) -> list[dict]:
    _write_evtx(tmp_path, events)
    if registry is not None:
        _write_registry(tmp_path, registry)
    if listed is not None:
        _write_list(tmp_path, listed)
    S.run(_Ctx(tmp_path, tmp_path / "out"))
    p = tmp_path / "out" / "service_installs.csv"
    if not p.is_file():
        return []
    with p.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# The signature
# --------------------------------------------------------------------------- #
def test_a_service_whose_image_is_a_command_shell_is_the_finding(tmp_path):
    r"""`cmd /c ... > file 2>&1` installed as a service is not a service. This is
    the strongest indicator here and it needs no list at all."""
    rows = _run(tmp_path, [_event(
        "BTOBTO",
        r"%COMSPEC% /Q /c echo whoami ^> \\127.0.0.1\C$\__out 2^>^&1 > "
        r"C:\Windows\Temp\execute.bat & C:\Windows\Temp\execute.bat")])
    assert len(rows) == 1
    assert rows[0]["suspicious"] == "yes"
    ind = rows[0]["indicators"]
    assert "image_is_a_shell" in ind
    assert "output_redirected" in ind
    assert "random_uppercase" in ind
    assert "runs_as_system" in ind


def test_an_ordinary_driver_install_is_not_reported(tmp_path):
    """7045 fires for every service on the host. A detector that reports installs
    reports the machine."""
    assert _run(tmp_path, [_event(
        "vmxnet3 NDIS 6 Ethernet Adapter Driver",
        r"\SystemRoot\System32\drivers\vmxnet3.sys", account="")]) == []


def test_a_binary_whose_name_merely_starts_with_cmd_is_not_a_shell(tmp_path):
    r"""`\...\cmdmon.exe` is a real product. Matching `cmd` unanchored would put a
    monitoring agent at the top of the table on every host that runs one."""
    assert _run(tmp_path, [_event(
        "CmdMonitor", r"C:\Program Files\Vendor\cmdmon.exe")]) == []


def test_the_deletion_at_the_end_only_counts_next_to_something_else(tmp_path):
    """An uninstall also removes a service. `not_in_registry` on its own would
    flag every retired printer driver on a five-year-old host."""
    gone = _run(tmp_path, [_event("OldPrinterSvc", r"C:\Program Files\P\p.exe")],
                registry=["w32time"])
    assert gone == [], "absent-from-registry alone is an uninstall"

    both = _run(tmp_path, [_event("ABCDEFGH", r"%COMSPEC% /c x.bat")],
                registry=["w32time"])
    assert "not_in_registry" in both[0]["indicators"]
    assert both[0]["in_registry"] == "no"


def test_a_service_that_survived_says_so(tmp_path):
    rows = _run(tmp_path, [_event("ABCDEFGH", r"%COMSPEC% /c x.bat")],
                registry=["abcdefgh", "w32time"])
    assert rows[0]["in_registry"] == "yes"
    assert "not_in_registry" not in rows[0]["indicators"]


def test_without_the_registry_the_column_is_empty_not_no(tmp_path):
    """reg_services may not have run. "Unknown" and "gone" are different answers,
    and writing `no` for the first invents the strongest half of the signature."""
    rows = _run(tmp_path, [_event("ABCDEFGH", r"%COMSPEC% /c x.bat")])
    assert rows[0]["in_registry"] == ""
    assert "not_in_registry" not in rows[0]["indicators"]


def test_a_dump_written_without_the_map_is_read_from_the_payload(tmp_path):
    """The bundled 7045 map fills PayloadData1..3; a dump produced without it
    carries the same fields in the raw JSON, and the finding must not depend on
    which one this case happened to get."""
    rows = _run(tmp_path, [_event("BTOBTO", r"%COMSPEC% /c x.bat > out.txt 2>&1",
                                  mapped=False)])
    assert len(rows) == 1 and rows[0]["service_name"] == "BTOBTO"
    assert rows[0]["suspicious"] == "yes"


def test_three_weak_indicators_together_are_a_finding(tmp_path):
    rows = _run(tmp_path, [_event("A1B2C3D4E5", r"C:\Users\Public\svc.exe")],
                registry=["w32time"])
    assert rows[0]["suspicious"] == "yes"
    assert "image_is_a_shell" not in rows[0]["indicators"]


def test_one_weak_indicator_is_reported_unflagged(tmp_path):
    """A service running from ProgramData is worth a row and is not a finding."""
    rows = _run(tmp_path, [_event("VendorAgent", r"C:\ProgramData\Vendor\agent.exe")])
    assert len(rows) == 1 and rows[0]["suspicious"] == ""


# --------------------------------------------------------------------------- #
# What the community list may and may not do
# --------------------------------------------------------------------------- #
def test_the_list_names_the_tool_behind_a_fixed_service_name(tmp_path):
    rows = _run(tmp_path, [_event("PSEXESVC", r"C:\Windows\PSEXESVC.exe")],
                listed=[{"service_name": "PSEXESVC", "metadata_tool_name": "PsExec",
                         "metadata_tool_category": "Lateral Movement",
                         "metadata_tool_type": "offensive_tool",
                         "metadata_severity": "high",
                         "metadata_reference": "https://example.invalid/psexec"}])
    assert rows[0]["tool"] == "PsExec"
    assert rows[0]["suspicious"] == "yes"
    assert rows[0]["reference"].startswith("https://")


def test_greyware_is_reported_and_never_flagged(tmp_path):
    """PDQ and the RMM agents are on the list and on every managed estate. A
    detector that flags the deployment tool is a detector that gets turned off."""
    rows = _run(tmp_path, [_event("PDQDeployRunner-1", r"C:\Windows\AdminArsenal\p.exe")],
                listed=[{"service_name": "PDQDeployRunner-*",
                         "metadata_tool_name": "PDQ",
                         "metadata_tool_category": "Lateral Movement",
                         "metadata_tool_type": "greyware_tool",
                         "metadata_severity": "low"}])
    assert rows[0]["tool"] == "PDQ" and rows[0]["suspicious"] == ""
    assert "known_greyware" in rows[0]["indicators"]


def test_the_finding_survives_a_missing_list(tmp_path):
    """The lists arrive with `aeng update`. A fresh install has none, and the
    structural detectors are the ones that carried the case."""
    rows = _run(tmp_path, [_event("BTOBTO", r"%COMSPEC% /c x.bat > o.txt 2>&1")])
    assert rows[0]["suspicious"] == "yes" and rows[0]["tool"] == ""


def test_a_list_pattern_is_anchored_not_a_substring(tmp_path):
    r"""`\Defender` is a real list entry (a backdoor's task name). Matched as a
    substring it covers every Defender service on every healthy machine."""
    assert _awesome.to_regex("Defender").search("WinDefendService") is None
    assert _awesome.to_regex("Defender").search("Defender") is not None
    assert _awesome.to_regex("*Defender*").search("WinDefendXDefenderY") is not None
    assert _awesome.to_regex("Live_*").search("Live_abc") is not None
    assert _awesome.to_regex("Live_*").search("xLive_abc") is None


def test_an_offensive_entry_wins_over_a_greyware_one(tmp_path):
    """A name on the list twice is reported at its more serious reading."""
    entries = [
        _awesome.Entry(pattern=_awesome.to_regex("*svc*"), raw="*svc*",
                       tool="Grey", kind="greyware_tool"),
        _awesome.Entry(pattern=_awesome.to_regex("badsvc"), raw="badsvc",
                       tool="Bad", kind="offensive_tool"),
    ]
    assert _awesome.match(entries, "badsvc").tool == "Bad"


def test_an_absent_list_file_loads_as_empty_not_an_error(tmp_path):
    assert _awesome.load(tmp_path, "not_there.csv", key="service_name") == []


def test_no_system_channel_skips(tmp_path):
    with pytest.raises(HandlerSkip):
        S.run(_Ctx(tmp_path, tmp_path / "out"))
