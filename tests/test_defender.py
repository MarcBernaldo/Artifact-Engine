r"""What Defender saw, and whether it did anything about it.

Three things a bare EvtxECmd dump of this channel cannot answer, and this module
exists for. A `CmdLine:_` detection read as a path is a file with a very strange
name; read as what it says it is, it is the command line -- and on a host with no
Sysmon that is the only surviving record of execution. Defender retries, so
"detected" and "removed" live in different events of the same detection_id and
neither one alone is the answer. And 5001 is not a separate question from the
detections around it.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _evtx
from artifact_engine.handlers import win_defender as D


class _Ctx:
    def __init__(self, evidence: Path, out: Path):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "C"
        self.log = None


_COLS = ["RecordNumber", "TimeCreated", "EventId", "Channel", "Provider",
         "UserName", "ExecutableInfo", "PayloadData1", "PayloadData2",
         "PayloadData3", "PayloadData4", "PayloadData5", "Payload"]


def _detection(eid: str = "1117", *, path: str = r"file:_C:\Users\jdoe\a.exe",
               threat: str = "Trojan:Win32/Example",
               desc: str = "Trojan (Severe)", detection_id: str = "{DID-1}",
               process: str = "", user: str = "HOST-01\\jdoe",
               action_id: str = "2", action_name: str = "Quarantine",
               error: str = "0x00000000", source: str = "Real-Time Protection",
               when: str = "2026-05-19 11:22:33.0000000",
               mapped: bool = True) -> dict:
    payload = {"Action ID": action_id, "Action Name": action_name,
               "Error Code": error, "Source Name": source,
               "Remediation User": "NT AUTHORITY\\SYSTEM"}
    if not mapped:
        payload.update({"Threat Name": threat, "Detection ID": detection_id,
                        "Path": path, "Process Name": process,
                        "Detection User": user, "Category Name": "Trojan",
                        "Severity Name": "Severe"})
    row = {c: "" for c in _COLS}
    row.update({"RecordNumber": "1", "TimeCreated": when, "EventId": eid,
                "Channel": "Microsoft-Windows-Windows Defender/Operational",
                "Provider": "Microsoft-Windows-Windows Defender",
                "Payload": json.dumps(payload)})
    if mapped:
        row.update({"UserName": f"Detection User: {user}",
                    "ExecutableInfo": path,
                    "PayloadData1": f"Malware name: {threat}",
                    "PayloadData2": f"Description: {desc}",
                    "PayloadData4": f"Process (if real-time detection): {process}",
                    "PayloadData5": f"Detection ID: {detection_id}"})
    return row


def _tamper(eid: str = "5001", old: str = "0x1", new: str = "0x0") -> dict:
    row = {c: "" for c in _COLS}
    row.update({"RecordNumber": "2", "TimeCreated": "2026-05-19 10:00:00.0000000",
                "EventId": eid, "PayloadData1": f"Old Value: {old}",
                "PayloadData2": f"New Value: {new}",
                "Payload": json.dumps({"Process Name": "powershell.exe",
                                       "User": "HOST-01\\jdoe"})})
    return row


def _run(tmp_path: Path, events: list[dict]) -> list[dict]:
    d = tmp_path / "CSVs" / "EventLogs"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "evtx_defender.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_COLS)
        w.writeheader()
        for e in events:
            w.writerow({c: e.get(c, "") for c in _COLS})
    D.run(_Ctx(tmp_path, tmp_path / "out"))
    p = tmp_path / "out" / "defender_detections.csv"
    if not p.is_file():
        return []
    with p.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# The command line
# --------------------------------------------------------------------------- #
def test_a_script_detection_is_a_command_line_not_a_path(tmp_path):
    """Read as a path this is a file with a very strange name. Read as what it
    says it is, it is the only record of what ran."""
    rows = _run(tmp_path, [_detection(
        path=r"CmdLine:_powershell.exe -nop -w hidden -enc SQBFAFgA")])
    assert rows[0]["command_line"].startswith("powershell.exe -nop")
    assert rows[0]["path"] == ""


def test_a_detection_carrying_both_keeps_both(tmp_path):
    rows = _run(tmp_path, [_detection(
        path=r"file:_C:\Users\jdoe\a.ps1; CmdLine:_powershell -File a.ps1")])
    assert rows[0]["path"] == r"C:\Users\jdoe\a.ps1"
    assert rows[0]["command_line"] == "powershell -File a.ps1"


def test_a_resource_with_no_scheme_is_still_a_path(tmp_path):
    """Older Defender writes a bare path. Dropping it would lose the file."""
    rows = _run(tmp_path, [_detection(path=r"C:\Users\jdoe\a.exe")])
    assert rows[0]["path"] == r"C:\Users\jdoe\a.exe"


def test_a_process_resource_is_neither_a_path_nor_a_command(tmp_path):
    files, cmds, other = D.split_resources(
        r"process:_pid:4242,ProcessStart:133000000000000000")
    assert files == "" and cmds == ""
    assert other.startswith("process:_pid:4242")


# --------------------------------------------------------------------------- #
# Whether it was cleaned
# --------------------------------------------------------------------------- #
def test_a_detection_never_acted_on_is_the_flagged_row(tmp_path):
    """Defender saw it and it ran anyway. That is the row worth reading."""
    rows = _run(tmp_path, [_detection(action_id="9", action_name="No Action")])
    assert rows[0]["outcome"] == "NOT remediated"
    assert rows[0]["suspicious"] == "yes"


def test_a_quarantined_threat_is_an_incident_that_ended(tmp_path):
    rows = _run(tmp_path, [_detection(action_id="2", action_name="Quarantine")])
    assert rows[0]["outcome"] == "remediated" and rows[0]["suspicious"] == ""


def test_the_outcome_is_decided_across_the_retry_not_per_event(tmp_path):
    """Defender retries: action 9 and action 3 are two events of ONE attempt, and
    either one read alone gives the opposite answer to the truth."""
    rows = _run(tmp_path, [
        _detection("1116", action_id="9", action_name="No Action"),
        _detection("1117", action_id="3", action_name="Remove"),
    ])
    assert {r["outcome"] for r in rows} == {"remediated"}
    assert all(r["suspicious"] == "" for r in rows)


def test_two_detections_do_not_share_an_outcome(tmp_path):
    rows = _run(tmp_path, [
        _detection("1117", detection_id="{DID-1}", action_id="3", action_name="Remove"),
        _detection("1117", detection_id="{DID-2}", action_id="9", action_name="No Action"),
    ])
    by_id = {r["detection_id"]: r for r in rows}
    assert by_id["{DID-1}"]["outcome"] == "remediated"
    assert by_id["{DID-2}"]["outcome"] == "NOT remediated"
    assert by_id["{DID-2}"]["suspicious"] == "yes"


def test_a_detection_with_no_id_is_judged_alone_and_says_so(tmp_path):
    """No detection_id means no group to reason over. `unknown` is the honest
    answer; claiming `remediated` would be the dangerous one."""
    rows = _run(tmp_path, [_detection(detection_id="", action_id="",
                                      action_name="", mapped=True)])
    assert rows[0]["outcome"] == "unknown"


# --------------------------------------------------------------------------- #
# Tampering, in the same table
# --------------------------------------------------------------------------- #
def test_protection_being_switched_off_is_a_first_class_row(tmp_path):
    rows = _run(tmp_path, [_tamper("5001")])
    assert rows[0]["kind"] == "tamper"
    assert "real-time protection DISABLED" in rows[0]["threat_name"]
    assert rows[0]["suspicious"] == "yes"
    assert rows[0]["process_name"] == "powershell.exe"


def test_a_configuration_change_carries_what_changed(tmp_path):
    rows = _run(tmp_path, [_tamper("5007", old="0x1", new="0x0")])
    assert "0x1 -> 0x0" in rows[0]["other_resources"]


def test_an_unremarkable_defender_event_is_not_a_row(tmp_path):
    """The channel carries signature updates and scan starts by the thousand."""
    quiet = {c: "" for c in _COLS}
    quiet.update({"EventId": "2000", "TimeCreated": "2026-05-19 09:00:00.0000000"})
    assert _run(tmp_path, [quiet]) == []


# --------------------------------------------------------------------------- #
# Reading the row whichever way it arrived
# --------------------------------------------------------------------------- #
def test_a_dump_written_without_the_map_reads_the_same(tmp_path):
    """The map fills PayloadData1..5 and ExecutableInfo; without it everything is
    in the raw JSON. The finding must not depend on which one this case got."""
    rows = _run(tmp_path, [_detection(mapped=False, action_id="9",
                                      action_name="No Action")])
    assert rows[0]["threat_name"] == "Trojan:Win32/Example"
    assert rows[0]["path"] == r"C:\Users\jdoe\a.exe"
    assert rows[0]["detection_id"] == "{DID-1}"
    assert rows[0]["suspicious"] == "yes"


def test_the_action_survives_an_id_with_no_name(tmp_path):
    rows = _run(tmp_path, [_detection(action_id="3", action_name="")])
    assert "remove" in rows[0]["action"].lower()
    assert rows[0]["outcome"] == "remediated"


def test_the_payload_reader_handles_the_xml_node_shape(tmp_path):
    """A named EventData field arrives flattened on some versions and as its XML
    node on others. A handler that knows one shape works on some hosts in a case
    and not others, which is worse than not working."""
    flat = json.dumps({"EventData": {"Action Name": "Quarantine"}})
    node = json.dumps({"EventData": {"Data": [
        {"@Name": "Action Name", "#text": "Quarantine"}]}})
    assert _evtx.payload_field(flat, "action name") == "Quarantine"
    assert _evtx.payload_field(node, "Action Name") == "Quarantine"


def test_an_unparseable_payload_does_not_lose_the_row(tmp_path):
    broken = _detection(action_id="9", action_name="No Action")
    broken["Payload"] = '{"Action Name": "No Action", TRUNCATED'
    rows = _run(tmp_path, [broken])
    assert len(rows) == 1 and rows[0]["outcome"] == "NOT remediated"


def test_no_defender_csv_skips(tmp_path):
    with pytest.raises(HandlerSkip):
        D.run(_Ctx(tmp_path, tmp_path / "out"))
