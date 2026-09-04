r"""Scheduled tasks, and telling a removal from an update.

Event 106/141 fire constantly on a healthy machine -- every vendor updater
re-registers its task by deleting it first -- so the whole difficulty is the same
one the service handler has: a detector that reports task churn reports the
machine. These tests pin the order rule that separates the two readings, the
things only the event log knows about a task that no longer exists, and the two
places the handler deliberately stays quiet.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _awesome, _evtx
from artifact_engine.handlers import win_task_installs as T


class _Ctx:
    def __init__(self, evidence: Path, out: Path):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "C"
        self.log = None


_COLS = ["RecordNumber", "TimeCreated", "EventId", "Channel", "Provider",
         "UserName", "ExecutableInfo", "PayloadData1", "PayloadData2", "Payload"]


def _event(eid: str, task: str, when: str, user: str = "EXAMPLE\\jdoe",
           action: str = "", mapped: bool = True) -> dict:
    row = {c: "" for c in _COLS}
    row.update({"RecordNumber": "1", "TimeCreated": when, "EventId": eid,
                "Channel": "Microsoft-Windows-TaskScheduler/Operational",
                "Provider": "Microsoft-Windows-TaskScheduler"})
    if mapped:
        row.update({"PayloadData1": f"Task: {task}", "UserName": user,
                    "ExecutableInfo": action})
    else:
        row["Payload"] = json.dumps({"EventData": {"Data": [
            {"@Name": "TaskName", "#text": task},
            {"@Name": "UserContext", "#text": user},
            {"@Name": "ActionName", "#text": action}]}})
    return row


def _write_evtx(tmp_path: Path, events: list[dict]) -> None:
    d = tmp_path / "CSVs" / "EventLogs"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "evtx_tsch.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_COLS)
        w.writeheader()
        for e in events:
            w.writerow({c: e.get(c, "") for c in _COLS})


def _write_disk(tmp_path: Path, tasks: dict[str, str]) -> None:
    d = tmp_path / "CSVs" / "Persistence"
    d.mkdir(parents=True, exist_ok=True)
    cols = ["task", "author", "created_local", "runas", "runlevel", "hidden",
            "disabled", "trigger", "command", "suspicious"]
    with (d / "tasks_disk.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for name, cmd in tasks.items():
            w.writerow({c: "" for c in cols} | {"task": name, "command": cmd})


def _write_list(tmp_path: Path, rows: list[dict]) -> None:
    d = tmp_path / _awesome.DIR
    d.mkdir(parents=True, exist_ok=True)
    cols = ["TaskName", "TaskCommand", "TaskArguments", "metadata_tool",
            "metadata_tool_category", "metadata_tool_type", "metadata_link",
            "metadata_severity", "metadata_comment", "metadata_reference"]
    with (d / T._TASKS_LIST).open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})


def _run(tmp_path: Path, events: list[dict] | None = None,
         disk: dict[str, str] | None = None,
         listed: list[dict] | None = None) -> list[dict]:
    if events is not None:
        _write_evtx(tmp_path, events)
    if disk is not None:
        _write_disk(tmp_path, disk)
    if listed is not None:
        _write_list(tmp_path, listed)
    T.run(_Ctx(tmp_path, tmp_path / "out"))
    p = tmp_path / "out" / "task_installs.csv"
    if not p.is_file():
        return []
    with p.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# Order is the whole difference
# --------------------------------------------------------------------------- #
def test_a_delete_before_the_registration_is_an_update_not_a_removal(tmp_path):
    """Windows re-registers a task by deleting it first. Reading that as a removal
    reports every vendor updater on the machine."""
    rows = _run(tmp_path, [
        _event("141", "\\VendorUpdate", "2026-05-19 03:00:00.0000000"),
        _event("106", "\\VendorUpdate", "2026-05-19 03:00:01.0000000"),
    ])
    assert rows == []


def test_registered_then_deleted_is_reported_and_not_flagged_on_its_own(tmp_path):
    """A vendor that removes its own task at the end of an upgrade does exactly
    this. It is worth a row; it is not a finding."""
    rows = _run(tmp_path, [
        _event("106", "\\VendorUpdate", "2026-05-19 03:00:00.0000000"),
        _event("141", "\\VendorUpdate", "2026-05-20 04:00:00.0000000"),
    ])
    assert len(rows) == 1
    assert rows[0]["indicators"] == "registered_then_deleted"
    assert rows[0]["suspicious"] == ""


def test_registered_ran_and_gone_inside_the_hour_is_the_finding(tmp_path):
    rows = _run(tmp_path, [
        _event("106", "\\Updater", "2026-05-19 11:00:00.0000000"),
        _event("200", "\\Updater", "2026-05-19 11:00:04.0000000",
               action=r"C:\Windows\Temp\a.exe"),
        _event("141", "\\Updater", "2026-05-19 11:02:00.0000000"),
    ])
    assert rows[0]["suspicious"] == "yes"
    assert "short_lived" in rows[0]["indicators"]
    assert "ran_before_deletion" in rows[0]["indicators"]
    assert rows[0]["lifespan_minutes"] == "2"


def test_a_long_lived_task_that_ran_is_not_short_lived(tmp_path):
    rows = _run(tmp_path, [
        _event("106", "\\Backup", "2026-01-01 01:00:00.0000000"),
        _event("201", "\\Backup", "2026-03-01 01:00:00.0000000",
               action=r"C:\Program Files\Vendor\backup.exe"),
        _event("141", "\\Backup", "2026-05-19 01:00:00.0000000"),
    ])
    assert "short_lived" not in rows[0]["indicators"]
    assert rows[0]["suspicious"] == ""


# --------------------------------------------------------------------------- #
# What only the log knows
# --------------------------------------------------------------------------- #
def test_the_account_and_the_command_survive_a_task_that_does_not(tmp_path):
    """Nothing is left on disk or in the TaskCache. This is the only record."""
    rows = _run(tmp_path, [
        _event("106", "\\WinUpdate", "2026-05-19 11:00:00.0000000",
               user="EXAMPLE\\svc_backup"),
        _event("200", "\\WinUpdate", "2026-05-19 11:00:02.0000000",
               action=r"C:\Users\Public\p.exe"),
        _event("141", "\\WinUpdate", "2026-05-19 11:00:30.0000000"),
    ], disk={"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag": "defrag.exe"})
    assert rows[0]["registered_by"] == "EXAMPLE\\svc_backup"
    assert rows[0]["action"] == r"C:\Users\Public\p.exe"
    assert rows[0]["on_disk"] == "no"
    assert "gone_from_disk" in rows[0]["indicators"]
    assert rows[0]["source"] == "eventlog"
    assert rows[0]["runs"] == "1"


def test_without_the_disk_store_the_column_is_empty_not_no(tmp_path):
    """tasks_disk may not have run. "Unknown" and "gone" are different answers, and
    writing `no` for the first invents an indicator on every such case."""
    rows = _run(tmp_path, [
        _event("106", "\\Updater", "2026-05-19 11:00:00.0000000"),
        _event("141", "\\Updater", "2026-05-19 11:05:00.0000000"),
    ])
    assert rows[0]["on_disk"] == ""
    assert "gone_from_disk" not in rows[0]["indicators"]


def test_a_task_still_on_disk_says_both(tmp_path):
    rows = _run(tmp_path, [
        _event("106", "\\Updater", "2026-05-19 11:00:00.0000000"),
        _event("141", "\\Updater", "2026-05-19 11:05:00.0000000"),
    ], disk={"\\Updater": r"C:\Program Files\V\u.exe"})
    assert rows[0]["source"] == "both" and rows[0]["on_disk"] == "yes"
    assert "gone_from_disk" not in rows[0]["indicators"]


def test_an_action_that_is_a_command_shell_on_a_removed_task_is_the_finding(tmp_path):
    rows = _run(tmp_path, [
        _event("106", "\\SysHealth", "2026-05-19 11:00:00.0000000"),
        _event("200", "\\SysHealth", "2026-05-19 11:00:01.0000000",
               action=r"%COMSPEC% /c whoami"),
        _event("141", "\\SysHealth", "2026-05-20 12:00:00.0000000"),
    ])
    assert rows[0]["suspicious"] == "yes"
    assert "action_is_a_shell" in rows[0]["indicators"]


def test_a_binary_whose_name_merely_starts_with_cmd_is_not_a_shell(tmp_path):
    assert not T.action_is_a_shell(r"C:\Program Files\Vendor\cmdmon.exe")
    assert T.action_is_a_shell(r"C:\Windows\System32\cmd.exe")
    assert T.action_is_a_shell("%COMSPEC% /Q /c x.bat")


def test_a_download_cradle_flags_on_its_own(tmp_path):
    """A living task with this action is already reported by tasks_disk; for a
    deleted one the channel is the only place the command survives."""
    rows = _run(tmp_path, [
        _event("106", "\\Health", "2026-05-19 11:00:00.0000000"),
        _event("200", "\\Health", "2026-05-19 11:00:01.0000000",
               action="powershell -nop -w hidden -enc SQBFAFgA"),
    ])
    assert rows[0]["suspicious"] == "yes"
    assert "download_or_encoded_command" in rows[0]["indicators"]


def test_an_ordinary_task_that_merely_ran_is_not_a_row(tmp_path):
    """200/201 fire for every task on the machine, all day."""
    assert _run(tmp_path, [
        _event("201", "\\Microsoft\\Windows\\Windows Error Reporting\\QueueReporting",
               "2026-05-19 06:41:30.0000000", action=r"%windir%\system32\wermgr.exe"),
    ]) == []


# --------------------------------------------------------------------------- #
# What the community list may and may not do
# --------------------------------------------------------------------------- #
def test_the_list_names_the_tooling_behind_a_task_still_on_disk(tmp_path):
    """No events survive for it, so the lifecycle has nothing to say. The
    attribution has nowhere else in the engine to live."""
    rows = _run(tmp_path, [], disk={"\\Microsoft_Auto_Scheduler": r"C:\x\a.exe"},
                listed=[{"TaskName": "\\Microsoft_Auto_Scheduler",
                         "metadata_tool": "Example Ransomware",
                         "metadata_tool_category": "Ransomware",
                         "metadata_tool_type": "offensive_tool",
                         "metadata_severity": "high",
                         "metadata_link": "https://example.invalid/report"}])
    assert rows[0]["source"] == "disk"
    assert rows[0]["tool"] == "Example Ransomware"
    assert rows[0]["suspicious"] == "yes"
    assert rows[0]["reference"].startswith("https://")


def test_greyware_is_reported_and_never_flagged(tmp_path):
    rows = _run(tmp_path, [], disk={"\\PDQInventory": r"C:\Windows\AdminArsenal\p.exe"},
                listed=[{"TaskName": "\\PDQ*", "metadata_tool": "PDQ",
                         "metadata_tool_type": "greyware_tool",
                         "metadata_severity": "low"}])
    assert rows[0]["tool"] == "PDQ" and rows[0]["suspicious"] == ""
    assert "known_greyware" in rows[0]["indicators"]


def test_an_unlisted_task_still_on_disk_is_not_re_reported(tmp_path):
    """tasks_disk already carries every registered task in full."""
    assert _run(tmp_path, [], disk={"\\Something": r"C:\Windows\Temp\x.exe"}) == []


def test_the_finding_survives_a_missing_list(tmp_path):
    rows = _run(tmp_path, [
        _event("106", "\\Updater", "2026-05-19 11:00:00.0000000"),
        _event("200", "\\Updater", "2026-05-19 11:00:02.0000000",
               action=r"C:\Windows\Temp\a.exe"),
        _event("141", "\\Updater", "2026-05-19 11:01:00.0000000"),
    ])
    assert rows[0]["suspicious"] == "yes" and rows[0]["tool"] == ""


# --------------------------------------------------------------------------- #
# Reading the row whichever way it arrived
# --------------------------------------------------------------------------- #
def test_a_dump_written_without_the_map_reads_the_same(tmp_path):
    rows = _run(tmp_path, [
        _event("106", "\\Updater", "2026-05-19 11:00:00.0000000",
               user="EXAMPLE\\jdoe", mapped=False),
        _event("200", "\\Updater", "2026-05-19 11:00:02.0000000",
               action=r"C:\Windows\Temp\a.exe", mapped=False),
        _event("141", "\\Updater", "2026-05-19 11:01:00.0000000", mapped=False),
    ])
    assert len(rows) == 1 and rows[0]["registered_by"] == "EXAMPLE\\jdoe"
    assert rows[0]["suspicious"] == "yes"


def test_an_unparseable_timestamp_keeps_the_pair_and_drops_the_duration(tmp_path):
    """The registration and the removal are still facts; the minutes between them
    are not, and inventing a 0 would flag it as short-lived."""
    rows = _run(tmp_path, [
        _event("106", "\\Updater", "not a date"),
        _event("141", "\\Updater", "also not a date"),
    ])
    assert rows[0]["lifespan_minutes"] == ""
    assert "short_lived" not in rows[0]["indicators"]


def test_the_time_reader_accepts_both_stamp_shapes(tmp_path):
    assert _evtx.when("2026-05-19 11:22:33.1234567") is not None
    assert _evtx.when("2026-05-19T11:22:33.0000000+02:00") is not None
    assert _evtx.when("") is None and _evtx.when("2026-13-40 99:99:99") is None


def test_no_task_source_at_all_skips(tmp_path):
    with pytest.raises(HandlerSkip):
        T.run(_Ctx(tmp_path, tmp_path / "out"))
