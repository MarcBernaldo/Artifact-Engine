"""Alerts gathered by artifact: one table per artifact, the sources untouched.

All values are synthetic."""

import csv
import logging
from pathlib import Path

from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import _alertgroups


def _table(path: Path, header: list[str], rows: list[list]) -> None:
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


def _run(module, machine: Path) -> Path:
    out = machine / "CSVs" / "Detections" / ".work_alert_groups"
    out.mkdir(parents=True, exist_ok=True)
    module.run(ParserContext(evidence=machine, out=out, tools=machine, assets=machine,
                             machine_name="HOST-01", volume="live",
                             log=logging.getLogger("aeng.test")))
    return out


def test_windows_gathers_by_artifact(tmp_path):
    from artifact_engine.handlers import win_alert_groups as W
    m = tmp_path / "HOST-01"
    det, fs, ex = m / "CSVs" / "Detections", m / "CSVs" / "Filesystem", m / "CSVs" / "Execution"
    _table(det / "ransomware_traces.csv",
           ["kind", "marker", "files", "first_modified_utc", "example", "note", "suspicious"],
           [["extension", ".locked", 900, "2024-01-02T03:04:05", "C:\\d\\a.docx.locked", "", "yes"]])
    # a timestomp table left by an engine before v0.7.161 is not gathered
    _table(fs / "timestomp.csv",
           ["path", "si_created_utc", "fn_created_utc", "delta_days", "note", "suspicious"],
           [["C:\\Users\\Public\\x.exe", "2019-01-01T00:00:00", "2024-01-01T00:00:00", 1826,
             "", "yes"],
            ["C:\\Windows\\y.dll", "2020-01-01T00:00:00", "2020-01-02T00:00:00", 1, "", ""]])
    _table(det / "byovd.csv",
           ["category", "known_driver", "amcache_name", "path", "sha1", "first_seen_utc"],
           [["vulnerable", "drv", "drv.sys", "C:\\t\\drv.sys", "a" * 40, "2024-01-01"],
            ["malicious", "bad", "bad.sys", "C:\\t\\bad.sys", "b" * 40, "2024-01-02"]])
    _table(det / "rmm.csv", ["tool", "match", "path", "sources", "first_seen_utc",
                             "last_seen_utc", "runs", "users", "sha1"],
           [["AnyRemote", "ar.exe", "C:\\t\\ar.exe", "amcache, bam", "", "", "", "", ""]])
    _table(det / "suspicious_tools.csv", ["category", "binary", "path", "sources",
                                          "first_seen_utc", "last_seen_utc", "runs", "users", "sha1"],
           [["credential_theft", "mimikatz.exe", "C:\\t\\mimikatz.exe", "prefetch", "2024-01-03",
             "2024-01-03", 2, "", ""]])
    # consolehost's own flag column is no longer read: cmd_hunt covers the history
    _table(ex / "consolehost.csv", ["id", "user", "flag", "command"],
           [[1, "jdoe", "", "Get-ChildItem"], [2, "jdoe", "mimikatz", "Invoke-Mimikatz"]])
    _table(det / "suspicious_commands.csv", ["category", "source", "who", "command",
                                             "first_seen_utc", "last_seen_utc", "count"],
           [["credential_theft", "powershell_history", "jdoe", "Invoke-Mimikatz", "", "", 1]])
    _table(det / "exfil_commands.csv", ["severity", "tool", "detect_type", "purpose", "source",
                                        "who", "command", "first_seen_utc", "last_seen_utc",
                                        "count", "pattern"],
           [["high", "rclone", "exfil_action", "", "process", "pid 9 rclone.exe",
             "rclone copy C:\\d mega:x", "2024-01-04", "2024-01-04", 1, ""]])
    # a parser's scratch copy is never read
    _table(det / ".work_rmm" / "rmm.csv", ["tool", "path"], [["Decoy", "C:\\decoy.exe"]])

    out = _run(W, m)
    mft = _read(out / "alerts_mft.csv")
    assert [(r["alert"], r["severity"], r["source_table"]) for r in mft] == [
        ("ransomware: extension", "high", "ransomware_traces")]
    assert mft[0]["subject"] == "C:\\d\\a.docx.locked"
    assert mft[0]["time_utc"] == "2024-01-02T03:04:05"
    assert "marker=.locked" in mft[0]["detail"] and "suspicious" not in mft[0]["detail"]
    amc = _read(out / "alerts_execution.csv")
    assert [(r["alert"], r["severity"]) for r in amc] == [
        ("byovd: malicious", "high"), ("byovd: vulnerable", "medium"), ("rmm: AnyRemote", "medium"),
        ("tool: credential_theft", "medium")]
    assert "Decoy" not in (out / "alerts_execution.csv").read_text(encoding="utf-8")
    shell = _read(out / "alerts_shell.csv")
    assert [(r["alert"], r["severity"], r["subject"]) for r in shell] == [
        ("exfil: rclone", "high", "rclone copy C:\\d mega:x"),
        ("shell: credential_theft", "medium", "Invoke-Mimikatz")]


def test_linux_gathers_by_artifact_and_writes_nothing_empty(tmp_path):
    from artifact_engine.handlers import lin_alert_groups as L
    m = tmp_path / "HOST-01"
    _table(m / "CSVs" / "Detections" / "gtfobins.csv",
           ["user", "shell", "id", "binary", "function", "sudo", "command"],
           [["jdoe", "bash", 1, "vim", "shell", "", "vim -c ':!sh'"],
            ["jdoe", "bash", 2, "find", "shell", "yes", "sudo find . -exec /bin/sh \\;"]])
    out = _run(L, m)
    shell = _read(out / "alerts_shell.csv")
    assert [(r["alert"], r["severity"]) for r in shell] == [
        ("gtfobins: shell", "high"), ("gtfobins: shell", "medium")]
    assert not (out / "alerts_bodyfile.csv").exists()     # no source table, no table


def test_every_spec_names_a_table_its_os_writes():
    """A renamed source table would silently drop out of its group."""
    handlers = Path(__file__).resolve().parents[1] / "src" / "artifact_engine" / "handlers"
    for os_name, groups in _alertgroups.SPECS.items():
        prefix = "win_" if os_name == "windows" else "lin_"
        text = "".join(f.read_text(encoding="utf-8") for f in handlers.glob(f"{prefix}*.py"))
        text += (handlers / "_ransom.py").read_text(encoding="utf-8")
        text += (handlers / "_exfil.py").read_text(encoding="utf-8")     # shared writer
        for specs in groups.values():
            for table, *_ in specs:
                assert f'"{table}.csv"' in text, (os_name, table)
