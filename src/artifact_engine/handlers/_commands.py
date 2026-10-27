"""Every command line a Windows machine kept, from every artifact that keeps one (v0.7.104).

The command-line sibling of `_execution`: each source is read once and yields
(source, who, text, time_utc) for one searcher (`win_cmd_hunt`) that runs every
command-line catalog over it.

  source             text                                       who            time (UTC)
  powershell_history ConsoleHost_history.txt, a line per entry  the profile    --
  process            LiveResponse Pslist CommandLine            pid + name     process start
  task               scheduled task command + arguments         run-as         --
  service            service ImagePath, arguments included      service name   key last write
  ps_host            Windows PowerShell 400/800 HostApplication account        event time
  ps_scriptblock     PowerShell Operational 4104 ScriptBlockText account        event time
                     (not a module manifest: it declares commands, runs none)
  ps_pipeline        PowerShell Operational 4103 Payload         account        event time
  sysmon             Sysmon 1 CommandLine                       account        event time

Security 4688 is deliberately not read: its table runs to hundreds of MB per
machine (the user's call, 2026-10-11). The live response is the live host's, so
a VSS volume never reads it.
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from artifact_engine.handlers._execution import utc
from artifact_engine.handlers._tables import find_table
from artifact_engine.handlers.win_consolehost import iter_history
from artifact_engine.handlers.win_liveresponse_velociraptor import (
    _artifact_key,
    _find_results,
    _read_jsonl,
)

csv.field_size_limit(10_000_000)

# A module manifest logged as a script block DECLARES its commands
# (`CmdletsToExport = ... Clear-EventLog ...`) and runs none of them: measured on a
# real case, every log_clearing hit in 4104 was Microsoft's own manifest.
_MANIFEST = re.compile(r"\b(?:CmdletsToExport|FunctionsToExport)\s*=", re.IGNORECASE)


def _table(csvs: Path, table: str):
    p = find_table(csvs, table)
    if p is None:
        return
    try:
        with open(p, encoding="utf-8-sig", errors="replace", newline="") as fh:
            yield from csv.DictReader(line.replace("\x00", "") for line in fh)
    except (OSError, csv.Error):
        return


def _event_data(payload: str) -> dict:
    """EvtxECmd's `Payload` column: {"EventData": {"Data": [{"@Name", "#text"}...]}}."""
    try:
        data = (json.loads(payload or "{}").get("EventData") or {}).get("Data")
    except (ValueError, AttributeError):
        return {}
    if isinstance(data, dict):
        data = [data]
    out = {}
    for d in data if isinstance(data, list) else []:
        if isinstance(d, dict) and d.get("@Name"):
            out[d["@Name"]] = d.get("#text") or ""
    return out


def history(ctx):
    for user, _seq, cmd in iter_history(Path(ctx.evidence)):
        yield "powershell_history", user, cmd, ""


def processes(ctx):
    if str(ctx.volume).upper().startswith("VSS"):
        return                                   # LiveResponse is the live host's
    results = _find_results(ctx)
    if results is None:
        return
    for f in results.glob("*.json"):
        if _artifact_key(f) != "Windows.System.Pslist":
            continue
        for p in _read_jsonl(f):
            who = f"pid {p.get('Pid')} {p.get('Name') or ''}".strip()
            yield "process", who, p.get("CommandLine") or "", utc(p.get("CreateTime"))


def tasks(csvs: Path):
    for r in _table(csvs, "tasks_disk"):
        yield "task", r.get("runas") or "", r.get("command") or "", ""


def services(csvs: Path):
    for r in _table(csvs, "reg_services"):
        if (r.get("ValueName") or "").lower() == "imagepath":
            name = (r.get("KeyPath") or "").rstrip("\\").rsplit("\\", 1)[-1]
            yield "service", name, r.get("ValueData") or "", utc(r.get("LastWriteTimestamp"))


def powershell_events(csvs: Path):
    for r in _table(csvs, "evtx_pwsh"):
        if r.get("EventId") in ("400", "800"):
            host = (r.get("PayloadData1") or "").partition("HostApplication=")[2]
            yield "ps_host", r.get("UserName") or "", host, utc(r.get("TimeCreated"))
    for r in _table(csvs, "evtx_pwshScrip"):
        event = r.get("EventId")
        if event not in ("4104", "4103"):
            continue
        data = _event_data(r.get("Payload") or "")
        text = data.get("ScriptBlockText", "") if event == "4104" else data.get("Payload", "")
        if event == "4104" and _MANIFEST.search(text):
            continue
        yield ("ps_scriptblock" if event == "4104" else "ps_pipeline",
               r.get("UserName") or r.get("UserId") or "", text, utc(r.get("TimeCreated")))


def sysmon(csvs: Path):
    for r in _table(csvs, "evtx_sysmon"):
        if r.get("EventId") == "1":
            yield "sysmon", r.get("UserName") or "", r.get("ExecutableInfo") or "", \
                utc(r.get("TimeCreated"))


def commands(ctx, csvs: Path):
    """Every (source, who, text, time_utc) the machine kept."""
    yield from history(ctx)
    yield from processes(ctx)
    for reader in (tasks, services, powershell_events, sysmon):
        yield from reader(csvs)
