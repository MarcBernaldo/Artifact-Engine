"""Render lateral_movement.html from SYNTHETIC data so the JS can be exercised in a
browser. Invented hosts/accounts only -- never case data (this folder is gitignored,
but the rule holds anyway).

NOTE ON ADDRESSES: the internet sources here are plain routable placeholders (45.x,
91.x), NOT RFC 5737 documentation ranges. Python's `ipaddress.is_global` reports
203.0.113.x / 198.51.100.x / 192.0.2.x as NON-global (they sit in the special-purpose
registry), so a doc-range address gets the `external` role and the "public IP only"
filter finds nothing -- which looks exactly like a broken filter. Real attacker IPs
are genuinely global, so only this preview needs the substitution."""
import csv
import json
import random
from pathlib import Path

from artifact_engine.core import lateral
from artifact_engine.core.detector import Machine, Volume

HDR = ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider",
       "Channel", "ProcessId", "ThreadId", "Computer", "ChunkNumber", "UserId",
       "MapDescription", "UserName", "RemoteHost", "PayloadData1", "PayloadData2",
       "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo",
       "HiddenRecord", "SourceFile", "Keywords", "ExtraDataOffset", "Payload"]
OUT = Path(__file__).resolve().parent


def machine(name, ips):
    p = OUT / name
    (p / "CSVs" / "SystemInfo").mkdir(parents=True, exist_ok=True)
    (p / "CSVs" / "EventLogs").mkdir(parents=True, exist_ok=True)
    (p / "CSVs" / "SystemInfo" / "machine_info.json").write_text(
        json.dumps({"machine_name": name, "fqdn": f"{name}.corp.local", "IPs": ips}),
        encoding="utf-8")
    return Machine(name, "windows", "kape", "windows_kape", p, "src", [Volume("C", p, True)])


def write(m, fname, rows):
    with (m.path / "CSVs" / "EventLogs" / fname).open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=HDR)
        w.writeheader()
        for r in rows:
            w.writerow(r)


random.seed(7)
dc = machine("DC01", ["10.10.0.1"])
fs = machine("FS01", ["10.10.0.5"])
wk = machine("WKSTN07", ["10.10.0.20"])
sec_dc, sec_fs, sec_wk, rdp_wk = [], [], [], []

# an internet spray campaign: many sources, only failures (must collapse)
for i in range(120):
    src = f"45.66.{i // 254}.{i % 254 + 1}"
    for n in range(random.randint(1, 40)):
        sec_dc.append({"TimeCreated": f"2026-03-0{1 + i % 8} 0{n % 9}:15:00", "EventId": "4625",
                       "Computer": "DC01.corp.local", "UserName": "CORP\\administrator",
                       "RemoteHost": f"- ({src})", "PayloadData1": "Target: CORP\\administrator",
                       "PayloadData2": "LogonType 10"})
# the one that got in from the internet, then pivots
sec_wk.append({"TimeCreated": "2026-03-09 21:40:00", "EventId": "4624", "Computer": "WKSTN07.corp.local",
               "UserName": "CORP\\jdoe", "RemoteHost": "- (91.207.8.44)",
               "PayloadData1": "Target: CORP\\jdoe", "PayloadData2": "LogonType 10"})
sec_fs.append({"TimeCreated": "2026-03-09 22:05:00", "EventId": "4624", "Computer": "FS01.corp.local",
               "UserName": "CORP\\jdoe", "RemoteHost": "- (10.10.0.20)",
               "PayloadData1": "Target: CORP\\jdoe", "PayloadData2": "LogonType 10"})
sec_fs.append({"TimeCreated": "2026-03-09 22:30:00", "EventId": "4648", "Computer": "FS01.corp.local",
               "UserName": "CORP\\svc_backup", "RemoteHost": "-:-",
               "PayloadData1": "Target: CORP\\svc_backup", "PayloadData2": "TargetServerName: DC01"})
# an anonymous null session, and routine internal RDP that must NOT be flagged
sec_fs.append({"TimeCreated": "2026-03-08 03:12:00", "EventId": "4624", "Computer": "FS01.corp.local",
               "UserName": "ANONYMOUS LOGON", "RemoteHost": "- (185.220.101.77)",
               "PayloadData1": "Target: ANONYMOUS LOGON", "PayloadData2": "LogonType 3"})
for i in range(15):
    rdp_wk.append({"TimeCreated": f"2026-03-0{1 + i % 8} 09:00:00", "EventId": "21",
                   "Computer": "WKSTN07.corp.local", "UserName": "CORP\\helpdesk",
                   "RemoteHost": f"192.168.10.{i + 2}", "PayloadData1": "Session ID: 1"})

write(dc, "evtx_security.csv", sec_dc)
write(fs, "evtx_security.csv", sec_fs)
write(wk, "evtx_security.csv", sec_wk)
write(wk, "evtx_rdpSessions.csv", rdp_wk)

print(lateral.build([dc, fs, wk], OUT))
print("->", OUT / "lateral_movement.html")
