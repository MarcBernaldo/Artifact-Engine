"""Handler: what in a memory image deserves a look first (v0.7.92).

The forty-odd Volatility tables of a memory unit are complete and unranked: the
injected region is row 212 of `mem_malfind`, the process nobody can see is the
difference between two tables, and a typosquatted `svch0st.exe` is one line of a
hundred and fifty. This reads those tables (never the image) and writes two:

- `mem_alerts` -- one row per thing that fired: severity, the rule, the process
  it concerns and the evidence, naming the table it came from. Every row is a
  finding, grouped in one table rather than one table per rule.
- `mem_processes` -- one row per process ever seen (active list and carved),
  with its parent, path, command line, account, connections and injected
  regions beside it, and `suspicious`/`severity`/`reasons` set from the alerts.
  This is the table the report's Findings section ranks, and the one to read a
  process's whole story in.

Severities are this module's claim and say so in the rule name: `high` is
something a healthy Windows does not do (a hidden process, a second lsass, an
unbacked executable region holding a PE header), `medium` is abuse-shaped but
seen in legitimate software, `low` is context worth having next to the rest.

Every rule reads tables a plugin may not have produced (a plugin can fail, or
find nothing). A missing table is not an error and costs only the rules built
on it -- and the tables that were missing are written into every alert-free
report as `mem_alerts` rows of rule `coverage`, so an empty alert table is
never mistaken for a clean image when it is an unread one.
"""

from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

from artifact_engine.core import netclass
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._indicators import load_indicators, match_labels
from artifact_engine.handlers._lincommon import write_csv

_HIGH, _MED, _LOW = "high", "medium", "low"
_RANK = {_HIGH: 3, _MED: 2, _LOW: 1, "": 0}

# Tables this handler reads; the first two are what makes a process list.
_TABLES = ("mem_pslist", "mem_psscan", "mem_pstree", "mem_cmdline", "mem_getsids",
           "mem_netscan", "mem_malfind", "mem_hollowprocesses", "mem_processghosting",
           "mem_pebmasquerade", "mem_psxview", "mem_drivermodule", "mem_svcdiff",
           "mem_skeleton_key", "mem_etwpatch", "mem_orphan_threads",
           "mem_suspicious_threads", "mem_yara")

# Who may start whom. A system process under any other parent is the shape of an
# injected or impersonated one. Parents that exit as part of boot (smss children,
# userinit) are allowed to be absent: only a PRESENT parent of the wrong name fires.
_PARENTS = {
    "smss.exe": {"system", "smss.exe"},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsaiso.exe": {"wininit.exe"},
    "lsm.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe", "msmpeng.exe"},
    "spoolsv.exe": {"services.exe"},
    "taskhostw.exe": {"svchost.exe"},
    "runtimebroker.exe": {"svchost.exe"},
    "dllhost.exe": {"svchost.exe", "services.exe"},
}
# One per boot. A second live one is an impostor (or a dump being run).
_SINGLETONS = {"lsass.exe", "services.exe", "wininit.exe", "lsaiso.exe", "smss.exe"}
# Names worth impersonating: a near miss of one of these is a disguise.
_SYSTEM_NAMES = sorted({*_PARENTS, "explorer.exe", "conhost.exe", "taskhost.exe",
                        "searchindexer.exe", "ctfmon.exe", "audiodg.exe", "dwm.exe"})
# The system binaries that only ever run out of the Windows directory.
_SYSTEM_DIR = re.compile(r"\\(windows|systemroot)\\(system32|syswow64|winsxs)\\",
                         re.IGNORECASE)
_USER_WRITABLE = re.compile(
    r"\\(appdata|temp|tmp|downloads|users\\public|programdata|perflogs|\$recycle\.bin)\\",
    re.IGNORECASE)

# Office/browser/reader spawning a shell: the macro and the exploit kit.
_SPAWN_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                  "onenote.exe", "mspub.exe", "msaccess.exe", "visio.exe",
                  "acrord32.exe", "acrobat.exe", "chrome.exe", "firefox.exe",
                  "msedge.exe", "iexplore.exe", "wordpad.exe"}
_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
           "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe",
           "certutil.exe", "wmic.exe", "msbuild.exe", "installutil.exe", "hh.exe"}

# Command lines that are the attack rather than evidence of software. (label, regex)
_CMDLINE = [
    (_HIGH, "shadow_copy_deletion",
     (r"vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|"
      r"wbadmin(\.exe)?\s+delete\s+catalog|bcdedit(\.exe)?.*recoveryenabled\s+no")),
    (_HIGH, "event_log_clearing", r"wevtutil(\.exe)?\s+(cl|clear-log)\b"),
    (_HIGH, "encoded_powershell",
     r"powershell.*\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[a-z0-9+/=]{20,}"),
    (_HIGH, "download_cradle",
     (r"downloadstring|downloadfile|invoke-webrequest|iwr\s+http|net\.webclient|"
      r"start-bitstransfer|frombase64string")),
    (_MED, "hidden_window", r"-w(indowstyle)?\s+h(idden)?\b"),
    (_MED, "lolbin_download",
     (r"certutil.*-urlcache|bitsadmin.*/transfer|mshta(\.exe)?\s+https?:|"
      r"regsvr32.*/i:https?:|rundll32.*javascript:")),
    (_MED, "credential_access",
     r"sekurlsa|lsadump|procdump.*lsass|comsvcs(\.dll)?.*minidump|ntdsutil.*ifm"),
]
_CMDLINE_RX = [(sev, label, re.compile(rx, re.IGNORECASE)) for sev, label, rx in _CMDLINE]

# A shell or script host talking to the internet is how a payload phones home.
_NET_SHELLS = _SHELLS | {"powershell_ise.exe"}

_ALERT_HEADER = ["severity", "rule", "pid", "process", "ppid", "parent", "path",
                 "detail", "source"]
_PROC_HEADER = ["pid", "ppid", "process", "parent", "path", "cmdline", "user",
                "session", "create_time", "exit_time", "found_by", "connections",
                "injected_regions", "severity", "reasons", "suspicious"]


_ABSENT = {"-", "N/A"}


def _read(base: Path, table: str) -> list[dict] | None:
    """The rows of one Volatility table, or None when the plugin left none.

    Volatility writes `-` and `N/A` for a value it could not read; here they are
    empty, so a rule never takes `-` for a path."""
    for p in base.rglob(f"{table}.csv"):
        with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            return [{k: ("" if (v or "").strip() in _ABSENT else v) for k, v in r.items()}
                    for r in csv.DictReader(fh)]
    return None


# The forms one Windows path takes in these tables: the kernel's device path,
# a drive letter, or the boot-time SystemRoot alias. Reduced to the part below
# the volume, lower-cased, before two of them are compared.
_VOLUME = re.compile(r"^(\\device\\harddiskvolume\d+|[a-z]:|\\\?\?\\[a-z]:)", re.IGNORECASE)


def _norm_path(path: str) -> str:
    p = (path or "").strip().lower()
    p = re.sub(r"^\\systemroot\\", r"\\windows\\", p)
    return _VOLUME.sub("", p)


def _plausible_name(name: str) -> bool:
    """A carved EPROCESS can be any bytes; a real one is named in printable ASCII."""
    return bool(name) and all(32 <= ord(c) < 127 for c in name)


def _int(v) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _base(name: str) -> str:
    return (name or "").strip().lower()


def _one_off(a: str, b: str) -> bool:
    """Edit distance exactly 1 (substitution, insertion or deletion)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def _impersonates(name: str) -> str:
    """The system name `name` is one keystroke away from, or ''."""
    if len(name) < 7 or name in _SYSTEM_NAMES:
        return ""
    for sysname in _SYSTEM_NAMES:
        # ImageFileName is cut at 14 characters: compare like with like.
        if _one_off(name, sysname[:14]) or _one_off(name, sysname):
            return sysname
    return ""


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


class _Alerts:
    def __init__(self) -> None:
        self.rows: list[list] = []
        self.by_pid: dict[int, list[tuple[str, str]]] = defaultdict(list)

    def add(self, sev: str, rule: str, proc: dict | None, detail: str, source: str,
            pid: int | None = None) -> None:
        proc = proc or {}
        pid = proc.get("pid", pid)
        self.rows.append([sev, rule, "" if pid is None else pid, proc.get("process", ""),
                          proc.get("ppid", ""), proc.get("parent", ""),
                          proc.get("path", ""), detail[:400], source])
        if pid is not None:
            self.by_pid[pid].append((sev, rule))


def _processes(t: dict) -> dict[int, dict]:
    """Every process seen, keyed by PID: the active list first, carved ones added."""
    procs: dict[int, dict] = {}
    for table in ("mem_pslist", "mem_psscan"):
        for r in t.get(table) or []:
            pid = _int(r.get("PID"))
            if pid is None:
                continue
            p = procs.setdefault(pid, {
                "pid": pid, "ppid": _int(r.get("PPID")), "process": r.get("ImageFileName", ""),
                "session": r.get("SessionId", ""), "create_time": r.get("CreateTime", ""),
                "exit_time": r.get("ExitTime", ""), "seen": set(), "path": "",
                "cmdline": "", "user": "", "connections": [], "injected": 0})
            p["seen"].add(table.removeprefix("mem_"))
    for r in t.get("mem_pstree") or []:
        p = procs.get(_int(r.get("PID")))
        if p is not None:
            p["path"] = (r.get("Path") or r.get("Audit") or "").strip()
            p["cmdline"] = p["cmdline"] or (r.get("Cmd") or "").strip()
    for r in t.get("mem_cmdline") or []:
        p = procs.get(_int(r.get("PID")))
        if p is not None and (r.get("Args") or "").strip():
            p["cmdline"] = r["Args"].strip()
    for r in t.get("mem_getsids") or []:
        p = procs.get(_int(r.get("PID")))
        sid = r.get("SID") or ""
        # The account a process runs as is the first user or service SID on its
        # token; groups (S-1-5-32-*, S-1-1-0, ...) come after it.
        if p is not None and not p["user"] and (sid.startswith("S-1-5-21-")
                                                or sid in ("S-1-5-18", "S-1-5-19", "S-1-5-20")):
            p["user"] = r.get("Name") or sid
    for r in t.get("mem_psxview") or []:
        p = procs.get(_int(r.get("PID")))
        if p is not None and (_truthy(r.get("thrdscan")) or _truthy(r.get("csrss"))):
            p["threads_seen"] = True
    for p in procs.values():
        parent = procs.get(p["ppid"]) if p["ppid"] is not None else None
        p["parent"] = parent["process"] if parent else ""
        p["parent_live"] = bool(parent) and _alive(parent)
    return procs


def _alive(p: dict) -> bool:
    return str(p.get("exit_time", "")).strip() in ("", "N/A", "-")


def _process_rules(procs: dict[int, dict], al: _Alerts, has: set[str]) -> None:
    live_names = Counter(_base(p["process"]) for p in procs.values() if _alive(p))
    for p in procs.values():
        name, parent = _base(p["process"]), _base(p["parent"])
        if ("pslist" in has and "psscan" in p["seen"] and "pslist" not in p["seen"]
                and _alive(p) and _plausible_name(p["process"])):
            if p.get("threads_seen"):
                al.add(_HIGH, "hidden_process", p,
                       "absent from the active process list while its threads are "
                       "still scheduled (psxview: thrdscan/csrss) -- unlinked", "mem_psxview")
            else:
                al.add(_MED, "carved_process_not_in_list", p,
                       "carved from memory (psscan), absent from the active list and "
                       "with no exit time; no live thread seen -- hidden, or exited "
                       "without its exit recorded", "mem_psscan")
        allowed = _PARENTS.get(name)
        if allowed and parent and p["parent_live"] and parent not in allowed:
            al.add(_HIGH, "unexpected_parent", p,
                   f"{name} started by {parent}; expected {', '.join(sorted(allowed))}",
                   "mem_pslist")
        if name in _SINGLETONS and _alive(p) and live_names[name] > 1:
            al.add(_HIGH, "duplicate_system_process", p,
                   f"{live_names[name]} live {name} processes; Windows runs one", "mem_pslist")
        twin = _impersonates(name)
        if twin:
            al.add(_HIGH, "masquerading_name", p,
                   f"{name} is one character away from {twin}", "mem_pslist")
        path = p["path"]
        if name in _SYSTEM_NAMES and path and not _SYSTEM_DIR.search(path) \
                and name not in ("explorer.exe", "system"):
            al.add(_HIGH, "system_binary_out_of_place", p,
                   f"{name} running from {path}", "mem_pstree")
        if path and _USER_WRITABLE.search(path):
            al.add(_MED, "runs_from_user_writable_dir", p, path, "mem_pstree")
        if parent in _SPAWN_PARENTS and name in _SHELLS:
            al.add(_HIGH, "document_or_browser_spawned_shell", p,
                   f"{parent} -> {name}", "mem_pslist")


def _cmdline_rules(procs, al: _Alerts, tools) -> None:
    for p in procs.values():
        cmd = p["cmdline"]
        if not cmd:
            continue
        for sev, label, rx in _CMDLINE_RX:
            m = rx.search(cmd)
            if m:
                al.add(sev, label, p, cmd, "mem_cmdline")
        for label in match_labels(tools, cmd) if tools else []:
            al.add(_MED, "named_offensive_tool", p, f"{label}: {cmd}", "mem_cmdline")


def _network_rules(t, procs, al: _Alerts, nc) -> None:
    for r in t.get("mem_netscan") or []:
        pid = _int(r.get("PID"))
        p = procs.get(pid)
        foreign = (r.get("ForeignAddr") or "").strip()
        conn = (f"{r.get('Proto', '')} {r.get('LocalAddr', '')}:{r.get('LocalPort', '')} -> "
                f"{foreign}:{r.get('ForeignPort', '')} {r.get('State', '')}").strip()
        if p is not None:
            p["connections"].append(conn)
        owner = _base(r.get("Owner") or (p or {}).get("process", ""))
        if foreign and foreign not in ("*", "0.0.0.0", "::") and nc.is_public(foreign) \
                and owner in _NET_SHELLS:
            al.add(_HIGH, "shell_talking_to_internet", p, conn, "mem_netscan", pid=pid)


def _finding_tables(t, procs, al: _Alerts) -> None:
    """Plugins whose every row is already a finding."""
    for r in t.get("mem_malfind") or []:
        pid = _int(r.get("PID"))
        p = procs.get(pid)
        if p is not None:
            p["injected"] += 1
        hexdump = (r.get("Hexdump") or "").replace(" ", "").lower()
        pe = hexdump.startswith("4d5a") or "MZ" in (r.get("Notes") or "")
        # Without a PE header an RWX private region is ordinary on a modern
        # Windows (JIT, CFG, security products): 296 on one healthy server, 134
        # of them in svchost. It is kept, as context; the header is the lead.
        al.add(_HIGH if pe else _LOW, "injected_pe" if pe else "injected_code", p,
               f"{r.get('Protection', '')} region {r.get('Start VPN', '')}-{r.get('End VPN', '')}"
               f" {r.get('Tag', '')}".strip(), "mem_malfind", pid=pid)
    for table, rule in (("mem_hollowprocesses", "hollowed_process"),
                        ("mem_processghosting", "ghosted_process")):
        for r in t.get(table) or []:
            pid = _int(r.get("PID"))
            notes = r.get("Notes", "") or table
            # "No VAD at the image base" is also how a protected process (an
            # endpoint product, PPL) looks to the plugin; a mismatch is not.
            sev = _MED if "no vad starting at the base" in notes.lower() else _HIGH
            al.add(sev, rule, procs.get(pid), notes, table, pid=pid)
    for r in t.get("mem_pebmasquerade") or []:
        if not (_truthy(r.get("PEB_ImageFilePath_Spoofed"))
                or _truthy(r.get("PEB_CommandLine_Spoofed"))):
            continue
        # Volatility calls a path spoofed when the kernel's and the PEB's spellings
        # differ, and they differ on every healthy machine: a device path against
        # a drive letter, `\SystemRoot`, case. Measured on six images: 15 of 15
        # "spoofed" rows were the same file written two ways. Compared reduced.
        kernel = _norm_path(r.get("EPROCESS_SeAudit_ImageFileName", ""))
        peb = _norm_path(r.get("PEB_ImageFilePath", ""))
        if not kernel or not peb or kernel == peb:
            continue
        pid = _int(r.get("PID"))
        same_name = kernel.rpartition("\\")[2] == peb.rpartition("\\")[2]
        al.add(_MED if same_name else _HIGH, "peb_masquerade", procs.get(pid),
               f"kernel: {r.get('EPROCESS_SeAudit_ImageFileName', '')} / "
               f"PEB: {r.get('PEB_ImageFilePath', '')}", "mem_pebmasquerade", pid=pid)
    for r in t.get("mem_skeleton_key") or []:
        if _truthy(r.get("Skeleton Key Found")):
            pid = _int(r.get("PID"))
            al.add(_HIGH, "skeleton_key", procs.get(pid),
                   "LSASS Kerberos encryption functions patched", "mem_skeleton_key", pid=pid)
    for r in t.get("mem_drivermodule") or []:
        if not _truthy(r.get("Known Exception")):
            # Medium: the plugin's own known exceptions are not exhaustive, and a
            # carved driver object can be bytes that only look like one.
            al.add(_MED, "driver_without_module", None,
                   f"{r.get('Driver Name', '')} ({r.get('Service Key', '')})", "mem_drivermodule")
    for table, rule, sev in (("mem_svcdiff", "hidden_service", _HIGH),
                             ("mem_etwpatch", "etw_patched", _HIGH),
                             ("mem_orphan_threads", "orphan_kernel_thread", _MED),
                             ("mem_suspicious_threads", "suspicious_thread", _MED)):
        for r in t.get(table) or []:
            pid = _int(r.get("PID") or r.get("Pid"))
            detail = "; ".join(f"{k}={v}" for k, v in r.items()
                               if k != "TreeDepth" and v not in ("", None))
            al.add(sev, rule, procs.get(pid), detail, table, pid=pid)


# A rule's own `score` (signature-base's 0-100 convention) from which a match
# outside a security product is high rather than medium.
_YARA_HIGH = 75


def _yara_rules(t, procs, al: _Alerts) -> None:
    """One alert per process and rule matched in its memory (v0.7.93). Inside an
    endpoint-security product it is usually that product's signatures: low,
    said, and kept."""
    for r in t.get("mem_yara") or []:
        pid = _int(r.get("pid"))
        score = _int(r.get("score"))
        if r.get("in_security_product") == "yes":
            sev = _LOW
        elif score is not None and score >= _YARA_HIGH:
            sev = _HIGH
        else:
            sev = _MED
        detail = (f"{r.get('rule', '')}: {r.get('hits', '')} string(s)"
                  + (f", score {score}" if score is not None else "")
                  + (f" -- {r.get('description', '')}" if r.get("description") else "")
                  + (" (inside a security product: likely its own signatures)"
                     if sev == _LOW else ""))
        al.add(sev, "yara_match", procs.get(pid), detail, "mem_yara", pid=pid)


def run(ctx) -> None:
    base = Path(ctx.evidence) / "CSVs"
    t = {name: _read(base, name) for name in _TABLES}
    if not t["mem_pslist"] and not t["mem_psscan"]:
        raise HandlerSkip("no process table from the memory image (pslist/psscan)")
    has = {name.removeprefix("mem_") for name, rows in t.items() if rows is not None}

    procs = _processes(t)
    al = _Alerts()
    tools = load_indicators(Path(ctx.assets) / "suspicious_tools.txt")
    nc = netclass.parse(getattr(ctx, "internal_networks", ()) or ())
    _process_rules(procs, al, has)
    _cmdline_rules(procs, al, tools)
    _network_rules(t, procs, al, nc)
    _finding_tables(t, procs, al)
    _yara_rules(t, procs, al)

    # What was not read is said where the alerts are, so an empty table of
    # alerts is never taken for a clean image.
    missing = sorted(n for n, rows in t.items() if rows is None)
    for n in missing:
        al.rows.append([_LOW, "coverage", "", "", "", "", "",
                        (f"{n} was not produced (plugin failed or found nothing); "
                         f"the rules built on it did not run"), n])

    al.rows.sort(key=lambda r: (-_RANK.get(r[0], 0), r[1], str(r[2])))
    write_csv(ctx.out, "mem_alerts.csv", _ALERT_HEADER, al.rows)

    rows = []
    for pid in sorted(procs):
        p = procs[pid]
        fired = al.by_pid.get(pid, [])
        sev = max((s for s, _ in fired), key=lambda s: _RANK[s], default="")
        rows.append([pid, "" if p["ppid"] is None else p["ppid"], p["process"], p["parent"],
                     p["path"], p["cmdline"], p["user"], p["session"], p["create_time"],
                     p["exit_time"], ",".join(sorted(p["seen"])),
                     " | ".join(p["connections"][:20]), p["injected"], sev,
                     ",".join(sorted({r for _, r in fired})),
                     "yes" if _RANK.get(sev, 0) >= _RANK[_MED] else ""])
    write_csv(ctx.out, "mem_processes.csv", _PROC_HEADER, rows)
