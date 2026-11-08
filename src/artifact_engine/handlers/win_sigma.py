"""Handler: SigmaHQ's Windows rules over the engine's own tables. Output: alert_win_sigma.csv

NOT over EVTX (hayabusa reads those: `alert_hayabusa`) and NOT over memory
(`alert_mem_sigma`). These are the artifacts that say a program, a file, a registry
value or a connection existed, parsed by the engine's other parsers:

  source        table                         Sigma category          fields built
  prefetch      art_prefetch                  process_creation        Image (path from FilesLoaded)
  amcache       art_amcache_*_files           process_creation        Image, Hashes (SHA1)
  shimcache     art_reg_shimcache             process_creation        Image
  liveresponse  Velociraptor Pslist           process_creation        Image, CommandLine, User, parent
  mft           art_mft                       file_event              TargetFilename
  usn           art_usn                       file_event/file_delete  TargetFilename (create / delete)
  registry      every RECmd-format table      registry_set/event/add  TargetObject, Details, EventType
  netstat       art_process_network           network_connection      Image, User, addresses, Initiated

A field a table does not hold is empty, so a rule can miss but never fires on it. The
rules (v0.7.194): the analyst's fork of SigmaHQ, `sigma_disk_repo` at its
`aeng` branch, where rules are adapted to these tables, mirrored by `aeng update`
into `assets/sigma_disk/`. Without it, SigmaHQ's rules as written: the
process_creation set `alert_mem_sigma` uses, and for the other categories the copy
hayabusa ships with (its channel selection taken out, see core/sigma_wincat.py).
Either way, plus the analyst's own under `sigma_custom/windows/<category>`.
`informational` rules are context, not alerts, and are dropped.

An MFT or USN journal holds millions of rows, so a table is streamed, never loaded:
the rows a rule could match (core/sigma_prefilter.py) are collected in batches of
`_BATCH`, each batch goes into an in-memory SQLite table the rules query, and the
matches are folded across batches into ONE row per (rule, source): the count, the
first and last time and a sample of the first matching row.
"""

from __future__ import annotations

import csv
import re
import sqlite3
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.core.sigma_engine import CUSTOM_SIGMA
from artifact_engine.core.sigma_prefilter import Gate, necessary, never_true
from artifact_engine.core.sigma_wincat import CATEGORIES, load_category
from artifact_engine.core.sigma_windows import load_process_rules
from artifact_engine.handlers._execution import _WINSXS, _collection_trees, basename, norm_path, utc
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers._procnet import _NO_PEER
from artifact_engine.handlers._tables import find_table, machine_root
from artifact_engine.handlers.lin_sigma import _run_rule
from artifact_engine.handlers.win_eventlogs_hayabusa import _find_exe
from artifact_engine.handlers.win_liveresponse_velociraptor import (
    _artifact_key,
    _find_results,
    _read_jsonl,
)

# Where `aeng update` mirrors the fork's `rules/windows/` (core/downloader.py).
DISK_SIGMA = "sigma_disk"

_HEADER = ["level", "rule", "source", "mitre", "first_seen", "last_seen", "count",
           "match", "rule_id"]

# Rows held before they are run through the rules (bounded memory on a big $MFT).
_BATCH = 50_000

# group -> (categories whose rules it runs, the Sigma fields its rows fill,
#           the fields the `match` sample is made of)
_GROUPS = {
    "process": (("process_creation",),
                ("ProcessId", "ParentProcessId", "Image", "CommandLine", "ParentImage",
                 "ParentCommandLine", "User", "ParentUser", "Hashes"),
                ("Image", "CommandLine")),
    "file_event": (("file_event",), ("TargetFilename",), ("TargetFilename",)),
    "file_delete": (("file_delete",), ("TargetFilename",), ("TargetFilename",)),
    "registry": (("registry_set", "registry_event", "registry_add"),
                 ("TargetObject", "Details", "EventType"), ("TargetObject", "Details")),
    "network": (("network_connection",),
                ("Image", "User", "Protocol", "SourceIp", "SourcePort", "DestinationIp",
                 "DestinationPort", "Initiated", "ProcessId"),
                ("Image", "DestinationIp", "DestinationPort")),
}

# Every field name a compiled rule's WHERE clause compares: it becomes a column (NULL
# when the table does not fill it), so the gate can read the rule instead of letting
# it see every row. A word that is not a field costs one empty column.
_FIELD = re.compile(
    r"(?<![\w'`\"])([A-Za-z_]\w*)\s*"
    r"(?:=|<>|!=|<=|>=|<|>|(?:NOT\s+)?(?:LIKE|IN|GLOB|REGEXP)\b|IS\b)", re.IGNORECASE)
_SQL_WORDS = {"and", "or", "not", "where", "select", "from", "escape", "null", "like", "in",
              "is", "glob", "regexp", "between"}


class _Group:
    """The rows of one kind, their rules, and the batches waiting to be run."""

    def __init__(self, name: str, rules) -> None:
        _cats, base, self.sample_keys = _GROUPS[name]
        self.name = name
        rules = [r for r in rules if r.level != "informational"
                 and not (name == "registry" and r.rule_id in _STATE_NOISE)]
        known = {c.casefold() for c in base} | {"x_time", "x_source"}
        extra: list[str] = []
        for r in rules:
            where = r.sql.split(" WHERE ", 1)[-1]
            for m in _FIELD.finditer(where):
                f = m.group(1)
                if f.casefold() not in known and f.casefold() not in _SQL_WORDS:
                    known.add(f.casefold())
                    extra.append(f)
        self.base = base
        # A field outside `base` is NULL in every row of this group (the MFT names
        # no process): a rule that needs one cannot match, and would only widen
        # the gate -- measured, it let 99% of a $MFT through (v0.7.192).
        self.rules = [r for r in rules if not never_true(r.sql, extra)]
        self.impossible = len(rules) - len(self.rules)
        self.pad = [None] * len(extra)
        self.cols = (*base, *extra, "x_time", "x_source")
        needs = [necessary(r.sql, self.cols) for r in self.rules]
        self.gated = [r for r, n in zip(self.rules, needs) if n is not None]
        self.ungated = [r for r, n in zip(self.rules, needs) if n is None]
        self.gate = Gate([n for n in needs if n is not None],
                         {c: i for i, c in enumerate(self.cols)})
        self.batch: list[list] = []         # rows a gated rule could match
        self.every: list[list] = []         # every row, only while a rule needs them all

    def add(self, source: str, time: str, fields: dict, agg: dict) -> None:
        if not self.rules:
            return
        row = [fields.get(c) for c in self.base]
        row += self.pad
        row += [time, source]
        if self.ungated:
            self.every.append(row)
        if self.gated and self.gate(row):
            self.batch.append(row)
        if len(self.batch) >= _BATCH or len(self.every) >= _BATCH:
            self.flush(agg)

    def flush(self, agg: dict) -> None:
        if self.batch:
            self._scan(self.batch, self.gated, agg)
            self.batch = []
        if self.every:
            self._scan(self.every, self.ungated, agg)
            self.every = []

    def _scan(self, rows: list[list], rules, agg: dict) -> None:
        if not rules:
            return
        q = lambda c: "`" + c + "`"      # backtick like the compiled rule SQL
        table = rules[0].table
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute(f"CREATE TABLE {table} ({', '.join(q(c) for c in self.cols)})")
            conn.executemany(
                f"INSERT INTO {table} VALUES ({', '.join(['?'] * len(self.cols))})", rows)
            for r in rules:
                cols, matches = _run_rule(conn, r.sql)
                if matches and self.name == "registry":
                    matches = _value_dependent(r.sql, cols, matches)
                if not matches:
                    continue
                idx = {c: i for i, c in enumerate(cols)}
                for row in matches:
                    t = (row[idx["x_time"]] if "x_time" in idx else "") or ""
                    source = (row[idx["x_source"]] if "x_source" in idx else "") or self.name
                    sample = " ".join(
                        f"{k}={row[idx[k]]}" for k in self.sample_keys
                        if k in idx and row[idx[k]] not in (None, ""))
                    _fold(agg, r, source, t, sample[:300])
        finally:
            conn.close()


# Rules that fire on a default of every host when read over a hive's state, not
# over a change event. Potential EventLog File Location Tampering: any `...\\File`
# value under Services\\EventLog that is not a Winevt path -- which includes the
# DWORD `ObjectNames\\File` of the Security log on every Windows Server.
_STATE_NOISE = frozenset({
    "6ac82221-3e82-1244-ebbc-6d0b98a5c534",     # hayabusa's id
    "0cb8d736-995d-4ce7-a31e-1e8d452a1459",     # SigmaHQ's id
})


def _value_dependent(sql: str, cols: list[str], matches: list[tuple]) -> list[tuple]:
    """The registry matches that need the value. Most registry rules were written
    for Sysmon's change events, and some match any write to a key ("every change
    here is suspicious"). Over a hive's state that key is simply there, with its
    default, on every host -- so a match that survives with Details emptied said
    nothing about this host and is dropped."""
    if "Details" not in cols:
        return matches
    at = cols.index("Details")
    conn = sqlite3.connect(":memory:")
    try:
        table = sql.split(" FROM ", 1)[1].split()[0]
        conn.execute(f"CREATE TABLE {table} ({', '.join('`' + c + '`' for c in cols)})")
        conn.executemany(f"INSERT INTO {table} VALUES ({', '.join(['?'] * len(cols))})",
                         [(*m[:at], None, *m[at + 1:]) for m in matches])
        _cols, still = _run_rule(conn, sql)
    finally:
        conn.close()
    keep = {(*m[:at], *m[at + 1:]) for m in still}
    return [m for m in matches if (*m[:at], *m[at + 1:]) not in keep]


def _fold(agg: dict, r, source: str, t: str, sample: str) -> None:
    """One match of rule `r` on a row of `source` at `t`."""
    key = (r.rule_id or r.title, source)
    a = agg.get(key)
    if a is None:
        agg[key] = {"rule": r, "source": source, "count": 1, "first": t, "last": t,
                    "match": sample}
        return
    a["count"] += 1
    if t and (not a["first"] or t < a["first"]):
        a["first"] = t
    if t and t > a["last"]:
        a["last"] = t


def _read(path: Path, names: tuple[str, ...], required: tuple[str, ...] = ()):
    """Rows of a CSV, streamed, as tuples of the named columns ('' when a row or the
    table lacks one). Nothing when a `required` column is missing."""
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
            rows = csv.reader(line.replace("\x00", "") for line in fh)
            head = next(rows, [])
            if any(n not in head for n in required):
                return
            idx = [head.index(n) if n in head else -1 for n in names]
            for row in rows:
                n = len(row)
                yield tuple(row[i] if 0 <= i < n else "" for i in idx)
    except (OSError, csv.Error):
        return


# ----------------------------------------------------------------- the sources

def _volume_path(entry: str) -> str:
    """`\\VOLUME{...}\\WINDOWS\\X.EXE` -> `C:\\WINDOWS\\X.EXE`."""
    return re.sub(r"^\\VOLUME\{[^}]*\}", "C:", entry.strip(), flags=re.IGNORECASE)


def _prefetch(csvs: Path):
    p = find_table(csvs, "art_prefetch")
    if p is None:
        return
    for name, last, loaded in _read(p, ("ExecutableName", "LastRun", "FilesLoaded")):
        name = name.strip()
        if not name:
            continue
        # Without its full path a name would trip every "X outside System32" rule.
        image = next((_volume_path(f) for f in loaded.split(",")
                      if basename(f) == name.lower()), None)
        if image is not None:
            yield "process", "prefetch", utc(last), {"Image": image}


def _amcache(csvs: Path):
    for table in ("art_amcache_associated_files", "art_amcache_unassociated_files"):
        p = find_table(csvs, table)
        if p is None:
            continue
        for path, sha1, when in _read(p, ("FullPath", "SHA1", "FileKeyLastWriteTimestamp")):
            if not path.strip():
                continue
            sha1 = sha1.strip()
            if len(sha1) == 44 and sha1.startswith("0000"):      # padded by older tools
                sha1 = sha1[4:]
            yield "process", "amcache", utc(when), {
                "Image": _image(path.strip()), "Hashes": f"SHA1={sha1}" if sha1 else None}


_SYSNATIVE = re.compile(r"^C:\\Windows\\Sysnative\\", re.IGNORECASE)


def _image(path: str) -> str:
    """`C:\\Windows\\Sysnative\\x` is System32 seen from a 32-bit process."""
    return _SYSNATIVE.sub(r"C:\\Windows\\System32\\", path)


_SYSVOL = re.compile(r"^(?:\\\?\?\\|SYSVOL\\)", re.IGNORECASE)


def _shimcache(csvs: Path):
    p = find_table(csvs, "art_reg_shimcache")
    if p is None:
        return
    for path, when in _read(p, ("Path", "LastModifiedTimeUTC")):
        path = _SYSVOL.sub("", path.strip())
        if not path:
            continue
        # AppCompatCache spells C:\ as SYSVOL\ (or \??\C:\): without the drive, every
        # "binary outside C:\Windows\System32" rule would fire on System32 itself.
        if path[1:2] != ":":
            path = "C:\\" + path.lstrip("\\")
        yield "process", "shimcache", utc(when), {"Image": _image(path)}


def _liveresponse(ctx):
    if str(ctx.volume).upper().startswith("VSS"):
        return                      # the live host's, never a snapshot's
    results = _find_results(ctx)
    if results is None:
        return
    procs: list[dict] = []
    for f in results.glob("*.json"):
        if _artifact_key(f) == "Windows.System.Pslist":
            procs = _read_jsonl(f)
            break
    by_pid = {p.get("Pid"): p for p in procs}
    for p in procs:
        if not (p.get("Exe") or p.get("CommandLine")):
            continue
        parent = by_pid.get(p.get("Ppid")) or {}
        yield "process", "liveresponse", utc(p.get("CreateTime")), {
            "Image": p.get("Exe") or None, "CommandLine": p.get("CommandLine") or None,
            "User": p.get("Username") or None, "ProcessId": p.get("Pid"),
            "ParentProcessId": p.get("Ppid"), "ParentImage": parent.get("Exe") or None,
            "ParentCommandLine": parent.get("CommandLine") or None}


def _target(parent: str, name: str) -> str:
    """`.\\Users\\jdoe` + `a.txt` -> `C:\\Users\\jdoe\\a.txt` (the root is `.`)."""
    parent = parent.strip().removeprefix(".")
    return "C:" + parent.rstrip("\\") + "\\" + name


_SERVICING = "\\windows\\servicing\\"     # update packages: OS payload, like WinSxS


def _not_evidence(csvs: Path):
    """The trees exec_hunt skips too: the collector's own copy of the volume
    (`art_collection` marks it; every file there is a second record of one that
    lives elsewhere), the component store WinSxS and the update packages under
    Windows\\servicing (OS payload such as ntds.dit or WsmPty.xsl that file
    rules name)."""
    skip = (*_collection_trees(csvs), _WINSXS, _SERVICING)
    return lambda target: any(norm_path(target[2:]).startswith(t) for t in skip)


def _mft(csvs: Path):
    p = find_table(csvs, "art_mft")
    if p is None:
        return
    skipped = _not_evidence(csvs)
    for parent, name, in_use, is_dir, created in _read(
            p, ("ParentPath", "FileName", "InUse", "IsDirectory", "Created0x10"),
            required=("ParentPath", "FileName")):
        if in_use != "True" or is_dir == "True" or not name:
            continue
        target = _target(parent, name)
        if not skipped(target):
            yield "file_event", "mft", utc(created), {"TargetFilename": target}


def _folders(csvs: Path) -> dict[str, str]:
    """MFT entry number -> folder path (`.\\Users\\jdoe`), directories only, so a
    USN record that names only its parent's entry number gets its folder."""
    p = find_table(csvs, "art_mft")
    if p is None:
        return {}
    out: dict[str, str] = {}
    for entry, parent, name, is_dir in _read(
            p, ("EntryNumber", "ParentPath", "FileName", "IsDirectory"),
            required=("EntryNumber", "ParentPath", "FileName", "IsDirectory")):
        if is_dir == "True" and entry:
            out[entry] = "." if name == "." else parent.rstrip("\\") + "\\" + name
    return out


def _usn(csvs: Path):
    p = find_table(csvs, "art_usn")
    if p is None:
        return
    skipped = _not_evidence(csvs)
    folders: dict[str, str] | None = None
    for parent, pentry, name, when, reasons in _read(
            p, ("ParentPath", "ParentEntryNumber", "Name", "UpdateTimestamp", "UpdateReasons"),
            required=("Name", "UpdateReasons")):
        if not name or not ("FileCreate" in reasons or "FileDelete" in reasons):
            continue
        if not parent.strip().startswith("."):
            if folders is None:
                folders = _folders(csvs)
            parent = folders.get(pentry.strip(), "")
        # Without its folder a name trips every "outside the usual folder" rule.
        if not parent.startswith("."):
            continue
        target = _target(parent, name)
        if skipped(target):
            continue
        if "FileCreate" in reasons:
            yield "file_event", "usn", utc(when), {"TargetFilename": target}
        if "FileDelete" in reasons:
            yield "file_delete", "usn", utc(when), {"TargetFilename": target}


_HIVES = {"SYSTEM": "HKLM\\SYSTEM", "SOFTWARE": "HKLM\\SOFTWARE", "SAM": "HKLM\\SAM",
          "SECURITY": "HKLM\\SECURITY", "NTUSER": "HKU\\USER", "USRCLASS": "HKU\\USER_Classes"}
_REG_TABLES = ("art_reg_services", "art_reg_tasks", "art_reg_bam", "art_reg_userassist",
               "art_reg_run_mru", "art_reg_profile_list", "art_reg_users",
               "art_reg_installed", "art_reg_persistence", "art_reg_user_activity")
_CONTROLSET = re.compile(r"^ControlSet00\d(?=\\|$)", re.IGNORECASE)
_ROOT = re.compile(r"^ROOT(?:\\|$)", re.IGNORECASE)
# a hive loaded offline is rooted at a "CsiTool-CreateHive-{GUID}" key
_OFFLINE_ROOT = re.compile(r"^CsiTool-CreateHive-\{[^}]*\}(?:\\|$)", re.IGNORECASE)


def _hive(hive_type: str, hive_path: str) -> str:
    t = (hive_type.strip() or basename(hive_path)).upper().split(".")[0]
    return _HIVES.get(t) or (f"HKLM\\{t}" if t else "")


def _target_object(hive: str, key: str, value: str) -> str:
    key = _OFFLINE_ROOT.sub("", _ROOT.sub("", key.replace("/", "\\").strip("\\")))
    key = _CONTROLSET.sub("CurrentControlSet", key)
    return hive + ("\\" + key if key else "") + ("\\" + value if value else "")


def _details(value_type: str, data: str) -> str | None:
    """Value data the way Sysmon writes it, which is what the rules compare:
    `DWORD (0x00000001)`, `QWORD (0x...)`; anything else as is."""
    t = value_type.strip().lower().replace("_", "")
    if t in ("regdword", "regqword") and data.strip():
        try:
            n = int(data.strip(), 0)
        except ValueError:
            return data
        return f"DWORD (0x{n:08x})" if t == "regdword" else f"QWORD (0x{n:016x})"
    return data or None


def _registry(csvs: Path):
    for table in _REG_TABLES:
        p = find_table(csvs, table)
        if p is None:
            continue
        for htype, hpath, key, value, vtype, data, when in _read(
                p, ("HiveType", "HivePath", "KeyPath", "ValueName", "ValueType", "ValueData",
                    "LastWriteTimestamp"), required=("KeyPath", "ValueName")):
            if not key.strip():
                continue
            yield "registry", "registry", utc(when), {
                "TargetObject": _target_object(_hive(htype, hpath), key, value.strip()),
                "Details": _details(vtype, data), "EventType": "SetValue"}


def _netstat(csvs: Path):
    p = find_table(csvs, "art_process_network")
    if p is None:
        return
    names = ("pid", "path", "user", "state", "proto", "local_ip", "local_port",
             "remote_ip", "remote_port", "socket_created_utc", "start_utc")
    rows = list(_read(p, names, required=("pid", "remote_ip")))
    # what each process listens on: a connection to such a port came IN
    listening = {(r[0], r[6]) for r in rows if r[3].upper() == "LISTEN" and r[6]}
    for pid, path, user, state, proto, lip, lport, rip, rport, created, started in rows:
        if rip.strip() in _NO_PEER:
            continue
        initiated = state.upper() != "LISTEN" and (pid, lport) not in listening
        yield "network", "netstat", utc(created or started), {
            "Image": path or None, "User": user or None, "Protocol": proto or None,
            "SourceIp": lip or None, "SourcePort": lport or None,
            "DestinationIp": rip, "DestinationPort": rport or None,
            "Initiated": "true" if initiated else "false", "ProcessId": pid or None}


def _inputs(ctx):
    """Whether any table or live-response list exists to read."""
    csvs = machine_root(ctx.out) / "CSVs"
    tables = ("art_prefetch", "art_amcache_associated_files", "art_amcache_unassociated_files",
              "art_reg_shimcache", "art_mft", "art_usn", "art_process_network", *_REG_TABLES)
    if any(find_table(csvs, t) is not None for t in tables):
        return csvs, True
    results = None if str(ctx.volume).upper().startswith("VSS") else _find_results(ctx)
    return csvs, bool(results is not None and any(
        _artifact_key(f) == "Windows.System.Pslist" for f in results.glob("*.json")))


def run(ctx) -> None:
    csvs, found = _inputs(ctx)
    if not found:
        raise HandlerSkip("no Prefetch, Amcache, ShimCache, MFT, USN, registry, network "
                          "table or live-response process list to read")
    custom = Path(ctx.assets) / CUSTOM_SIGMA
    exe = _find_exe(Path(ctx.tools))
    haya = exe.parent / "rules" / "sigma" / "sysmon" if exe is not None else None
    if haya is not None and not haya.is_dir():
        haya = None

    # The analyst's fork of SigmaHQ, where rules are adapted to these tables
    # (`aeng update` mirrors its `aeng` branch here); without it, the bundled
    # process set and hayabusa's copy, as SigmaHQ wrote them.
    disk = Path(ctx.assets) / DISK_SIGMA
    disk = disk if disk.is_dir() else None
    groups: dict[str, _Group] = {}
    for name, (cats, _base, _keys) in _GROUPS.items():
        rules = []
        if name == "process":
            rules = (list(load_category("process_creation", custom, None, disk).rules)
                     if disk is not None and (disk / "process_creation").is_dir()
                     else list(load_process_rules(custom)))
        for c in cats:
            if c in CATEGORIES:
                loaded = load_category(c, custom, haya, disk)
                rules += loaded.rules
                if loaded.unwrap_skipped and ctx.log is not None:
                    ctx.log.debug(f"alert_win_sigma: {loaded.unwrap_skipped} {c} rule(s) "
                                  f"skipped: condition not unwrappable")
        groups[name] = _Group(name, rules)
        if groups[name].impossible and ctx.log is not None:
            ctx.log.debug(f"alert_win_sigma: {groups[name].impossible} {name} rule(s) "
                          f"dropped: they need a field these tables do not hold")
    if not any(g.rules for g in groups.values()):
        raise HandlerSkip("no Windows Sigma rule compiled")

    agg: dict = {}
    streams = (_prefetch(csvs), _amcache(csvs), _shimcache(csvs), _liveresponse(ctx),
               _mft(csvs), _usn(csvs), _registry(csvs), _netstat(csvs))
    for stream in streams:
        for group, source, when, fields in stream:
            groups[group].add(source, when, fields, agg)
    for g in groups.values():
        g.flush(agg)

    rows = [[a["rule"].level, a["rule"].title, a["source"], a["rule"].tags, a["first"],
             a["last"], a["count"], a["match"], a["rule"].rule_id] for a in agg.values()]
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rows.sort(key=lambda x: (_order.get(x[0], 9), -x[6], x[1], x[2]))
    write_csv(ctx.out, "alert_win_sigma.csv", _HEADER, rows)
