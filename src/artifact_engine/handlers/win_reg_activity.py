"""Handler: what each user ran and opened, from the keys no other parser reads,
and the software the machine had installed.

Outputs (per user, from NTUSER.DAT and UsrClass.dat):
  art_reg_compat_store   programs the Program Compatibility Assistant saw run
                         (`Compatibility Assistant\\Store`, Windows 7-10), and those
                         set to run in a compatibility mode or as administrator
                         (`AppCompatFlags\\Layers`, with the flags)
  art_reg_muicache       display name and company of every program the user ran
                         (UsrClass `MuiCache`)
  art_reg_feature_usage  taskbar use per program: AppSwitched, AppLaunch,
                         ShowJumpView, each with its count (Windows 10 1903+)
  art_reg_file_dialogs   files opened or saved through a common dialog
                         (`OpenSavePidlMRU`), and the program that opened one with
                         the folder it was left in (`LastVisitedPidlMRU`)
  art_reg_recent_docs    files and folders opened from Explorer (`RecentDocs`)
and, from SOFTWARE (handler `run_installed`):
  art_reg_installed      the Uninstall keys, 64- and 32-bit: name, version,
                         publisher, install date, location, source

RECmd reads the hives, because it replays their transaction logs (a dirty hive
read without them is missing its newest values) and its plugins decode the shell
items in the dialog and RecentDocs values. NTUSER.DAT is read ONE HIVE AT A TIME,
a few at once: a plugin's decoded rows go to a detail file that does not say which
hive they came from, so a run over the whole Users folder could not tell whose
they were. MuiCache needs no plugin, so every UsrClass.dat is read in one run,
each row carrying its hive path -- measured on a server with 98 profiles, hive by
hive for both was 2 minutes.

An Uninstall key with no DisplayName (an update or a component of another
product) is left out, as Windows' own list of programs leaves it out.

The tables are context, not verdicts: the execution keys feed `exec_hunt`
(`_execution.py`), which is where the remote-access, tunnelling, LOLBAS and
suspicious-tool catalogs are matched.
"""

from __future__ import annotations

import csv
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from artifact_engine.core import procs
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv

csv.field_size_limit(10_000_000)

_RECMD = Path("RECmd") / "RECmd.exe"
_USER_BATCH = "UserActivity.reb"
_CLASSES_BATCH = "UserClasses.reb"
_SOFTWARE_BATCH = "Installed.reb"
_MAIN = "main.csv"
_TIMEOUT = 600
_AT_ONCE = 4                # NTUSER hives read in parallel

_TS = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
_MUI_SUFFIX = re.compile(r"\.(FriendlyAppName|ApplicationCompany)$", re.IGNORECASE)

COMPAT_HEADER = ["user", "kind", "path", "flags", "key_last_write_utc"]
MUI_HEADER = ["user", "path", "name", "company"]
FEATURE_HEADER = ["user", "kind", "app", "count"]
DIALOG_HEADER = ["user", "kind", "executable", "path", "extension", "mru", "opened_utc"]
RECENT_HEADER = ["user", "extension", "name", "lnk", "mru", "opened_utc"]
INSTALLED_HEADER = ["name", "version", "publisher", "install_date", "location", "source",
                    "uninstall", "key", "key_last_write_utc"]


def utc(value) -> str:
    """`2026-01-02 03:04:05.1234567` -> `2026-01-02 03:04:05` (RECmd writes UTC)."""
    m = _TS.search(str(value or ""))
    return f"{m.group(1)} {m.group(2)}" if m else ""


def _user(hive: Path, users_dir: Path) -> str:
    """The profile folder a hive sits in: Users\\<name>\\NTUSER.DAT or
    Users\\<name>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat."""
    try:
        return hive.relative_to(users_dir).parts[0]
    except (ValueError, IndexError):
        return ""


def _read(path: Path) -> list[dict]:
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
            return list(csv.DictReader(line.replace("\x00", "") for line in fh))
    except (OSError, csv.Error):
        return []


def _recmd(exe: Path, source: Path, batch: Path, log) -> tuple[list[dict], dict[str, list[dict]]] | None:
    """RECmd over one hive (`-f`) or a folder of them (`-d`): (its main rows,
    {plugin: detail rows}), or None when it failed. The detail files sit in a
    timestamped folder RECmd names itself, called `<main stem>_<plugin>.csv`."""
    with tempfile.TemporaryDirectory(prefix="aeng_recmd_", ignore_cleanup_errors=True) as tmp:
        out = Path(tmp)
        rc, said, err = procs.run([str(exe), "-d" if source.is_dir() else "-f", str(source),
                                   "--bn", str(batch), "--csv", str(out), "--csvf", _MAIN,
                                   "--nl", "true"], timeout=_TIMEOUT)
        main = out / _MAIN
        if rc != 0 and not main.is_file():
            if log:
                why = (err or said or "").strip().splitlines()
                log.warning(f"[!] RECmd failed on {source.name} (exit {rc}): {why[-1][:160] if why else ''}")
            return None
        detail: dict[str, list[dict]] = {}
        prefix = Path(_MAIN).stem + "_"
        for f in out.rglob("*.csv"):
            if f.parent != out and f.name.startswith(prefix):
                detail[f.stem[len(prefix):].lower()] = _read(f)
        rows = _read(main)
    return rows, detail


def _unique(rows: list[list]) -> list[list]:
    """A plugin reports a key once per batch entry that reaches it: drop repeats."""
    seen: set[tuple] = set()
    out = []
    for r in rows:
        t = tuple(r)
        if t not in seen:
            seen.add(t)
            out.append(r)
    return out


def _muicache_rows(main: list[dict], users_dir: Path) -> list[list]:
    """One row per program and user: the `.FriendlyAppName` and `.ApplicationCompany`
    values of a path (Vista and later; Windows 7's bare path holds the name) joined."""
    mui: dict[tuple[str, str], list[str]] = {}
    for r in main:
        name = (r.get("ValueName") or "").strip()
        if r.get("Description") != "MUICache" or not name:
            continue
        if name.lower().startswith(("langid", "@")):
            continue                             # cache bookkeeping, resource strings
        m = _MUI_SUFFIX.search(name)
        key = (_user(Path(r.get("HivePath") or ""), users_dir), name[:m.start()] if m else name)
        ent = mui.setdefault(key, ["", ""])
        ent[1 if m and m.group(1).lower() == "applicationcompany" else 0] = (r.get("ValueData") or "").strip()
    return [[user, path, n, c] for (user, path), (n, c) in mui.items()]


def _ntuser_rows(user: str, main: list[dict], detail: dict[str, list[dict]], acc: dict) -> None:
    for r in main:
        desc = r.get("Description") or ""
        name = (r.get("ValueName") or "").strip()
        if not name:
            continue
        if desc == "Compatibility Assistant Store":
            acc["compat"].append([user, "compat_store", name, "", utc(r.get("LastWriteTimestamp"))])
        elif desc == "AppCompatFlags Layers":
            acc["compat"].append([user, "layers", name, (r.get("ValueData") or "").strip(),
                                  utc(r.get("LastWriteTimestamp"))])

    for r in detail.get("featureusage", []):
        acc["feature"].append([user, (r.get("KeyPath") or "").strip(), (r.get("ValueName") or "").strip(),
                               (r.get("Count") or "").strip()])
    for r in detail.get("opensavepidlmru", []):
        acc["dialog"].append([user, "open_save", "", (r.get("AbsolutePath") or "").strip(),
                              (r.get("Extension") or "").strip(), (r.get("MruPosition") or "").strip(),
                              utc(r.get("OpenedOn"))])
    for r in detail.get("lastvisitedpidlmru", []):
        acc["dialog"].append([user, "last_visited", (r.get("Executable") or "").strip(),
                              (r.get("AbsolutePath") or "").strip(), "",
                              (r.get("MruPosition") or "").strip(), utc(r.get("OpenedOn"))])
    for r in detail.get("recentdocs", []):
        acc["recent"].append([user, (r.get("Extension") or "").strip(), (r.get("TargetName") or "").strip(),
                              (r.get("LnkName") or "").strip(), (r.get("MruPosition") or "").strip(),
                              utc(r.get("OpenedOn"))])


def _exe(ctx) -> Path:
    exe = Path(ctx.tools) / _RECMD
    if not exe.is_file():
        raise HandlerSkip("RECmd not installed (run 'aeng setup')")
    return exe


def run(ctx) -> None:
    users_dir = Path(ctx.evidence) / "Users"
    if not users_dir.is_dir():
        raise HandlerSkip("no Users folder")
    exe = _exe(ctx)
    assets = Path(ctx.assets) / "recmd"
    ntusers = [p / "NTUSER.DAT" for p in sorted(users_dir.iterdir())
               if p.is_dir() and (p / "NTUSER.DAT").is_file()]
    classes = any(users_dir.glob("*/AppData/Local/Microsoft/Windows/UsrClass.dat"))
    if not ntusers and not classes:
        raise HandlerSkip("no user hives")
    acc: dict[str, list] = {"compat": [], "mui": [], "feature": [], "dialog": [], "recent": []}
    with ThreadPoolExecutor(max_workers=_AT_ONCE) as pool:
        got = list(pool.map(lambda h: _recmd(exe, h, assets / _USER_BATCH, ctx.log), ntusers))
    for hive, res in zip(ntusers, got):
        if res is not None:
            _ntuser_rows(_user(hive, users_dir), *res, acc)
    mui = _recmd(exe, users_dir, assets / _CLASSES_BATCH, ctx.log) if classes else None
    if mui is not None:
        acc["mui"] = _muicache_rows(mui[0], users_dir)
    if (not ntusers or all(r is None for r in got)) and (not classes or mui is None):
        raise RuntimeError("RECmd failed on every user hive")
    write_csv(ctx.out, "art_reg_compat_store.csv", COMPAT_HEADER, _unique(acc["compat"]))
    write_csv(ctx.out, "art_reg_muicache.csv", MUI_HEADER, _unique(acc["mui"]))
    write_csv(ctx.out, "art_reg_feature_usage.csv", FEATURE_HEADER, _unique(acc["feature"]))
    write_csv(ctx.out, "art_reg_file_dialogs.csv", DIALOG_HEADER, _unique(acc["dialog"]))
    write_csv(ctx.out, "art_reg_recent_docs.csv", RECENT_HEADER, _unique(acc["recent"]))


def run_installed(ctx) -> None:
    hive = Path(ctx.evidence) / "Windows" / "System32" / "config" / "SOFTWARE"
    if not hive.is_file():
        raise HandlerSkip("no SOFTWARE hive")
    got = _recmd(_exe(ctx), hive, Path(ctx.assets) / "recmd" / _SOFTWARE_BATCH, ctx.log)
    if got is None:
        raise RuntimeError("RECmd failed on the SOFTWARE hive")
    rows = [[(r.get("DisplayName") or "").strip(), (r.get("DisplayVersion") or "").strip(),
             (r.get("Publisher") or "").strip(), (r.get("InstallDate") or "").strip(),
             (r.get("InstallLocation") or "").strip(), (r.get("InstallSource") or "").strip(),
             (r.get("UninstallString") or "").strip(), (r.get("KeyName") or "").strip(),
             utc(r.get("Timestamp"))]
            for r in got[1].get("uninstall", []) if (r.get("DisplayName") or "").strip()]
    write_csv(ctx.out, "art_reg_installed.csv", INSTALLED_HEADER, _unique(rows))
