"""Every program a Windows machine recorded, from every artifact that records one (v0.7.103).

A detector that asks "was tool X here?" used to read Amcache alone, and three of
them read it separately. This reads each execution artifact the engine has
already parsed ONCE and yields the same record from all of them, so one
searcher (`win_exec_hunt`) can run every catalog over one pass:

  source        what it says                          time (UTC)
  amcache       on disk, with its SHA1                key last write
  prefetch      ran, how many times                   last run
  shimcache     on disk (ran, on older Windows)       -- (the file's own mtime)
  bam           ran, by which account (SID)           last run
  userassist    ran from the shell, by which user     last run
  pca           ran (Windows 11)                      -- (local time)
  srum          ran and used the network / CPU        record time
  service       installed as a service (ImagePath)    key last write
  task          a scheduled task runs it              -- (local time)
  lnk/jumplist  a shortcut or jump list points at it  --
  process       running at collection (LiveResponse)  process start

Only clocks the engine knows are UTC fill `time_utc`; the others still count as
a source. The live response is the live host's, so a VSS volume never reads it.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import NamedTuple

from artifact_engine.handlers._alertgroups import find_table
from artifact_engine.handlers.win_liveresponse_velociraptor import (
    _artifact_key,
    _find_results,
    _read_jsonl,
)

# Amcache and SRUM rows (rich PE metadata) can exceed csv's default field limit.
csv.field_size_limit(10_000_000)


class Sighting(NamedTuple):
    source: str
    name: str          # executable basename, lower-case
    path: str          # as the artifact wrote it ("" when it keeps no path)
    user: str = ""
    time_utc: str = ""
    runs: int = 0
    sha1: str = ""


_TS = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
_DEVICE = re.compile(r"^\\device\\harddiskvolume\d+", re.IGNORECASE)
_VOLUME = re.compile(r"^\\volume\{[^}]*\}", re.IGNORECASE)


def utc(value) -> str:
    """`2026-01-02T03:04:05.123Z` / `2026-01-02 03:04:05.1234567` -> `2026-01-02 03:04:05`."""
    m = _TS.search(str(value or ""))
    return f"{m.group(1)} {m.group(2)}" if m else ""


def basename(path: str) -> str:
    return str(path or "").strip().strip('"').replace("/", "\\").rsplit("\\", 1)[-1].lower()


def norm_path(path: str) -> str:
    """One spelling per file across artifacts: no drive or device prefix, lower-case."""
    p = str(path or "").strip().strip('"').replace("/", "\\").lower()
    p = _DEVICE.sub("", p)
    p = _VOLUME.sub("", p)
    return re.sub(r"^[a-z]:", "", p)


def _rows(csvs: Path, table: str):
    p = find_table(csvs, table)
    if p is None:
        return
    try:
        with open(p, encoding="utf-8-sig", errors="replace", newline="") as fh:
            # some Amcache dumps carry stray NUL bytes that csv rejects
            yield from csv.DictReader(line.replace("\x00", "") for line in fh)
    except (OSError, csv.Error):
        return


def _int(v) -> int:
    m = re.search(r"\d+", str(v or ""))
    return int(m.group()) if m else 0


def _program(path: str) -> str:
    """The program a command line or service ImagePath starts."""
    p = str(path or "").strip()
    if p.startswith('"'):
        return p[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.(?:exe|com|bat|cmd|scr|sys|dll))(?:\s|$)", p, re.IGNORECASE)
    return m.group(1) if m else p.split(" ", 1)[0]


def _user_from_hive(hive: str) -> str:
    parts = str(hive or "").replace("/", "\\").split("\\")
    low = [x.lower() for x in parts]
    return parts[low.index("users") + 1] if "users" in low and low.index("users") + 1 < len(parts) else ""


def amcache(csvs: Path):
    for table in ("amcache_AssociatedFileEntries", "amcache_UnassociatedFileEntries"):
        for r in _rows(csvs, table):
            path = r.get("FullPath") or ""
            yield Sighting("amcache", (r.get("Name") or basename(path)).strip().lower(), path,
                           time_utc=utc(r.get("FileKeyLastWriteTimestamp")),
                           sha1=(r.get("SHA1") or "").strip().lower())


def prefetch(csvs: Path):
    for r in _rows(csvs, "prefetch"):
        name = (r.get("ExecutableName") or "").strip().lower()
        if not name:
            continue
        path = next((f.strip() for f in (r.get("FilesLoaded") or "").split(",")
                     if basename(f) == name), "")
        yield Sighting("prefetch", name, path, time_utc=utc(r.get("LastRun")),
                       runs=_int(r.get("RunCount")))


def shimcache(csvs: Path):
    for r in _rows(csvs, "reg_shimcache"):
        path = r.get("Path") or ""
        if path:
            yield Sighting("shimcache", basename(path), path)


def bam(csvs: Path):
    for r in _rows(csvs, "reg_bamDam"):
        path = r.get("ValueName") or ""
        if "\\" not in path:
            continue
        sid = (r.get("KeyPath") or "").rstrip("\\").rsplit("\\", 1)[-1]
        yield Sighting("bam", basename(path), path, user=sid if sid.startswith("S-") else "",
                       time_utc=utc(r.get("ValueData2")))


def userassist(csvs: Path):
    for r in _rows(csvs, "reg_userAssist"):
        path = r.get("ValueName") or ""
        if not basename(path).endswith(".exe"):
            continue
        yield Sighting("userassist", basename(path), path, user=_user_from_hive(r.get("HivePath")),
                       time_utc=utc(r.get("ValueData2")), runs=_int(r.get("ValueData3")))


def pca(csvs: Path):
    for r in _rows(csvs, "pca"):
        path = r.get("executable_path") or ""
        if path:
            yield Sighting("pca", basename(path), path)


def srum(csvs: Path):
    for table in ("srum_NetworkUsages", "srum_AppResourceUseInfo"):
        for r in _rows(csvs, table):
            path = r.get("ExeInfo") or ""
            if "\\" in path:
                yield Sighting("srum", basename(path), path, user=r.get("UserName") or "",
                               time_utc=utc(r.get("Timestamp")))


def services(csvs: Path):
    for r in _rows(csvs, "reg_services"):
        if (r.get("ValueName") or "").lower() != "imagepath":
            continue
        path = _program(r.get("ValueData") or "")
        if path:
            yield Sighting("service", basename(path), path, time_utc=utc(r.get("LastWriteTimestamp")))


def tasks(csvs: Path):
    for r in _rows(csvs, "tasks_disk"):
        path = _program(r.get("command") or "")
        if path:
            yield Sighting("task", basename(path), path, user=r.get("runas") or "")


def shortcuts(csvs: Path):
    for table, col in (("lnk", "LocalPath"), ("jumplist_AutomaticDestinations", "Path"),
                       ("jumplist_CustomDestinations", "LocalPath")):
        for r in _rows(csvs, table):
            path = r.get(col) or ""
            if basename(path).endswith(".exe"):
                yield Sighting("lnk" if table == "lnk" else "jumplist", basename(path), path)


def processes(ctx):
    """The LiveResponse process list -- the live host's, so never for a VSS volume."""
    if str(ctx.volume).upper().startswith("VSS"):
        return
    results = _find_results(ctx)
    if results is None:
        return
    for f in results.glob("*.json"):
        if _artifact_key(f) != "Windows.System.Pslist":
            continue
        for p in _read_jsonl(f):
            path = p.get("Exe") or ""
            name = basename(path) or (p.get("Name") or "").strip().lower()
            if name:
                yield Sighting("process", name, path, user=p.get("Username") or "",
                               time_utc=utc(p.get("CreateTime")))


READERS = (amcache, prefetch, shimcache, bam, userassist, pca, srum, services, tasks, shortcuts)


def sightings(ctx, csvs: Path):
    """Every Sighting the machine's parsed artifacts hold."""
    for reader in READERS:
        yield from reader(csvs)
    yield from processes(ctx)
