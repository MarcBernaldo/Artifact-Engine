"""Lay the DFIR Artifact Museum out as a case the engine can run.

The museum (github.com/AndrewRathbun/DFIRArtifactMuseum, MIT, with third-party
samples shared with permission) keeps loose artifacts by kind, then Windows
version, then the machine they came from: `Windows/Registry/Win10/RathbunVM/...`,
`Windows/Prefetch/Win11/SutharPC/...`, `Windows/NTFSArtifacts/MFT/Win10/RathbunVM/$MFT`,
often inside a .7z. This puts every sample back where a KAPE collection would
have it, one machine per (version, source): `<case>/<Source>-<Version>_kape/C/...`.
Samples with no source of their own (the LNK and Jump List files per version, WER
reports) go to a `Museum-<Version>` machine. Nothing is copied: files are hard
links into the checkout, or copies where a link cannot be made.

The samples are never committed. Fetch the museum (a sparse checkout of the
folders below is ~600 MB), unpack its archives, then:

    python tests/museum_layout.py <checkout> <unpacked> <case>

`<unpacked>` mirrors the checkout's paths with each archive unpacked into a folder
named after it (7-Zip: `7z x <archive> -o<unpacked>/<dir>/<archive stem>`).
`tests/test_museum.py` runs the engine over `<case>` when AENG_MUSEUM names it.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import sys
from pathlib import Path

# The museum's artifact folders this lays out, and those it reads by name only.
ARTIFACTS = ("$Recycle.Bin", "Amcache", "EventLogs", "JumpLists", "LNK",
             "PowerShellConsoleHost_history", "Prefetch", "RecentFileCache", "Registry",
             "ScheduledTasks", "SRUM", "SUM", "WBEM", "WER", "WindowsDefender",
             "WindowsSearchDB", "WindowsTimeline", "NTFSArtifacts")
# Folders keyed by source with no version level: the version they came from.
_SOURCE_ONLY = {"PowerShellConsoleHost_history", "WindowsDefender"}
_DEFAULT_VERSION = {"BelkasoftCTF_InsiderThreat": "Win10", "APTSimulatorVM": "Win10"}
_VERSION = re.compile(r"^(Win\w*|Server\d+|Unknown)$", re.IGNORECASE)
# The museum spells one source two ways.
_ALIAS = {"BelkasoftCTF_InisderThreat": "BelkasoftCTF_InsiderThreat"}

_SYSTEM_HIVES = {"system", "software", "sam", "security", "default"}
_USER = "museum"
_TASKS = "Windows/System32/Tasks"


def _machine_key(parts: tuple[str, ...]) -> tuple[str, str, tuple[str, ...]] | None:
    """(version, source, path below the source) of a file under Windows/<artifact>/."""
    art = parts[1]
    rest = parts[2:]
    if art == "NTFSArtifacts":              # NTFSArtifacts/<MFT|J>/<Version>/<Source>/...
        if len(rest) < 3 or rest[0] not in ("MFT", "J"):
            return None
        rest = rest[1:]
    if art in _SOURCE_ONLY:
        if not rest:
            return None
        if _VERSION.match(rest[0]):
            return (rest[0], rest[1], rest[2:]) if len(rest) > 2 else None
        return _DEFAULT_VERSION.get(rest[0], "Win10"), rest[0], rest[1:]
    if not rest or not _VERSION.match(rest[0]):
        return None
    version = rest[0]
    if len(rest) == 2:                       # a loose sample right under the version
        return version, "", rest[1:]
    source = rest[1]
    if art == "WER":                         # Win10/<report dir>/Report.wer
        return version, "", rest[1:]
    return version, _ALIAS.get(source, source), rest[2:]


def _user_of(below: tuple[str, ...], default: str = _USER) -> str:
    """A user folder named in the path below the source, if any."""
    for p in below[:-1]:
        name = p.removeprefix("L.")
        if name.lower() in ("$mft", "clean", "dirty", "archive", "config"):
            continue
        if re.search(r"(registryhives|_w1\d|hives|searchdb|wbem|defender|timeline)",
                     name, re.IGNORECASE):
            continue
        return re.sub(r"[^\w.-]+", "_", name)
    return default


def destination(artifact: str, below: tuple[str, ...]) -> str | None:
    """The path under the volume root a KAPE collection would give this file."""
    name = below[-1]
    low = name.lower()
    stem = low.split(".")[0]
    if low.endswith((".7z", ".zip", ".rar", ".md")):
        return None                          # the archive is unpacked; the notes are notes
    if low.endswith(".evtx"):
        return f"Windows/System32/winevt/Logs/{name}"
    if low.endswith(".pf"):
        return f"Windows/prefetch/{name}"
    if stem == "amcache" and (low == "amcache.hve" or low.startswith("amcache.hve.log")):
        return f"Windows/AppCompat/Programs/{name}"
    if low.endswith(".bcf"):
        return "Windows/AppCompat/Programs/RecentFileCache.bcf"
    if artifact == "Registry":
        if stem in ("ntuser",):
            return f"Users/{_user_of(below)}/{name}"
        if stem == "usrclass":
            return f"Users/{_user_of(below)}/AppData/Local/Microsoft/Windows/{name}"
        if stem in _SYSTEM_HIVES and len(below) <= 3:
            return f"Windows/System32/config/{name}"
        return None
    if artifact == "SRUM":
        return f"Windows/System32/sru/{name}"
    if artifact == "NTFSArtifacts":
        if low in ("$mft", "mft"):
            return "$MFT"
        if low in ("$j", "j"):
            return "$Extend/$J"
        return None
    if artifact == "SUM" and low.endswith(".mdb"):
        return f"Windows/System32/LogFiles/SUM/{name}"
    if low.endswith("destinations-ms"):
        kind = "AutomaticDestinations" if "automatic" in low else "CustomDestinations"
        return f"Users/{_USER}/AppData/Roaming/Microsoft/Windows/Recent/{kind}/{name}"
    if low.endswith(".lnk"):
        return f"Users/{_USER}/AppData/Roaming/Microsoft/Windows/Recent/{name}"
    if artifact == "WindowsTimeline" and stem == "activitiescache":
        user = _user_of(below)
        return f"Users/{user}/AppData/Local/ConnectedDevicesPlatform/L.{user}/{name}"
    if artifact == "WindowsSearchDB" and stem == "windows":
        return f"ProgramData/Microsoft/Search/Data/Applications/Windows/{name}"
    if artifact == "WBEM" and (low == "objects.data" or low == "index.btr"
                               or low.startswith("mapping")):
        return f"Windows/System32/wbem/Repository/{name}"
    if artifact == "WER" and low == "report.wer":
        return f"ProgramData/Microsoft/Windows/WER/ReportArchive/{below[0]}/{name}"
    if artifact == "ScheduledTasks":
        return f"{_TASKS}/{'/'.join(below)}"
    if artifact == "PowerShellConsoleHost_history" and low == "consolehost_history.txt":
        return (f"Users/{_USER}/AppData/Roaming/Microsoft/Windows/PowerShell/"
                f"PSReadLine/{name}")
    if artifact == "WindowsDefender" and low.startswith(("mplog", "mpdetection")):
        return f"ProgramData/Microsoft/Windows Defender/Support/{name}"
    if artifact == "$Recycle.Bin" and re.match(r"^\$[IR][0-9A-Z]{6}(\.\w+)?$", name) \
            and not low.endswith(".txt"):
        return f"$Recycle.Bin/S-1-5-21-1-2-3-1001/{name}"
    return None


def machine_dir(version: str, source: str) -> str:
    src = source or "Museum"
    if len(src) > 30:                         # the per-build Prefetch sets name an ISO
        src = "iso-" + hashlib.sha1(src.encode()).hexdigest()[:8]
    return f"{re.sub(r'[^A-Za-z0-9.]+', '', src)}-{version}_kape"


def _place(src: Path, dst: Path) -> bool:
    if dst.exists():
        return False                          # the first sample of a name wins
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)
    return True


def _superseded(root: Path) -> set[Path]:
    """Folders a sibling replaces: `Clean` beside `Dirty` (the dirty copy is what a
    collector gets) and `X` beside `X_1DayLater` (SRUM a day on holds data). Whole
    folders, so a database never lands beside another snapshot's logs."""
    gone: set[Path] = set()
    for d in root.rglob("*"):
        if not d.is_dir():
            continue
        low = d.name.lower()
        for sib in d.parent.iterdir():
            if sib.is_dir() and ((low == "dirty" and sib.name.lower() == "clean")
                                 or low == f"{sib.name.lower()}_1daylater"):
                gone.add(sib)
    return gone


def lay_out(checkout: Path, unpacked: Path, case: Path) -> dict[str, int]:
    """Place every sample; returns {machine dir: files placed}."""
    placed: dict[str, int] = {}
    for root in (checkout, unpacked):
        gone = _superseded(root)
        for f in sorted(root.rglob("*")):
            if not f.is_file() or ".git" in f.parts or gone.intersection(f.parents):
                continue
            parts = f.relative_to(root).parts
            if len(parts) < 3 or parts[0] != "Windows" or parts[1] not in ARTIFACTS:
                continue
            key = _machine_key(parts)
            if key is None:
                continue
            version, source, below = key
            if not below:
                continue
            dest = destination(parts[1], below)
            if dest is None:
                continue
            mdir = machine_dir(version, source)
            vol = case / mdir / "C"
            if _place(f, vol / dest):
                placed[mdir] = placed.get(mdir, 0) + 1
    for mdir in placed:                       # what the windows_kape profile looks for
        (case / mdir / "C" / "Windows" / "System32").mkdir(parents=True, exist_ok=True)
    return placed


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    result = lay_out(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    for m, n in sorted(result.items()):
        print(f"{n:5}  {m}")
