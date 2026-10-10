"""Handlers: Volatility 3 over a memory image, one plugin per parser (v0.7.88).

A memory unit (see `core/memory.py`) is a folder beside the image holding a
pointer to it. Each parser here runs ONE Volatility plugin over that image with
the CSV renderer and keeps the table it prints as `mem_<name>.csv`, which the
consolidation turns into a table of the unit's `.db`/`.xlsx` like any other.

Why a plugin per parser rather than one parser running them all: the scheduler
then runs them in parallel across the pool, a plugin that dies costs its own
table and not the rest, a re-run repeats only what failed, and the summary names
exactly which plugin it was. `mem_info` runs first and every other parser
depends on it: the first plugin over an image is the one that resolves the
kernel's symbols (downloading them once, if this host has never seen that
build), and forty plugins doing that at the same moment would download the same
file forty times into one cache.

TWO WAYS THIS LOSES ROWS IN SILENCE, both closed here:

- Volatility writes its table to stdout, and a Python child whose stdout is a
  FILE on Windows encodes it with the ANSI code page. The first process, file or
  service name holding a character that page cannot encode raises
  `UnicodeEncodeError` mid-table and the plugin exits -- measured on a real
  image, twelve of the first thirty-three plugins stopped that way, `filescan`
  after 16 rows. The child is run with UTF-8 forced (`PYTHONIOENCODING`,
  `PYTHONUTF8`).
- A plugin that exits non-zero has printed SOME of its table. That prefix is
  never kept: it would land in the `.db` looking like the whole answer. The
  output is written to a scratch file and only renamed into place on exit 0;
  otherwise it is removed and the parser fails with the tool's last line.

Timestamps come out as `YYYY-MM-DD hh:mm:ss.ffffff UTC`: the basis is in the
value, so the columns keep Volatility's names.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from artifact_engine.core import procs
from artifact_engine.core.memory import image_of
from artifact_engine.core.runner import HandlerSkip

# A scan plugin reads the whole image; on a 18 GB image with a dozen running at
# once the slowest measured took under two minutes. An hour is room for images
# several times that size on slower storage, and still ends a plugin that hangs.
_TIMEOUT = 3600

# `python -c` leaves "-c" in sys.argv[0], and Volatility's parser then reads it as
# its own `-c/--config` option and exits 2 before running anything: measured, all
# 44 plugins of the first real run. argv[0] is set to what `vol` itself would see.
_LAUNCH = ("import sys; sys.argv[0] = 'vol'; "
           "from volatility3.cli import main; sys.exit(main())")


def vol_command() -> list[str] | None:
    """How to start Volatility 3 on this host, or None when it is not installed.

    The interpreter running the engine is asked first, so the version that runs is
    the one installed next to the engine (`pip install artifact-engine[memory]`)
    and not whichever `vol` happens to be first on PATH. A standalone `vol` is the
    fallback."""
    if importlib.util.find_spec("volatility3") is not None:
        return [sys.executable, "-c", _LAUNCH]
    exe = shutil.which("vol") or shutil.which("vol.exe")
    return [exe] if exe else None


def vol_version() -> str:
    try:
        from volatility3.framework import constants
        return str(constants.PACKAGE_VERSION)
    except Exception:  # noqa: BLE001 -- standalone vol, or a broken install
        return ""


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[-1][:300] if lines else ""


def _has_rows(path: Path) -> bool:
    """More than the header line."""
    with path.open("rb") as fh:
        fh.readline()
        return bool(fh.readline().strip())


def _run_to_file(cmd: list[str], dst: Path, timeout: int) -> tuple[int, str]:
    """Run `cmd` with its stdout written to `dst` whole; return (rc, stderr).

    `procs.run` keeps stdout as a diagnostic and caps it, and Volatility's stdout is
    the table itself. This is that function with the stream going to a file, and
    it registers the process the same way so Ctrl+C (`procs.cancel_all`) still ends
    it. It lives here rather than as an option of `procs.run` on purpose: `procs`
    is in the import closure of every handler (`runner` imports it), so changing
    it would re-fingerprint every parser and re-parse every case already done."""
    with open(dst, "wb") as fout, tempfile.TemporaryFile() as ferr:
        proc = subprocess.Popen(cmd, stdout=fout, stderr=ferr, env=_env(),
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        with procs._lock:
            procs._active.add(proc)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise
        finally:
            with procs._lock:
                procs._active.discard(proc)
        ferr.seek(0)
        return proc.returncode, ferr.read(1 << 20).decode("utf-8", "replace")


def run_plugin(ctx, plugin: str, table: str, timeout: int = _TIMEOUT) -> Path | None:
    """Run one plugin over the unit's image into `<out>/<table>.csv`.

    Returns the CSV, or None when the plugin ran cleanly and found nothing (no file
    is written: an empty table is clutter, as everywhere else in the engine)."""
    image = image_of(Path(ctx.evidence))
    if image is None:
        raise HandlerSkip("not a memory unit (no memory.image pointer)")
    if not image.is_file():
        raise HandlerSkip(f"memory image {image.name} is not where the unit says")
    cmd = vol_command()
    if cmd is None:
        raise HandlerSkip("Volatility 3 is not installed "
                          "(pip install volatility3, or put `vol` on PATH)")
    out = Path(ctx.out)
    out.mkdir(parents=True, exist_ok=True)
    final = out / f"{table}.csv"
    part = out / f".{table}.csv.part"
    try:
        rc, err = _run_to_file([*cmd, "-q", "-r", "csv", "-f", str(image), plugin],
                               part, timeout)
    except subprocess.TimeoutExpired:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"volatility {plugin}: no answer after {timeout}s") from None
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    if rc != 0:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"volatility {plugin} exited {rc}: {_last_line(err)}")
    if not _has_rows(part):
        part.unlink(missing_ok=True)
        return None
    os.replace(part, final)
    if ctx.log:
        ctx.log.debug(f"memory: {plugin} -> {final.name}")
    return final


def _plugin(plugin: str, table: str):
    def run(ctx) -> None:
        run_plugin(ctx, plugin, table)
    run.__doc__ = f"Volatility 3 `{plugin}` -> {table}.csv"
    return run


def info(ctx) -> None:
    """`windows.info`, plus three rows saying what produced the rest of the unit:
    the Volatility version, the image's name and its size."""
    path = run_plugin(ctx, "windows.info.Info", "mem_info")
    if path is None:
        raise RuntimeError("windows.info found no Windows kernel in the image")
    image = image_of(Path(ctx.evidence))
    import csv
    with path.open("a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([0, "Volatility 3", vol_version() or "(standalone vol)"])
        w.writerow([0, "Image file", image.name])
        w.writerow([0, "Image size (bytes)", image.stat().st_size])


# --- processes ------------------------------------------------------------------
pslist = _plugin("windows.pslist.PsList", "mem_pslist")
psscan = _plugin("windows.psscan.PsScan", "mem_psscan")
pstree = _plugin("windows.pstree.PsTree", "mem_pstree")
psxview = _plugin("windows.malware.psxview.PsXView", "mem_psxview")
cmdline = _plugin("windows.cmdline.CmdLine", "mem_cmdline")
envars = _plugin("windows.envars.Envars", "mem_envars")
dlllist = _plugin("windows.dlllist.DllList", "mem_dlllist")
getsids = _plugin("windows.getsids.GetSIDs", "mem_getsids")
privileges = _plugin("windows.privileges.Privs", "mem_privileges")
handles = _plugin("windows.handles.Handles", "mem_handles")
sessions = _plugin("windows.sessions.Sessions", "mem_sessions")
cmdscan = _plugin("windows.cmdscan.CmdScan", "mem_cmdscan")
consoles = _plugin("windows.consoles.Consoles", "mem_consoles")
# --- network --------------------------------------------------------------------
netscan = _plugin("windows.netscan.NetScan", "mem_netscan")
netstat = _plugin("windows.netstat.NetStat", "mem_netstat")
# --- services, drivers, kernel --------------------------------------------------
svcscan = _plugin("windows.svcscan.SvcScan", "mem_svcscan")
svcdiff = _plugin("windows.malware.svcdiff.SvcDiff", "mem_svcdiff")
modules = _plugin("windows.modules.Modules", "mem_modules")
modscan = _plugin("windows.modscan.ModScan", "mem_modscan")
driverscan = _plugin("windows.driverscan.DriverScan", "mem_driverscan")
drivermodule = _plugin("windows.malware.drivermodule.DriverModule", "mem_drivermodule")
unloadedmodules = _plugin("windows.unloadedmodules.UnloadedModules", "mem_unloadedmodules")
callbacks = _plugin("windows.callbacks.Callbacks", "mem_callbacks")
ssdt = _plugin("windows.ssdt.SSDT", "mem_ssdt")
mutantscan = _plugin("windows.mutantscan.MutantScan", "mem_mutantscan")
symlinkscan = _plugin("windows.symlinkscan.SymlinkScan", "mem_symlinkscan")
# --- code that should not be there ----------------------------------------------
malfind = _plugin("windows.malware.malfind.Malfind", "mem_malfind")
ldrmodules = _plugin("windows.malware.ldrmodules.LdrModules", "mem_ldrmodules")
hollowprocesses = _plugin("windows.malware.hollowprocesses.HollowProcesses",
                          "mem_hollowprocesses")
processghosting = _plugin("windows.malware.processghosting.ProcessGhosting",
                          "mem_processghosting")
pebmasquerade = _plugin("windows.malware.pebmasquerade.PebMasquerade", "mem_pebmasquerade")
suspicious_threads = _plugin("windows.malware.suspicious_threads.SuspiciousThreads",
                             "mem_suspicious_threads")
etwpatch = _plugin("windows.etwpatch.EtwPatch", "mem_etwpatch")
orphan_threads = _plugin("windows.orphan_kernel_threads.Threads", "mem_orphan_threads")
skeleton_key = _plugin("windows.malware.skeleton_key_check.Skeleton_Key_Check",
                       "mem_skeleton_key")
# --- registry and files still in memory -----------------------------------------
hivelist = _plugin("windows.registry.hivelist.HiveList", "mem_hivelist")
userassist = _plugin("windows.registry.userassist.UserAssist", "mem_userassist")
scheduled_tasks = _plugin("windows.registry.scheduled_tasks.ScheduledTasks",
                          "mem_scheduled_tasks")
shimcache = _plugin("windows.shimcachemem.ShimcacheMem", "mem_shimcache")
amcache = _plugin("windows.registry.amcache.Amcache", "mem_amcache")
filescan = _plugin("windows.filescan.FileScan", "mem_filescan")
mftscan = _plugin("windows.mftscan.MFTScan", "mem_mftscan")
ads = _plugin("windows.mftscan.ADS", "mem_ads")
