"""Handlers: Volatility 3 over a memory image, one plugin per parser (v0.7.88).

A memory unit (see `core/memory.py`) is a folder beside the image holding a
pointer to it. Each parser here runs ONE Volatility plugin over that image with
the CSV renderer and keeps the table it prints, rewritten as plain CSV
(backslashes un-doubled, blank rows dropped -- v0.7.90), as `mem_<name>.csv`,
which the consolidation turns into a table of the unit's `.db`/`.xlsx`.

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
  otherwise it is removed and the parser fails with the tool's last line --
  except two answers that are not failures of the run (v0.7.91): a plugin that
  declines the Windows build is a skip, and no readable kernel is one worded
  `mem_info` error with every other plugin skipped (see `kernel_found`). Since
  v0.7.117 a plugin that cannot be validated against a kernel `mem_info` DID
  read, or says the kernel is unsupported, is a skip too, and every failure
  carries Volatility's own reason (see `_LAUNCH`).

Timestamps come out as `YYYY-MM-DD hh:mm:ss.ffffff UTC`: the basis is in the
value, so the columns keep Volatility's names.

Where Volatility's own plugin fails or wastes the run, the engine ships its own
(`volplugins`, loaded with `-p`; `run_plugin(..., ours=True)`), and `with_stock`
falls back to Volatility's when the engine's does not run (v0.7.163-164).
"""

from __future__ import annotations

import csv
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from artifact_engine import volplugins
from artifact_engine.core import procs
from artifact_engine.core.memory import image_of
from artifact_engine.core.runner import HandlerSkip, marker_path

if TYPE_CHECKING:
    # never imported here (they import Volatility); named so that a change to
    # one changes the fingerprint of every parser that can run it
    from artifact_engine.volplugins import aeng_linux, aeng_windows  # noqa: F401

# Volatility's -p: the engine's own plugins
PLUGIN_DIR = str(Path(volplugins.__file__).parent)

# A scan plugin reads the whole image; on a 18 GB image with a dozen running at
# once the slowest measured took under two minutes. An hour is room for images
# several times that size on slower storage, and still ends a plugin that hangs.
_TIMEOUT = 3600

# `python -c` leaves "-c" in sys.argv[0], and Volatility's parser then reads it as
# its own `-c/--config` option and exits 2 before running anything: measured, all
# 44 plugins of the first real run. argv[0] is set to what `vol` itself would see.
#
# And when a plugin raises, Volatility prints only "Volatility encountered an
# unexpected situation", keeping the exception's own words for -vvv (megabytes of
# debug lines). The launcher hooks `CommandLine.process_exceptions` to write them
# to stderr first, on one marked line (`_reason`): a plugin saying it does not
# support this kernel is then a skip, and every other failure says why (v0.7.113
# for Linux, here for both since v0.7.117). A `volatility3.cli` without the hook
# point runs as it is.
_REASON = "AENG-VOLATILITY-REASON: "
_LAUNCH = ("import sys; sys.argv[0] = 'vol'\n"
           "from volatility3 import cli\n"
           "_said = getattr(getattr(cli, 'CommandLine', None), 'process_exceptions', None)\n"
           "def _say(self, excp):\n"
           f"    sys.stderr.write('\\n{_REASON}' + type(excp).__name__ + ': ' + str(excp) + '\\n')\n"
           "    sys.stderr.flush()\n"
           "    return _said(self, excp)\n"
           "if _said is not None:\n"
           "    cli.CommandLine.process_exceptions = _say\n"
           "sys.exit(cli.main())\n")
# What a plugin raises when the kernel lacks what it reads -- measured on Linux:
# kthreads ("only works with kernels >= 5.8"), capabilities ("Unsupported kernel
# capabilities implementation"), ebpf ("... Unsupported kernel").
_UNSUPPORTED_RX = re.compile(r"unsupported|only works with kernels?|not supported",
                             re.IGNORECASE)


def _reason(err: str) -> str:
    """The exception Volatility gave up on, as the launcher wrote it, or ''."""
    lines = [ln[len(_REASON):].strip() for ln in err.splitlines() if ln.startswith(_REASON)]
    return lines[-1][:300] if lines else ""


# Volatility's automagic catches every exception it meets while stacking the
# image's layers and only logs it (this WARNING, to stderr); the plugin then
# fails "Unable to validate the plugin requirements" too. So that line alone
# does not say the kernel lacks what the plugin reads: an image another process
# holds open, a volume that dropped, a MemoryError among parallel plugins look
# the same -- except for this line (found by review, v0.7.117).
_AUTOMAGIC_FAILED = "Automagic exception occurred"


def kernel_gap(err: str) -> bool:
    """Whether a failed plugin's stderr says THIS plugin does not apply to a
    kernel that was read -- a skip once the unit's info plugin succeeded --
    rather than that something went wrong, which stays an error."""
    why = _reason(err)
    if why and _UNSUPPORTED_RX.search(why):
        return True
    return _NO_KERNEL in err and _AUTOMAGIC_FAILED not in err


def _automagic_line(err: str) -> str:
    """The first exception automagic logged, on one line."""
    i = err.find(_AUTOMAGIC_FAILED)
    tail = err[i:].splitlines() if i >= 0 else []
    return " ".join(ln.strip() for ln in tail[:3])[:300]


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


def _unescape(src: Path, dst: Path) -> int:
    """Rewrite Volatility's CSV as an ordinary one; return the data rows written.

    Volatility's CSV renderer is a `csv.DictWriter` with a backslash as its escape
    character, which writes every backslash in a value TWICE. Read as a plain CSV
    -- which is how the consolidation reads every table -- every path and command
    line came out of the `.db` with its separators doubled, so a search for the
    path as Windows writes it found nothing, and any rule on a path or a command
    line matched nothing (v0.7.88 and v0.7.89, seen on a real image).
    Reading with the same escape character is the exact inverse, checked on UNC
    paths, a value ending in a backslash, quotes and line breaks. The renderer's
    trailing blank line is dropped with the other empty rows."""
    rows = 0
    with src.open("r", encoding="utf-8", errors="replace", newline="") as fin, \
            dst.open("w", encoding="utf-8", newline="") as fout:
        w = csv.writer(fout)
        for i, row in enumerate(csv.reader(fin, escapechar="\\")):
            if not row:
                continue
            w.writerow(row)
            rows += i > 0
    return rows


def _tree(pid: int, children: dict[int, list[int]], created) -> list[int]:
    """The processes under `pid`: each names its parent in `children` AND was
    created strictly after it (`created(pid)` -> a time, or None for a process
    gone, unreadable or not to be trusted). Equal times are refused: Windows
    keeps a dead parent's PID in its children's records and reuses the number,
    and its clock ticks every ~15 ms, so an earlier owner's child can share the
    tick; missing a real child only leaves it to the launcher's kill."""
    found: list[int] = []
    queue = [(pid, created(pid))]
    while queue:
        parent, born = queue.pop()
        if born is None:
            continue
        for child in children.get(parent, ()):
            t = created(child)
            if t is not None and t > born and child not in found:
                found.append(child)
                queue.append((child, t))
    return found


def _end_descendants(pid: int) -> None:
    """Terminate every process `pid` started, and theirs, and wait for them to
    be gone (Windows; nothing elsewhere). Called while `pid` is still alive.

    A child is found by its parent PID AND its creation time, read on the one
    handle it is then terminated through: after `pid`'s, and before the
    snapshot was taken -- a process that took a listed child's PID after the
    snapshot was created after it, and is refused. Not `taskkill /T`, which
    follows the PID alone and can reach an unrelated tree; not a job object,
    which a process inside a job allowing silent breakaway never joins."""
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    class _Entry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    k32.Process32FirstW.argtypes = k32.Process32NextW.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(_Entry))
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    k32.GetSystemTimeAsFileTime.argtypes = (ctypes.POINTER(wintypes.FILETIME),)
    k32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)

    def ticks(ft: wintypes.FILETIME) -> int:
        return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

    now = wintypes.FILETIME()
    k32.GetSystemTimeAsFileTime(ctypes.byref(now))
    taken = ticks(now)                                  # read before the snapshot
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)         # TH32CS_SNAPPROCESS
    if not snap or snap == wintypes.HANDLE(-1).value:
        return
    children: dict[int, list[int]] = {}
    try:
        e = _Entry()
        e.dwSize = ctypes.sizeof(_Entry)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            children.setdefault(e.th32ParentProcessID, []).append(e.th32ProcessID)
            ok = k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)

    handles: dict[int, int] = {}

    def created(p: int) -> int | None:
        # QUERY_LIMITED_INFORMATION | TERMINATE | SYNCHRONIZE, held until the end
        # so the PID cannot change hands between the check and the kill
        h = handles.get(p) or k32.OpenProcess(0x1000 | 0x0001 | 0x00100000, False, p)
        if not h:
            return None
        handles[p] = h
        t = [wintypes.FILETIME() for _ in range(4)]
        if not k32.GetProcessTimes(h, *map(ctypes.byref, t)):
            return None
        born = ticks(t[0])
        return born if born < taken else None

    try:
        tree = _tree(pid, children, created)
        for p in tree:
            k32.TerminateProcess(handles[p], 1)
        for p in tree:
            k32.WaitForSingleObject(handles[p], 30_000)  # gone, its files closed
    finally:
        for h in handles.values():
            k32.CloseHandle(h)


def _kill_tree(proc: subprocess.Popen) -> None:
    """End `proc` and every process it started (`_end_descendants`). In a Windows
    venv `python.exe` is a launcher that starts the real interpreter as its
    child: killing the launcher alone left Volatility running, still holding the
    scratch file, so removing it failed and a core stayed busy for nothing. Any
    failure finding the tree leaves the launcher's own kill, as before."""
    try:
        _end_descendants(proc.pid)
    except Exception:  # noqa: BLE001 -- the launcher is still killed below
        pass
    proc.kill()


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
            _kill_tree(proc)
            proc.wait()
            raise
        finally:
            with procs._lock:
                procs._active.discard(proc)
        ferr.seek(0)
        return proc.returncode, ferr.read(1 << 20).decode("utf-8", "replace")


def with_stock(ctx, run, plugin: str, stock: str):
    """`run(plugin, True)` -- the engine's plugin -- or `run(stock, False)` when it
    fails with an error: any but a timeout, since the likeliest is the engine's
    plugin not loading on this Volatility, and the stock one answers the same
    question. An image or symbol error is run again too, and fails again the
    same way; a skip (HandlerSkip) is not an error and is never run again."""
    try:
        return run(plugin, True)
    except RuntimeError as e:
        if "no answer after" in str(e):
            raise
        if ctx.log:
            ctx.log.warning(f"memory: {plugin} failed ({e}); running {stock}")
        return run(stock, False)


_INFO = "mem_info"
# What Volatility says when automagic found no kernel to build a plugin on.
_NO_KERNEL = "Unable to validate the plugin requirements"
# What a plugin says when it found the kernel and does not handle its build.
_UNSUPPORTED = "This version of Windows is not supported"


def kernel_found(unit: Path) -> bool:
    """Whether `mem_info` succeeded on this unit, which is the proof that
    Volatility found a kernel in the image it can read.

    Asked by every other plugin before it starts. When the answer is no, all of
    them would fail the same way after the same minute of scanning -- measured on
    two lab images, 44 errors each, every one the same line -- so they skip
    instead, naming `mem_info`, and the unit reports one error that says what is
    wrong. Read from the parser's `.done` marker (written only on success) in the
    category folder, so a table left by an earlier run is not taken for it."""
    return marker_path(unit / "CSVs" / "Memory", _INFO).is_file()


def run_plugin(ctx, plugin: str, table: str, timeout: int = _TIMEOUT,
               extra: list[str] = (), ours: bool = False) -> Path | None:
    """Run one plugin over the unit's image into `<out>/<table>.csv`.

    Returns the CSV, or None when the plugin ran cleanly and found nothing (no file
    is written: an empty table is clutter, as everywhere else in the engine).
    `ours`: the plugin is one of the engine's (`volplugins`)."""
    image = image_of(Path(ctx.evidence))
    if image is None:
        raise HandlerSkip("not a memory unit (no memory.image pointer)")
    if not image.is_file():
        raise HandlerSkip(f"memory image {image.name} is not where the unit says")
    cmd = vol_command()
    if cmd is None:
        raise HandlerSkip("Volatility 3 is not installed "
                          "(pip install volatility3, or put `vol` on PATH)")
    if table != _INFO and not kernel_found(Path(ctx.evidence)):
        raise HandlerSkip(f"{_INFO} did not succeed on this image, so no plugin can read "
                          f"it -- its error says why")
    out = Path(ctx.out)
    out.mkdir(parents=True, exist_ok=True)
    final = out / f"{table}.csv"
    part = out / f".{table}.csv.part"
    try:
        rc, err = _run_to_file([*cmd, "-q", *(["-p", PLUGIN_DIR] if ours else []),
                                "-r", "csv", "-f", str(image), plugin, *extra],
                               part, timeout)
    except subprocess.TimeoutExpired:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"volatility {plugin}: no answer after {timeout}s") from None
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    if rc != 0:
        part.unlink(missing_ok=True)
        if _UNSUPPORTED in err:
            # The plugin read the image and declined it: a gap in what this
            # plugin covers, not a failure of the run (measured: cmdscan and
            # consoles on Windows 7, five lab images, ten "errors").
            raise HandlerSkip(f"{plugin} does not support this Windows version "
                              f"({_last_line(err).rpartition(': ')[2]})")
        why = _reason(err)
        if table != _INFO and kernel_gap(err):
            # mem_info read this kernel, so it is this plugin that does not apply
            # to it -- a structure this build lacks (v0.7.117; seen: scheduled
            # tasks on an x86 XP image, an error until then).
            raise HandlerSkip(f"{plugin} cannot run on this image's kernel "
                              f"({why or _NO_KERNEL.lower()})")
        if table != _INFO and _AUTOMAGIC_FAILED in err:
            raise RuntimeError(f"volatility {plugin}: could not read the image -- "
                               f"{_automagic_line(err)}")
        if _NO_KERNEL in err:
            raise RuntimeError(
                f"volatility {plugin}: no Windows kernel it can read in this image "
                f"({_NO_KERNEL.lower()}) -- an unsupported Windows build or "
                f"architecture (some 32-bit images), a non-Windows image, or a "
                f"truncated one")
        raise RuntimeError(f"volatility {plugin} exited {rc}: {why or _last_line(err)}")
    clean = out / f".{table}.csv.clean"
    try:
        rows = _unescape(part, clean)
    except BaseException:
        clean.unlink(missing_ok=True)
        raise
    finally:
        part.unlink(missing_ok=True)
    if not rows:
        clean.unlink(missing_ok=True)
        return None
    os.replace(clean, final)
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
    path = run_plugin(ctx, "windows.info.Info", _INFO)
    if path is None:
        raise RuntimeError("windows.info found no Windows kernel in the image")
    image = image_of(Path(ctx.evidence))
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
