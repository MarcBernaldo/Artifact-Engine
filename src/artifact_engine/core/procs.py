"""Cancelable external process execution.

Registers every running process so they can all be terminated with Ctrl+C
(`cancel_all`). Used by both the extractor (7-Zip) and the parser runner.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time

_active: set[subprocess.Popen] = set()
_lock = threading.Lock()
# The ones `cancel_all` ended: their exit code is the kill's, not the tool's verdict
# on its input, and `run` says so instead of returning it (v0.7.201, AE-102).
_cancelled: set[subprocess.Popen] = set()


class Cancelled(RuntimeError):
    """The tool was ended by `cancel_all`. A killed 7-Zip exits 1, which reads as
    "read to the end, with complaints": returned as a code, a Ctrl+C mid-extraction
    marked a half tree `warnings` and no later run named it."""

# Tool output is a diagnostic here, never data: callers read a return code and quote
# a line or two of it. Past this the rest is dropped rather than held in memory.
_MAX_CAPTURE = 1 << 20


def _read(fh) -> str:
    fh.seek(0)
    return fh.read(_MAX_CAPTURE).decode("utf-8", "replace")


def run(cmd: list[str], timeout: int | None = None, cwd: str | None = None) -> tuple[int, str, str]:
    """Run `cmd`, return (returncode, stdout, stderr).

    Registers the process so `cancel_all` can terminate it. If the timeout
    expires, kills the process and re-raises subprocess.TimeoutExpired; ended by
    `cancel_all`, it raises `Cancelled` instead of returning the kill's exit code.
    The tool's stdin is the null device: nothing is ever typed into it. `cwd` sets
    the working dir (e.g. esentutl writes <db>.INTEG.RAW into the CWD).

    Output goes to temp FILES, not pipes. `Popen.communicate()` on Windows starts a
    reader thread per pipe, so capturing stdout and stderr costs TWO threads for
    every tool that runs -- at `max_workers: 32` that is ~64 threads in the parent
    doing nothing but copying bytes, on top of the task threads themselves. The
    parent was observed crashing (a null dereference inside the interpreter, same
    instruction every time) only ever at ~128 live threads; the cause is below this
    code, but the thread count is the one thing that correlates, and two thirds of
    it came from here. Files also stop a chatty tool's output from accumulating in
    RAM. Nothing is lost: the process is waited on directly, so the semantics are
    the same minus the threads.
    """
    with tempfile.TemporaryFile() as fout, tempfile.TemporaryFile() as ferr:
        proc = subprocess.Popen(
            cmd,
            stdout=fout,
            stderr=ferr,
            # Nothing is ever typed into a tool here. Inherited, a 7-Zip opening an
            # encrypted archive waited for a password nobody was asked for.
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            cwd=cwd,
        )
        with _lock:
            _active.add(proc)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            proc.wait()
            raise
        finally:
            with _lock:
                _active.discard(proc)
                stopped = proc in _cancelled
                _cancelled.discard(proc)
        if stopped:
            raise Cancelled(f"{os.path.basename(cmd[0])} was ended by a cancel "
                            f"(exit {proc.returncode})")
        # Decoded here, not by the child's writer: tool output carries non-UTF8
        # bytes and a strict decode would turn a successful parse into a crash.
        return proc.returncode, _read(fout), _read(ferr)


def tree(pid: int, children: dict[int, list[int]], created) -> list[int]:
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


def end_descendants(pid: int, wait: bool = True) -> None:
    """Terminate every process `pid` started, and theirs, and with `wait` wait for
    them to be gone (Windows; nothing elsewhere). Called while `pid` is still alive.

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
        found = tree(pid, children, created)
        for p in found:
            k32.TerminateProcess(handles[p], 1)
        for p in found if wait else ():
            k32.WaitForSingleObject(handles[p], 30_000)  # gone, its files closed
    finally:
        for h in handles.values():
            k32.CloseHandle(h)


def kill_tree(proc: subprocess.Popen) -> None:
    """End `proc` and every process it started (`end_descendants`). In a Windows
    venv `python.exe` is a launcher that starts the real interpreter as its
    child: killing the launcher alone left Volatility running, still holding the
    scratch file, so removing it failed and a core stayed busy for nothing. Any
    failure finding the tree leaves the launcher's own kill, as before."""
    try:
        end_descendants(proc.pid)
    except Exception:  # noqa: BLE001 -- the launcher is still killed below
        pass
    proc.kill()


_KILL_GRACE = 3.0   # seconds a tool gets to exit on terminate() before kill()


def cancel_all() -> None:
    """Terminate all running external processes (Ctrl+C handler).

    Escalates to kill(): terminate() is a request, and a tool that blocks or ignores
    it used to survive Ctrl+C and keep running against the evidence after the engine
    had reported itself cancelled. Everything still alive after a short grace period
    is killed outright -- these are read-only triage tools, so there is no partial
    write worth protecting.

    What each tool started is ended first, while the tool is still alive: once it
    is gone nothing names its children any more. A Windows venv's `python.exe`
    (Volatility) is a launcher whose child is the real interpreter, and a Ctrl+C
    that ended the launcher alone left Volatility reading the image, holding its
    scratch file, after the engine had said it stopped. Those are only told to end,
    not waited for: a child stuck in I/O on a share that stopped answering cannot
    finish terminating until the I/O does, and thirty uncancellable seconds per
    child, tool after tool, would freeze the Ctrl+C -- and a second one pressed
    meanwhile would leave before any tool itself had been told to stop.
    """
    with _lock:
        procs = list(_active)
        _cancelled.update(procs)
    for proc in procs:
        pid = getattr(proc, "pid", None)
        if pid:
            try:
                end_descendants(pid, wait=False)
            except Exception:  # noqa: BLE001 -- the tool itself is still ended below
                pass
    for proc in procs:
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
    deadline = time.monotonic() + _KILL_GRACE
    for proc in procs:
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
        except Exception:  # noqa: BLE001
            pass
