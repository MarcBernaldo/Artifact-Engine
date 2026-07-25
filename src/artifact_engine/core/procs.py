"""Cancelable external process execution.

Registers every running process so they can all be terminated with Ctrl+C
(`cancel_all`). Used by both the extractor (7-Zip) and the parser runner.
"""

from __future__ import annotations

import subprocess
import tempfile
import threading
import time

_active: set[subprocess.Popen] = set()
_lock = threading.Lock()

# Tool output is a diagnostic here, never data: callers read a return code and quote
# a line or two of it. Past this the rest is dropped rather than held in memory.
_MAX_CAPTURE = 1 << 20


def _read(fh) -> str:
    fh.seek(0)
    return fh.read(_MAX_CAPTURE).decode("utf-8", "replace")


def run(cmd: list[str], timeout: int | None = None, cwd: str | None = None) -> tuple[int, str, str]:
    """Run `cmd`, return (returncode, stdout, stderr).

    Registers the process so `cancel_all` can terminate it. If the timeout
    expires, kills the process and re-raises subprocess.TimeoutExpired. `cwd` sets
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
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            cwd=cwd,
        )
        with _lock:
            _active.add(proc)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise
        finally:
            with _lock:
                _active.discard(proc)
        # Decoded here, not by the child's writer: tool output carries non-UTF8
        # bytes and a strict decode would turn a successful parse into a crash.
        return proc.returncode, _read(fout), _read(ferr)


_KILL_GRACE = 3.0   # seconds a tool gets to exit on terminate() before kill()


def cancel_all() -> None:
    """Terminate all running external processes (Ctrl+C handler).

    Escalates to kill(): terminate() is a request, and a tool that blocks or ignores
    it used to survive Ctrl+C and keep running against the evidence after the engine
    had reported itself cancelled. Everything still alive after a short grace period
    is killed outright -- these are read-only triage tools, so there is no partial
    write worth protecting.
    """
    with _lock:
        procs = list(_active)
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
