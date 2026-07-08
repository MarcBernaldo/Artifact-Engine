"""Cancelable external process execution.

Registers every running process so they can all be terminated with Ctrl+C
(`cancel_all`). Used by both the extractor (7-Zip) and the parser runner.
"""

from __future__ import annotations

import subprocess
import threading

_active: set[subprocess.Popen] = set()
_lock = threading.Lock()


def run(cmd: list[str], timeout: int | None = None, cwd: str | None = None) -> tuple[int, str, str]:
    """Run `cmd`, return (returncode, stdout, stderr).

    Registers the process so `cancel_all` can terminate it. If the timeout
    expires, kills the process and re-raises subprocess.TimeoutExpired. `cwd` sets
    the working dir (e.g. esentutl writes <db>.INTEG.RAW into the CWD).
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",  # tool output contains non-UTF8 bytes; don't crash the reader thread
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        cwd=cwd,
    )
    with _lock:
        _active.add(proc)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    finally:
        with _lock:
            _active.discard(proc)
    return proc.returncode, out, err


def cancel_all() -> None:
    """Terminate all running external processes (Ctrl+C handler)."""
    with _lock:
        procs = list(_active)
    for proc in procs:
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
