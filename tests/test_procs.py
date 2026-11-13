"""External process execution: capture, timeout, and the thread cost of a run."""

from __future__ import annotations

import subprocess
import sys
import threading
import time

import pytest

from artifact_engine.core import procs


def test_run_captures_both_streams_and_the_return_code():
    rc, out, err = procs.run([sys.executable, "-c",
                              "import sys; print('OUT'); print('ERR', file=sys.stderr);"
                              " sys.exit(3)"])

    assert rc == 3
    assert "OUT" in out
    assert "ERR" in err


def test_non_utf8_tool_output_does_not_raise():
    """EZ tools emit bytes that are not valid UTF-8; a strict decode would turn a
    successful parse into a crash."""
    rc, out, _err = procs.run([sys.executable, "-c",
                               "import sys; sys.stdout.buffer.write(b'a\\xff\\xfeb')"])

    assert rc == 0
    assert "a" in out and "b" in out


def test_a_timeout_kills_the_tool_and_is_re_raised():
    with pytest.raises(subprocess.TimeoutExpired):
        procs.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)


def test_a_running_tool_costs_no_reader_threads():
    """`communicate()` starts a reader thread per pipe, so capturing stdout and
    stderr used to cost TWO threads per tool -- ~64 of them at max_workers: 32,
    in the parent, doing nothing but copying bytes."""
    base = threading.active_count()
    peak = 0
    stop = threading.Event()

    def sample() -> None:
        nonlocal peak
        while not stop.is_set():
            peak = max(peak, threading.active_count())
            time.sleep(0.005)

    watcher = threading.Thread(target=sample)
    watcher.start()
    try:
        procs.run([sys.executable, "-c", "import time; time.sleep(0.5); print('x')"])
    finally:
        stop.set()
        watcher.join()

    assert peak <= base + 1, f"a single tool run added {peak - base - 1} extra thread(s)"


def test_only_python_310_on_windows_is_flagged():
    """The guard names 3.10 on Windows because that is the one measured: it
    reproduces the fault, 3.13 never reaches it, and 3.11/3.12 were not tested --
    so neither is claimed either way."""
    from artifact_engine.cli import interpreter_risks_memoryview_crash as risky

    assert risky("nt", (3, 10, 11))
    assert not risky("nt", (3, 13, 14))
    assert not risky("posix", (3, 10, 11))     # the pool uses fork, not pipes+overlapped
    assert not risky("nt", (3, 14, 0))


def test_cancel_all_leaves_no_process_registered():
    procs.cancel_all()                      # nothing running: must not raise
    rc, _out, _err = procs.run([sys.executable, "-c", "pass"])

    assert rc == 0
    assert not procs._active


# A Windows venv's python.exe: it starts the real interpreter as its child and
# waits. The child writes its own PID down so the test can look for it after.
_LAUNCHER = """
import subprocess, sys
subprocess.call([sys.executable, "-c",
                 "import os, sys, time; open(sys.argv[1], 'w').write(str(os.getpid())); "
                 "time.sleep(120)", sys.argv[1]])
"""


def _alive(pid: int) -> bool:
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True,
                         text=True, check=False).stdout
    return str(pid) in out.split()


def _launch(tmp_path, **kw):
    script = tmp_path / "launcher.py"
    script.write_text(_LAUNCHER, encoding="utf-8")
    pidfile = tmp_path / "child.pid"
    errors: list = []

    def go():
        try:
            procs.run([sys.executable, str(script), str(pidfile)], **kw)
        except Exception as e:  # noqa: BLE001
            errors.append(e)
    t = threading.Thread(target=go, daemon=True)
    t.start()
    deadline = time.monotonic() + 30
    while not (pidfile.is_file() and pidfile.read_text()) and time.monotonic() < deadline:
        time.sleep(0.1)
    return t, int(pidfile.read_text()), errors


@pytest.mark.skipif(sys.platform != "win32", reason="a launcher process is a Windows venv's")
def test_ctrl_c_ends_what_a_tool_started_not_only_the_tool(tmp_path):
    """Ending the launcher alone left its child -- Volatility, under a venv --
    reading the evidence after the engine had said it stopped."""
    t, child, _ = _launch(tmp_path)
    assert _alive(child)
    procs.cancel_all()
    t.join(30)
    assert not t.is_alive() and not _alive(child)
    assert not procs._active


@pytest.mark.skipif(sys.platform != "win32", reason="a launcher process is a Windows venv's")
def test_a_timeout_ends_what_a_tool_started_too(tmp_path):
    t, child, errors = _launch(tmp_path, timeout=5)
    t.join(60)
    assert errors and isinstance(errors[0], subprocess.TimeoutExpired)
    assert not _alive(child)


def test_ctrl_c_tells_the_children_to_end_without_waiting_for_them(monkeypatch):
    """A child stuck in I/O cannot finish terminating; waiting for it, tool after
    tool, froze the Ctrl+C, and a second one pressed meanwhile left before any tool
    had been told to stop. The timeout path still waits: it has a file to free."""
    calls = []
    monkeypatch.setattr(procs, "end_descendants", lambda pid, wait=True: calls.append((pid, wait)))

    class _Tool:
        pid = 4242
        terminated = False

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

    tool = _Tool()
    procs._active.add(tool)
    try:
        procs.cancel_all()
    finally:
        procs._active.discard(tool)
    assert calls == [(4242, False)] and tool.terminated


def test_a_tool_is_given_no_stdin_to_wait_on(monkeypatch):
    """Inherited, stdin let a 7-Zip opening an encrypted archive wait for a
    password nobody was asked for (AE-102). Whether an inherited stdin blocks
    depends on how the tests were started, so the call itself is checked."""
    seen: dict = {}

    class _Stop(Exception):
        pass

    def popen(cmd, **kw):
        seen.update(kw)
        raise _Stop

    monkeypatch.setattr(procs.subprocess, "Popen", popen)
    with pytest.raises(_Stop):
        procs.run(["7z.exe"])
    assert seen.get("stdin") == subprocess.DEVNULL


def test_a_tool_ended_by_a_cancel_is_not_returned_as_an_exit_code(tmp_path):
    """A killed 7-Zip exits 1, which the extractor reads as "read to the end, with
    complaints": a Ctrl+C mid-extraction marked a half tree `warnings` (AE-102)."""
    errors: list = []
    started = threading.Event()

    def go():
        started.set()
        try:
            procs.run([sys.executable, "-c", "import time; time.sleep(120)"])
        except Exception as e:  # noqa: BLE001
            errors.append(e)
    t = threading.Thread(target=go, daemon=True)
    t.start()
    started.wait(10)
    deadline = time.monotonic() + 30
    while not procs._active and time.monotonic() < deadline:
        time.sleep(0.05)
    procs.cancel_all()
    t.join(30)
    assert not t.is_alive()
    assert [type(e) for e in errors] == [procs.Cancelled]
    assert not [p for p in procs._cancelled if isinstance(p, subprocess.Popen)]
