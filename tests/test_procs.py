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
