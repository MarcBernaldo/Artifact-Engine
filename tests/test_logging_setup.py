"""Everything `logging_setup` owns: where a run is recorded, and what it refuses
to print.

Two subjects, and they only look unrelated. The first is the record itself -- the
per-case `aeng-run.log`, and beside it the rotated index of invocations that
exists for the run which fails BEFORE it knows where the case is, whose only
other trace is a stdout a scheduled task discards. The second is the quiet
unraisable hook, which is here because the same module installs it and because
its one hard rule is about logging: it runs from the cyclic GC, so a log call
there re-enters a handler mid-write and deadlocks the run.

What binds them is the line this module draws around what leaves the case
directory. The global log is an INDEX, never a copy: mirroring a real run into a
file outside the case would put hostnames, accounts and evidence paths somewhere
that rotates out of the analyst's sight -- see "Case data never becomes text" in
CLAUDE.md.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import pytest

from artifact_engine import cli, logging_setup


def _lines(directory: Path) -> list[dict]:
    log = directory / logging_setup.GLOBAL_LOG_NAME
    if not log.is_file():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _said(directory: Path) -> str:
    return "\n".join(r["msg"] for r in _lines(directory))


@pytest.fixture
def logdir(monkeypatch, tmp_path) -> Path:
    d = tmp_path / "statedir"
    monkeypatch.setenv(logging_setup.GLOBAL_LOG_ENV, str(d))
    return d


# --------------------------------------------------------------------------- #
# The window nothing else covers
# --------------------------------------------------------------------------- #
def test_a_run_that_dies_before_it_finds_the_case_still_leaves_a_record(logdir):
    """The failure this whole file exists for: there is no case root, so there is
    no `aeng-run.log` to write the reason into."""
    assert cli.main(["run", "-p", str(logdir / "nowhere")]) == 1

    assert "path does not exist" in _said(logdir)


def test_every_invocation_is_bracketed_by_a_start_and_a_finish(logdir):
    """A start with no finish is the signature of a process that was KILLED --
    the interpreter fault, a reboot, an OOM. Nothing else records that, because
    nothing else gets to run afterwards."""
    cli.main(["list-parsers"])

    records = _lines(logdir)
    assert [r["msg"].split()[1] for r in records] == ["started", "finished"]
    assert len({r["pid"] for r in records}) == 1


def test_a_crash_is_named_on_the_way_out_and_not_swallowed(logdir, monkeypatch):
    """An `except` that recorded a crash and then returned an exit code would
    hide it from everything upstream. It is named in passing and re-raised."""
    def _boom(_args):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(cli, "cmd_list_parsers", _boom)
    with pytest.raises(RuntimeError):
        cli.main(["list-parsers"])

    assert "crashed RuntimeError" in _said(logdir)


def test_the_verdict_of_an_ordinary_run_is_recorded_too(logdir, monkeypatch):
    monkeypatch.setattr(cli, "cmd_list_parsers", lambda _a: 2)
    assert cli.main(["list-parsers"]) == 2

    assert "finished rc=2" in _said(logdir)


# --------------------------------------------------------------------------- #
# The line it must not cross
# --------------------------------------------------------------------------- #
def test_a_warning_is_kept_while_no_case_log_is_open(logdir):
    root = logging_setup.setup_logging()
    root.warning("[!] nowhere to put this yet")

    assert "nowhere to put this yet" in _said(logdir)


def test_the_case_log_is_never_mirrored_outside_the_case(logdir, tmp_path):
    """The privacy property, and the reason this log is an index and not a copy.

    A real run's warnings name hosts, accounts and evidence paths. Once the case
    has a log of its own, that is where they belong and the only place they go --
    see "Case data never becomes text" in CLAUDE.md.
    """
    case = tmp_path / "case" / "aeng-run.log"
    root = logging_setup.setup_logging(log_file=case)
    root.warning("[!] could not read the profile of jdoe on HOST-01")

    assert "jdoe" in case.read_text(encoding="utf-8")
    assert "jdoe" not in _said(logdir)
    assert "HOST-01" not in _said(logdir)


def test_the_progress_safe_channel_does_not_reach_it_either(logdir, tmp_path):
    """`log_file_only` hands records straight to every FileHandler, and the
    rotating one is a FileHandler. Filtered on the way in, not by luck."""
    case = tmp_path / "case" / "aeng-run.log"
    logging_setup.setup_logging(log_file=case)
    logging_setup.log_file_only("FAILED parser on HOST-01")

    assert "HOST-01" in case.read_text(encoding="utf-8")
    assert "HOST-01" not in _said(logdir)


# --------------------------------------------------------------------------- #
# Where it lives, and what happens when it cannot
# --------------------------------------------------------------------------- #
def test_the_location_is_the_platforms_own_and_does_not_roam(monkeypatch, tmp_path):
    """APPDATA is where the CONFIG lives, and a roaming profile copies it onto
    every machine the analyst signs into. A record of what THIS host did is not
    something to spread across the others."""
    monkeypatch.delenv(logging_setup.GLOBAL_LOG_ENV, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

    where = logging_setup.user_log_dir()
    expected = (tmp_path / "local") if os.name == "nt" else (tmp_path / "state")
    assert where == expected / "artifact-engine" / "logs"
    assert (tmp_path / "roaming") not in where.parents


def test_setting_the_variable_empty_means_keep_no_such_log(monkeypatch):
    """An account with no writable profile is a real deployment."""
    monkeypatch.setenv(logging_setup.GLOBAL_LOG_ENV, "")

    assert logging_setup.user_log_dir() is None
    assert logging_setup.global_log_path() is None
    assert not any(isinstance(h, logging_setup._QuietRotatingFileHandler)
                   for h in logging_setup.setup_logging().handlers)


def test_a_directory_it_cannot_create_never_stops_the_run(monkeypatch, tmp_path):
    """A missing global log must not be the reason a case goes unprocessed."""
    blocked = tmp_path / "afile"
    blocked.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv(logging_setup.GLOBAL_LOG_ENV, str(blocked / "logs"))

    root = logging_setup.setup_logging()
    assert not any(isinstance(h, logging_setup._QuietRotatingFileHandler)
                   for h in root.handlers)


def test_it_rotates_instead_of_growing_without_end(logdir, monkeypatch):
    """Unbounded is the other way this fails unattended: the file that records
    months of scheduled runs is the file nobody ever truncates."""
    monkeypatch.setattr(logging_setup, "_GLOBAL_MAX_BYTES", 2048)
    logging_setup.setup_logging()
    for i in range(200):
        logging_setup.log_globally(f"line {i} " + "x" * 80)

    live = logdir / logging_setup.GLOBAL_LOG_NAME
    assert live.stat().st_size <= 2048 * 2
    assert (logdir / f"{logging_setup.GLOBAL_LOG_NAME}.1").is_file()


def test_a_rollover_that_loses_the_race_never_reaches_the_console(logdir, capsys):
    """Two runs on one host share this file, and on Windows the rename inside
    `doRollover` fails outright while another process holds it open. A traceback
    on stdout lands inside the live progress bars, which repaint by counting
    lines -- so the failure is counted and dropped instead."""
    logging_setup.setup_logging()
    handler = next(h for h in logging.getLogger("aeng").handlers
                   if isinstance(h, logging_setup._QuietRotatingFileHandler))
    before = logging_setup._global_log_failures

    handler.handleError(logging.LogRecord("aeng", logging.INFO, __file__, 0,
                                          "x", (), None))

    assert logging_setup._global_log_failures == before + 1
    assert capsys.readouterr().err == ""


def test_a_replaced_file_handler_is_closed_and_not_merely_dropped(logdir, tmp_path):
    """`setup_logging` runs twice per invocation now -- once in `main` so this log
    exists before the command does, once by the command with the case log it has
    by then found."""
    logging_setup.setup_logging(log_file=tmp_path / "first.log")
    first = next(h for h in logging.getLogger("aeng").handlers
                 if isinstance(h, logging.FileHandler)
                 and not isinstance(h, logging_setup._QuietRotatingFileHandler))

    logging_setup.setup_logging(log_file=tmp_path / "second.log")

    assert first.stream is None


def test_the_config_command_says_where_to_find_it(logdir, caplog):
    """A log nobody can find is not a record."""
    import argparse

    with caplog.at_level(logging.INFO, logger="aeng"):
        cli.cmd_config(argparse.Namespace(config=None))

    assert str(logdir) in "\n".join(r.message for r in caplog.records)


# --------------------------------------------------------------------------- #
# The unraisable hook: a benign CPython artifact, and the deadlock it must not
# cause on its way out
# --------------------------------------------------------------------------- #
class _Args:
    """Stand-in for sys.UnraisableHookArgs (the real one has no public
    constructor); our hook and the delegate only read these attributes."""

    def __init__(self, exc, err_msg=""):
        self.exc_type = type(exc)
        self.exc_value = exc
        self.exc_traceback = None
        self.err_msg = err_msg
        self.object = None


def _with_spy_original():
    """Install our quiet hook on top of a recording spy, so we can observe what
    gets delegated. Returns (delegated_list, restore_fn)."""
    delegated: list = []
    saved = sys.unraisablehook
    sys.unraisablehook = lambda args: delegated.append(args.exc_value)
    # Force a fresh install over the spy (the spy becomes `original`).
    if getattr(sys.unraisablehook, "_aeng_quiet", False):  # pragma: no cover
        pass
    logging_setup._install_quiet_unraisablehook()

    def restore():
        sys.unraisablehook = saved

    return delegated, restore


def test_benign_buffererror_is_suppressed():
    delegated, restore = _with_spy_original()
    before = logging_setup._suppressed_unraisables
    try:
        sys.unraisablehook(_Args(BufferError("memoryview has 1 exported buffer"),
                                 "Exception ignored in tp_clear of"))
        assert delegated == []  # dropped, not delegated
        # counted, not logged: the hook does NO I/O (logging from the GC-context
        # hook re-enters the log stream and deadlocks -- see _install_...docstring)
        assert logging_setup._suppressed_unraisables == before + 1
    finally:
        restore()


def test_the_313_wording_of_the_same_conflict_is_suppressed_too():
    """CPython words one buffer-export conflict two ways, and the wording moved
    with the interpreter: 3.10 reached a memoryview ("memoryview has 1 exported
    buffer"), 3.13 reaches a BytesIO ("Existing exports of data: object cannot be
    re-sized"). Matching only the first meant the filter silently stopped working
    on the migration -- a real run printed raw tracebacks from dataclasses.py,
    functools.py and textwrap.py into the middle of the console output."""
    delegated, restore = _with_spy_original()
    before = logging_setup._suppressed_unraisables
    try:
        sys.unraisablehook(_Args(
            BufferError("Existing exports of data: object cannot be re-sized"),
            "Exception ignored in"))
        assert delegated == [], "the 3.13 wording reached the default hook and printed"
        assert logging_setup._suppressed_unraisables == before + 1
    finally:
        restore()


def test_quiet_hook_does_no_logging():
    """Regression guard: the benign path must not emit a log record. Logging from
    the GC-context unraisablehook re-enters the file handler's buffered stream and
    can deadlock the run, so the hook must stay I/O-free."""
    import logging as _logging

    _, restore = _with_spy_original()
    emitted: list = []

    class _Spy(_logging.Handler):
        def emit(self, record):
            emitted.append(record)

    lg = _logging.getLogger("aeng")
    spy = _Spy()
    lg.addHandler(spy)
    old_level = lg.level
    lg.setLevel(_logging.DEBUG)
    try:
        sys.unraisablehook(_Args(BufferError("memoryview has 2 exported buffers")))
        assert emitted == []   # hook counted it but wrote NOTHING to any handler
    finally:
        lg.removeHandler(spy)
        lg.setLevel(old_level)
        restore()


def test_other_unraisable_is_delegated():
    delegated, restore = _with_spy_original()
    try:
        real = ValueError("a genuine bug")
        sys.unraisablehook(_Args(real, "in <lambda>"))
        assert delegated == [real]  # passed through to the default hook
    finally:
        restore()


def test_unrelated_buffererror_is_delegated():
    # A BufferError that is NOT the mp/GC "exported buffer" artifact must not be
    # swallowed -- only the exact benign string is filtered.
    delegated, restore = _with_spy_original()
    try:
        other = BufferError("some other buffer problem")
        sys.unraisablehook(_Args(other))
        assert delegated == [other]
    finally:
        restore()


def test_install_is_idempotent():
    saved = sys.unraisablehook
    try:
        logging_setup._install_quiet_unraisablehook()
        first = sys.unraisablehook
        logging_setup._install_quiet_unraisablehook()
        assert sys.unraisablehook is first  # not re-wrapped
        assert getattr(sys.unraisablehook, "_aeng_quiet", False)
    finally:
        sys.unraisablehook = saved
