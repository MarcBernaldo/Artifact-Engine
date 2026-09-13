"""The record that outlives the run, and the line it must not cross.

Two questions, and they pull in opposite directions. A run that fails BEFORE it
knows where the case is has nowhere to write -- a mistyped path, a preflight
refusal -- so the only trace is stdout, and a scheduled task discards stdout: an
unattended failure that leaves no record reads exactly like a run that never
started. That argues for keeping everything somewhere central.

The other question is what a file OUTSIDE the case directory is allowed to hold.
Mirroring a real run into it would put hostnames, usernames and evidence paths in
a file that rotates out of the analyst's sight. So the global log takes the
lifecycle of each invocation plus whatever is raised while nothing else is
recording -- and stops the moment the case has a log of its own.
"""
from __future__ import annotations

import json
import logging
import os
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
