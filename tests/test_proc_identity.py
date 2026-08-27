"""Three answers to "what is this process", and what it means when they differ.

The per-PID tree UAC collects holds argv (the process's own claim), comm (the
kernel's name for it, which the process can still set) and the exe symlink
(which it cannot). An implant has to lie in all three to stay hidden, and the
files to catch it with were sitting in every acquisition, unread.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import lin_proc_identity as P


def _ctx(evidence: Path, out: Path) -> ParserContext:
    return ParserContext(
        evidence=evidence, out=out, tools=evidence, assets=evidence,
        machine_name="host", volume="live", log=logging.getLogger("aeng.test"),
    )


def _process(lr: Path, pid: str, *, argv: list[str], comm: str,
             uid: str = "0", ppid: str = "1", nul: bool = True) -> None:
    d = lr / "process" / "proc" / pid
    d.mkdir(parents=True, exist_ok=True)
    sep = "\x00" if nul else " "
    (d / "cmdline.txt").write_bytes((sep.join(argv) + ("\x00" if nul and argv else ""))
                                    .encode())
    (d / "comm.txt").write_text(comm + "\n", encoding="utf-8")
    (d / "status.txt").write_text(
        f"Name:\t{comm}\nState:\tS (sleeping)\nPPid:\t{ppid}\n"
        f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n", encoding="utf-8")


def _exe_listing(lr: Path, entries: dict[str, str]) -> None:
    lines = [f"lrwxrwxrwx 1 root root 0 May 18 06:31 /proc/{pid}/exe -> {target}"
             for pid, target in entries.items()]
    (lr / "process").mkdir(parents=True, exist_ok=True)
    (lr / "process" / "running_processes_full_paths.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


def _rows(evidence: Path, out: Path) -> dict[str, dict]:
    P.run(_ctx(evidence, out))
    text = (out / "proc_identity.csv").read_text(encoding="utf-8").splitlines()
    header = text[0].split(",")
    rows = {}
    for line in text[1:]:
        # no quoted commas in these fixtures
        r = dict(zip(header, line.split(",")))
        rows[r["pid"]] = r
    return rows


@pytest.fixture
def case(tmp_path) -> Path:
    lr = tmp_path / "live_response"
    (tmp_path / "[root]" / "etc").mkdir(parents=True)
    (tmp_path / "[root]" / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\njdoe:x:1000:1000::/home/jdoe:/bin/bash\n",
        encoding="utf-8")
    # an ordinary daemon: all three names agree
    _process(lr, "1", argv=["/usr/lib/systemd/systemd"], comm="systemd")
    # sshd rewrites argv[0] into a status string, as it always has
    _process(lr, "900", argv=["sshd: jdoe@pts/0"], comm="sshd", uid="1000")
    _exe_listing(lr, {"1": "/usr/lib/systemd/systemd",
                      "900": "/usr/sbin/sshd"})
    return tmp_path


# --------------------------------------------------------------------------- #
# The names honest programs use
# --------------------------------------------------------------------------- #
def test_the_ordinary_divergences_are_not_findings(case):
    """Every one of these has to be allowed or the flag is noise, and a flag that
    fires on the ordinary case is a flag nobody reads."""
    rows = _rows(case, case / "CSVs")
    assert rows["1"]["flags"] == "" and rows["1"]["suspicious"] == ""
    assert rows["900"]["flags"] == "", "sshd's argv[0] decoration is not a mismatch"


def test_a_shebang_script_is_settled_by_the_exe_not_by_argv():
    """A script with `#!/usr/bin/python3` runs with comm `python3` and an argv
    that never mentions python. Judged on argv alone, every such unit on the host
    is a mismatch -- which is why the exe is checked first: it is the kernel's
    answer, not the process's."""
    assert P.names_agree("python3", ["/usr/local/bin/collector"], "/usr/bin/python3.11")
    assert not P.names_agree("python3", ["/usr/local/bin/collector"], "")


def test_truncation_and_login_shells_agree():
    assert P.names_agree("systemd-journal", [], "/usr/lib/systemd/systemd-journald")
    assert P.names_agree("bash", ["-bash"], "")
    assert P.names_agree("nginx", ["nginx: worker process"], "")


# --------------------------------------------------------------------------- #
# The lies
# --------------------------------------------------------------------------- #
def test_a_process_wearing_three_different_names_is_flagged(case):
    """The shape this exists for: what `ps` shows, what the kernel calls it, and
    what it actually is are three different things, and no single artifact says
    so -- each one on its own looks ordinary."""
    lr = case / "live_response"
    _process(lr, "15289", argv=["/usr/lib/systemd/systemd-logind"], comm="crond")
    _exe_listing(lr, {"1": "/usr/lib/systemd/systemd",
                      "900": "/usr/sbin/sshd",
                      "15289": "/tmp/staged (deleted)"})

    row = _rows(case, case / "CSVs")["15289"]
    assert "comm_mismatch" in row["flags"]
    assert "exe_deleted" in row["flags"]
    assert row["suspicious"] == "yes"


def test_a_userland_process_dressed_as_a_kernel_thread(case):
    """`ps` renders kernel threads as [kworker/0:1]. A real one has an EMPTY
    cmdline in /proc, so nothing legitimate writes that shape into argv[0]."""
    lr = case / "live_response"
    _process(lr, "4242", argv=["[kworker/3:2]"], comm="bash")
    _exe_listing(lr, {"4242": "/bin/bash"})

    row = _rows(case, case / "CSVs")["4242"]
    assert "argv0_bracketed" in row["flags"] and row["suspicious"] == "yes"


def test_a_uid_with_no_account_behind_it(case):
    lr = case / "live_response"
    _process(lr, "7000", argv=["/usr/sbin/httpd"], comm="httpd", uid="1005")
    _exe_listing(lr, {"7000": "/usr/sbin/httpd"})

    row = _rows(case, case / "CSVs")["7000"]
    assert row["flags"] == "uid_no_passwd" and row["suspicious"] == "yes"
    assert row["user"] == "" and row["uid"] == "1005"


def test_a_replaced_binary_alone_is_not_suspicious(case):
    """A package update replaces the binary under every running process it
    touches. Recorded, because UAC recovered the bytes and they are worth
    looking at -- but not flagged, because routine patching would flag the host."""
    lr = case / "live_response"
    _process(lr, "8000", argv=["/usr/sbin/httpd"], comm="httpd")
    _exe_listing(lr, {"8000": "/usr/sbin/httpd (deleted)"})

    row = _rows(case, case / "CSVs")["8000"]
    assert row["flags"] == "exe_deleted" and row["suspicious"] == ""


# --------------------------------------------------------------------------- #
# The gaps
# --------------------------------------------------------------------------- #
def test_a_check_that_could_not_run_says_so_rather_than_passing(case):
    """Without the exe there is no way to tell a shebang script from a borrowed
    name, so comm_mismatch is not judged. An unjudged check that leaves the row
    blank is indistinguishable from a check that passed."""
    lr = case / "live_response"
    _process(lr, "9100", argv=["/usr/local/bin/thing"], comm="somethingelse")
    # deliberately not in the exe listing
    row = _rows(case, case / "CSVs")["9100"]
    assert row["flags"] == "exe_unknown"
    assert "comm_mismatch" not in row["flags"]
    assert row["suspicious"] == "", "a gap in the evidence is not a finding"


def test_a_space_separated_cmdline_is_read_too(tmp_path):
    """In /proc the arguments are NUL-separated; collectors differ on whether
    they keep that. Reading only one of the two shapes drops every process on
    whichever hosts used the other collector, silently."""
    lr = tmp_path / "live_response"
    (tmp_path / "[root]" / "etc").mkdir(parents=True)
    (tmp_path / "[root]" / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/sh\n",
                                                        encoding="utf-8")
    _process(lr, "1", argv=["/usr/bin/foo", "--flag", "value"], comm="foo", nul=False)
    _exe_listing(lr, {"1": "/usr/bin/foo"})

    row = _rows(tmp_path, tmp_path / "CSVs")["1"]
    assert row["argv0"] == "/usr/bin/foo"
    assert row["flags"] == ""


def test_no_per_pid_tree_writes_nothing(tmp_path):
    """An acquisition profile that did not collect it is not a host with no
    processes."""
    (tmp_path / "live_response" / "process").mkdir(parents=True)
    out = tmp_path / "CSVs"
    P.run(_ctx(tmp_path, out))
    assert not (out / "proc_identity.csv").exists()
