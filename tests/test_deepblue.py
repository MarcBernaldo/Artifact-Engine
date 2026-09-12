r"""A log DeepBlueCLI could not read must not pass as a log with nothing in it.

DeepBlue.ps1 catches its own `Get-WinEvent` failure, prints the reason with
`Write-Host` -- stdout, not stderr -- and then calls a bare `exit`, which is exit
code 0. The pipeline behind it still runs, so `Export-Csv` writes a three-byte
file. Every signal the caller normally reads says the log was analysed and was
clean, and a header-only DeepBlue table is exactly what a quiet log produces.

MEASURED against the `.evtx` samples that ship with the tool and 200 KB of random
bytes named `.evtx`; the stubs here reproduce what was observed, so these tests
run on a host with no PowerShell at all.

The log that fails this way is not a random one. A truncated or corrupt
Security.evtx is what tampering leaves behind, and "zero rows" reading as "no
attack" is the failure this engine exists not to have.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from artifact_engine.core import toolchain
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.handlers import win_deepblue as D

# What the script prints on stdout before giving up. The second line is the
# operating system's own message and is localised; nothing matches on it.
BAILED = "Get-WinEvent error:  <the OS reason, in the host's language>\n\nExiting...\n"


def _ctx(tmp_path: Path, tool: toolchain.Launch | None = "default") -> ParserContext:
    """A context carrying what `_run_handler` would have resolved for this parser.

    The handler no longer looks the script or the interpreter up: both arrive
    already decided, which is what stops it and `aeng preflight` from reaching
    different conclusions about the same host.
    """
    for d in ("ev/Windows/System32/winevt/Logs", "out", "tools/deepbluecli-master"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    ps1 = tmp_path / "tools/deepbluecli-master/DeepBlue.ps1"
    ps1.write_text("#", encoding="utf-8")
    if tool == "default":
        tool = toolchain.Launch((r"C:\powershell.exe", str(ps1)), "powershell")
    return ParserContext(
        evidence=tmp_path / "ev", out=tmp_path / "out", tools=tmp_path / "tools",
        assets=tmp_path / "tools", machine_name="HOST-01", volume="C",
        log=logging.getLogger("aeng.test"), tool=tool,
    )


def _logs(ctx: ParserContext, *names: str) -> None:
    for n in names:
        (ctx.evidence / "Windows/System32/winevt/Logs" / n).write_bytes(b"ElfFile\x00")


def _stub(monkeypatch, results: dict[str, tuple[int, str]]) -> list[list[str]]:
    """Answer each invocation by which log its command names. Records the argv."""
    seen: list[list[str]] = []

    def fake_run(cmd, timeout=None, cwd=None):
        seen.append(cmd)
        joined = " ".join(cmd)
        for log, (rc, out) in results.items():
            if log in joined:
                # Export-Csv writes its file whether or not the script produced
                # rows, so the stub does too: that is the whole trap.
                target = joined.split("-Path '")[-1].rstrip("'")
                Path(target).write_text("\n", encoding="utf-8")
                return rc, out, ""
        raise AssertionError(f"unexpected invocation: {joined[:120]}")

    monkeypatch.setattr(D.procs, "run", fake_run)
    return seen


# --------------------------------------------------------------------------- #
# The silent bail-out
# --------------------------------------------------------------------------- #
def test_a_log_the_script_gave_up_on_leaves_no_table(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    _logs(ctx, "Security.evtx")
    _stub(monkeypatch, {"Security.evtx": (0, BAILED)})

    with pytest.raises(RuntimeError):          # it was the only log
        D.run(ctx)
    assert not list(ctx.out.glob("*.csv")), (
        "a header-only CSV here is indistinguishable from a log that was read "
        "and held nothing")


def test_exit_zero_and_empty_stderr_are_not_success(tmp_path, monkeypatch, caplog):
    """The exit code alone was the first fix and it is not enough: the script
    exits 0 on the path that matters."""
    ctx = _ctx(tmp_path)
    _logs(ctx, "Security.evtx", "System.evtx")
    _stub(monkeypatch, {"Security.evtx": (0, BAILED), "System.evtx": (0, "")})

    with caplog.at_level(logging.WARNING, logger="aeng.test"):
        D.run(ctx)
    assert any("Security" in r.message for r in caplog.records)


def test_the_logs_that_worked_are_kept(tmp_path, monkeypatch):
    """One unreadable log is not a reason to throw away four good ones."""
    ctx = _ctx(tmp_path)
    _logs(ctx, "Security.evtx", "System.evtx")
    _stub(monkeypatch, {"Security.evtx": (0, BAILED), "System.evtx": (0, "")})

    D.run(ctx)
    assert [p.name for p in ctx.out.glob("*.csv")] == ["DeepBlue-System.csv"]


def test_failing_every_log_is_an_error_not_a_quiet_success(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    _logs(ctx, "Security.evtx", "System.evtx")
    _stub(monkeypatch, {"Security.evtx": (0, BAILED), "System.evtx": (1, "")})

    with pytest.raises(RuntimeError, match="none of the 2"):
        D.run(ctx)


def test_a_nonzero_exit_is_still_a_failure(tmp_path, monkeypatch):
    """The catastrophic cases -- a blocked script, a parse error -- never reach
    the bail-out message at all."""
    ctx = _ctx(tmp_path)
    _logs(ctx, "Security.evtx", "System.evtx")
    _stub(monkeypatch, {"Security.evtx": (1, ""), "System.evtx": (0, "")})

    D.run(ctx)
    assert [p.name for p in ctx.out.glob("*.csv")] == ["DeepBlue-System.csv"]


def test_a_log_that_analysed_cleanly_keeps_its_table(tmp_path, monkeypatch):
    """The counterpart that must not regress: an empty result from a log that WAS
    read is a real answer, and dropping it would be the opposite mistake."""
    ctx = _ctx(tmp_path)
    _logs(ctx, "Security.evtx")
    _stub(monkeypatch, {"Security.evtx": (0, "")})

    D.run(ctx)
    assert [p.name for p in ctx.out.glob("*.csv")] == ["DeepBlue-Security.csv"]


# --------------------------------------------------------------------------- #
# Which host can run it at all
# --------------------------------------------------------------------------- #
def test_a_host_that_cannot_run_it_says_why(tmp_path):
    """An ERROR carrying the reason, not a skip.

    `skipped` is a statement about the MACHINE -- no such artifact here -- and a
    missing or unusable tool is a statement about the INSTALLATION. Counting one
    as the other is how a limited run gets read as a quiet host, which is the
    confusion `aeng preflight` exists to prevent.
    """
    ctx = _ctx(tmp_path, tool=toolchain.Launch(reason="a Windows host is required"))
    _logs(ctx, "Security.evtx")

    with pytest.raises(RuntimeError, match="Windows host"):
        D.run(ctx)


def test_the_interpreter_comes_from_the_toolchain_not_from_here(tmp_path, monkeypatch):
    """`aeng preflight` and this handler have to reach the same verdict about this
    host, which they only do by being handed the same answer."""
    ctx = _ctx(tmp_path)
    _logs(ctx, "Security.evtx")
    seen = _stub(monkeypatch, {"Security.evtx": (0, "")})

    D.run(ctx)
    assert seen[0][0] == r"C:\powershell.exe"
    assert seen[0][1] == "-NoProfile", "the script is not passed as an argv entry"


def test_no_event_logs_at_all_is_a_skip(tmp_path):
    """Rather than a success that produced nothing, which is what an acquisition
    with no `winevt/Logs` used to report."""
    ctx = _ctx(tmp_path)
    with pytest.raises(HandlerSkip):
        D.run(ctx)
