r"""What this installation can run, said before the evidence is touched.

A binary that was never fetched is otherwise discovered by the parser that needed
it, as an error, once per parser and per volume. On a host missing a whole
toolchain -- a fresh install, or a Linux box handed a Windows acquisition -- that
is dozens of identical lines, each true and none of them the point.

The two things these tests hold down: that the answer is a SINGLE statement made
up front, and that it is resolved the same way the runner resolves it. A
preflight that looked somewhere the runner does not would call a tool present and
then watch the parser fail on it, which is worse than not checking at all.
"""
from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from artifact_engine import cli
from artifact_engine.core import extractor as c_extractor
from artifact_engine.core import preflight, report
from artifact_engine.models import ParserManifest, Tool


def _parser(pid: str, binary: str | None) -> ParserManifest:
    if binary is None:
        return ParserManifest(id=pid, os="windows", handler="m:run")
    return ParserManifest(id=pid, os="windows", tool=Tool(binary=binary),
                          command=["{binary}"])


def _exe(stem: str) -> str:
    """A tool name this host could actually execute.

    `MFTECmd.exe` is not runnable on Linux even when the file is sitting right
    there -- which is the point of `toolchain._runs_here` and is tested in
    test_toolchain.py. These tests are about PRESENT versus ABSENT, so they name
    something the host can run and leave that distinction to its own file.
    """
    return f"{stem}.exe" if os.name == "nt" else stem


def _installed(tools: Path, *names: str) -> Path:
    """Installed the way `aeng setup` leaves a tool: on POSIX that includes the
    execute bit, whose absence is its own case in test_toolchain.py."""
    for n in names:
        p = tools / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"MZ")
        if os.name != "nt":
            p.chmod(0o755)
    return tools


# --------------------------------------------------------------------------- #
# Finding a tool, by the runner's rule
# --------------------------------------------------------------------------- #
def test_a_tool_is_looked_for_exactly_where_the_runner_looks(tmp_path):
    r"""`_run_command` does `ctx.tools / parser.tool.binary` and nothing else.

    Pinned as one assertion rather than two similar ones, because the failure
    mode is not either expression being wrong -- it is the two DRIFTING, which no
    test of each alone would notice. When this rule grows a PATH fallback, this
    is the test that says the runner has to grow it in the same commit.
    """
    binary = "chainsaw/chainsaw_x86_64.exe"
    _installed(tmp_path, binary)
    assert preflight.find(binary, tmp_path) == tmp_path / binary


def test_a_tool_that_is_not_there_is_not_found(tmp_path):
    assert preflight.find("AmcacheParser.exe", tmp_path) is None


def test_a_directory_with_the_binarys_name_is_not_the_binary(tmp_path):
    (tmp_path / "AmcacheParser.exe").mkdir()
    assert preflight.find("AmcacheParser.exe", tmp_path) is None


def test_the_reported_name_drops_the_subdirectory_a_manifest_declares(tmp_path):
    from artifact_engine.core import toolchain

    check = preflight.ToolCheck(binary="chainsaw/chainsaw_x86_64.exe",
                                launch=toolchain.Launch(reason="nope"),
                                parsers=("chainsaw_sigma",))
    assert check.name == "chainsaw_x86_64.exe"


# --------------------------------------------------------------------------- #
# Grouping, because seventeen parsers share one download
# --------------------------------------------------------------------------- #
def test_one_binary_shared_by_many_parsers_is_one_line(tmp_path):
    """EvtxECmd is one download and seventeen parsers. Seventeen lines saying so
    is a report nobody reads to the end."""
    parsers = [_parser(f"evtx_{i}", "EvtxECmd/EvtxECmd.exe") for i in range(17)]
    checks = preflight.check(parsers, tmp_path)
    assert len(checks) == 1
    assert len(checks[0].parsers) == 17
    assert len(preflight.blocked(checks)) == 17


def test_a_python_handler_needs_no_binary_and_is_never_blocked(tmp_path):
    checks = preflight.check([_parser("ransomware", None)], tmp_path)
    assert checks == []
    assert preflight.blocked(checks) == set()


def test_present_and_absent_are_told_apart(tmp_path):
    here, absent = _exe("AmcacheParser"), _exe("MFTECmd")
    _installed(tmp_path, here)
    checks = preflight.check(
        [_parser("amcache", here), _parser("mft", absent)], tmp_path)
    got = {c.binary: c.present for c in checks}
    assert got == {here: True, absent: False}
    assert preflight.blocked(checks) == {"mft"}


# --------------------------------------------------------------------------- #
# Saying it
# --------------------------------------------------------------------------- #
def test_nothing_is_said_when_every_tool_is_present(tmp_path):
    """A warning that fires on the ordinary case stops being read."""
    here = _exe("AmcacheParser")
    _installed(tmp_path, here)
    checks = preflight.check([_parser("amcache", here)], tmp_path)
    assert preflight.describe(checks, 1) == []


def test_the_report_counts_the_parsers_not_just_the_tools(tmp_path):
    """"2 tools missing" is not the number that matters to an analyst; "31 of the
    113 parsers cannot run" is."""
    parsers = ([_parser(f"evtx_{i}", "EvtxECmd/EvtxECmd.exe") for i in range(17)]
               + [_parser("mft", "MFTECmd.exe")])
    lines = preflight.describe(preflight.check(parsers, tmp_path), 40)
    assert "2 external tool(s) cannot be run here" in lines[0]
    assert "18 of 40 parser(s) cannot run" in lines[0]


def test_the_report_says_this_is_a_limit_and_not_an_error(tmp_path):
    """Nothing here is a mandatory tool: the parsers that CAN run still run, and
    a triage of the reachable artifacts is worth having. What it must not read as
    is a clean bill of health."""
    lines = preflight.describe(preflight.check([_parser("mft", "MFTECmd.exe")], tmp_path), 1)
    joined = " ".join(lines)
    assert "not" in joined and "error" in joined
    assert "aeng setup" in joined


def test_the_report_does_not_promise_a_blocked_parser_is_left_alone(tmp_path):
    """It said "They will not be tried". MEASURED on Kali: they were, and ended as
    errors with the run exiting 2 -- the design, and the opposite of that line."""
    lines = preflight.describe(preflight.check([_parser("mft", "MFTECmd.exe")], tmp_path), 1)
    joined = " ".join(lines)

    assert "will not be tried" not in joined
    assert "reported as an error, not a skip" in joined


def test_a_blocked_parser_whose_artifact_is_present_ends_as_an_error(tmp_path):
    """The behaviour the report above describes, pinned where it happens."""
    from artifact_engine.core.runner import ParserContext, run_parser

    evidence = tmp_path / "ev"
    evidence.mkdir()
    (evidence / "$MFT").write_bytes(b"FILE0")
    parser = ParserManifest(id="mft", os="windows", tool=Tool(binary="MFTECmd.exe"),
                            command=["{binary}"], requires=["$MFT"])
    ctx = ParserContext(evidence=evidence, out=tmp_path / "out", tools=tmp_path / "tools",
                        assets=tmp_path, machine_name="HOST-01", volume="C", log=None)

    run = run_parser(parser, ctx)

    assert run.status == "error"
    assert "not installed" in run.detail


def test_the_summary_names_the_blocked_parsers_for_the_json(tmp_path):
    parsers = [_parser("mft", "MFTECmd.exe"), _parser("usn", "MFTECmd.exe")]
    s = preflight.summary(preflight.check(parsers, tmp_path), 2)
    assert s["tools_missing"] == 1
    assert s["parsers_blocked"] == ["mft", "usn"]
    assert s["missing"][0]["binary"] == "MFTECmd.exe"


# --------------------------------------------------------------------------- #
# The command, and the run
# --------------------------------------------------------------------------- #
def test_the_command_exits_three_when_something_is_missing(tmp_path, monkeypatch):
    """3, not 1 or 2: nothing was processed. A deployment check wants to tell
    "this host is not set up" from "this case had errors"."""
    from artifact_engine import cli as c

    monkeypatch.setattr(c, "load_parsers", lambda dirs: [_parser("mft", "MFTECmd.exe")])
    cfg = c.load_config()
    monkeypatch.setattr(cfg, "tools_dir", tmp_path, raising=False)
    monkeypatch.setattr(c, "load_config", lambda p=None: cfg)

    rc = c.cmd_preflight(argparse.Namespace(config=None))
    assert rc == c.EXIT_CONFIG == 3


def _have_archiver(monkeypatch, present: bool) -> None:
    """Pin whether this host has a 7-Zip binary.

    Without this the test below passes on the development machine and fails on a
    Linux box that has no `p7zip` -- the exit code genuinely depends on it since
    v0.7.46, and a test that reads the host it runs on is a test that says
    different things on the two platforms this engine targets.
    """
    monkeypatch.setattr(c_extractor, "find_7z",
                        lambda tools_dir=None: Path("7z") if present else None)


def test_the_command_exits_zero_when_everything_is_there(tmp_path, monkeypatch):
    from artifact_engine import cli as c

    here = _exe("MFTECmd")
    _installed(tmp_path, here)
    monkeypatch.setattr(c, "load_parsers", lambda dirs: [_parser("mft", here)])
    cfg = c.load_config()
    monkeypatch.setattr(cfg, "tools_dir", tmp_path, raising=False)
    monkeypatch.setattr(c, "load_config", lambda p=None: cfg)
    _have_archiver(monkeypatch, True)

    assert c.cmd_preflight(argparse.Namespace(config=None)) == 0


def test_a_missing_archiver_alone_is_enough_to_refuse(tmp_path, monkeypatch):
    """Every parser tool present and the command still exits 3.

    It is the one absence that costs a WHOLE acquisition rather than one parser's
    table -- measured: four of eleven, on a host without it -- so a deployment
    check that passed on it would be telling the operator the box is ready to
    read archives it cannot open.
    """
    from artifact_engine import cli as c

    here = _exe("MFTECmd")
    _installed(tmp_path, here)
    monkeypatch.setattr(c, "load_parsers", lambda dirs: [_parser("mft", here)])
    cfg = c.load_config()
    monkeypatch.setattr(cfg, "tools_dir", tmp_path, raising=False)
    monkeypatch.setattr(c, "load_config", lambda p=None: cfg)
    _have_archiver(monkeypatch, False)

    assert c.cmd_preflight(argparse.Namespace(config=None)) == c.EXIT_CONFIG


def test_the_archiver_is_named_with_the_package_to_install(tmp_path, monkeypatch, caplog):
    from artifact_engine import cli as c

    monkeypatch.setattr(c, "load_parsers", lambda dirs: [_parser("py", None)])
    cfg = c.load_config()
    monkeypatch.setattr(cfg, "tools_dir", tmp_path, raising=False)
    monkeypatch.setattr(c, "load_config", lambda p=None: cfg)
    _have_archiver(monkeypatch, False)

    with caplog.at_level(logging.WARNING, logger="aeng"):
        c.cmd_preflight(argparse.Namespace(config=None))
    said = " ".join(r.message for r in caplog.records)
    assert "7-Zip" in said
    assert ("p7zip" in said) or ("drop 7z.exe" in said), "say what to install, not just what is missing"


def test_a_run_never_aborts_on_a_missing_tool(tmp_path, monkeypatch, caplog):
    """`aeng preflight` refuses; `aeng run` reports and carries on.

    Nothing here is a mandatory tool: the parsers that CAN run are still worth
    running, and a case half-triaged beats a case not triaged because one binary
    was absent. What the run must not do is stay quiet about it.
    """
    captured: dict = {}

    def fake_summary(root, results, incomplete=None, tools=None, started_at=None,
                     waiting=None):
        captured["tools"] = tools
        return {"machines": 0, "per_machine": [], "status": "complete",
                "totals": {"ok": 0, "cached": 0, "skipped": 0, "errors": 0}}

    monkeypatch.setattr(report, "build_run_summary", fake_summary)
    # A case with nothing in it selects no parsers, so the gap has to be injected
    # to be observed at all -- the point under test is what `cmd_run` DOES with
    # one, not whether this empty directory produces one.
    from artifact_engine.core import toolchain

    missing = [preflight.ToolCheck("MFTECmd.exe",
                                   toolchain.Launch(reason="not installed"),
                                   ("mft", "usn"))]
    monkeypatch.setattr(cli.preflight, "check", lambda parsers, tools_dir: missing)

    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)
    with caplog.at_level(logging.WARNING, logger="aeng"):
        rc = cli.cmd_run(args)

    assert rc == 0, "a missing tool is a limit, not a failure to start"
    assert any("cannot run on this host" in r.message for r in caplog.records)
    assert captured["tools"]["parsers_blocked"] == ["mft", "usn"]


def test_the_run_summary_carries_what_could_not_be_tried(tmp_path):
    """`skipped` is about the MACHINE -- this host has no such artifact. A tool
    that is not installed is about the INSTALLATION. Reading one as the other is
    how a limited run gets mistaken for a quiet host, so they are separate keys.
    """
    tools = preflight.summary(
        preflight.check([_parser("mft", "MFTECmd.exe")], tmp_path), 1)
    summary = report.build_run_summary(tmp_path, [], incomplete=None, tools=tools)

    assert summary["tools"]["parsers_blocked"] == ["mft"]
    text = (tmp_path / "run-summary.txt").read_text(encoding="utf-8")
    assert "External tools NOT installed: 1" in text
    assert "MFTECmd.exe" in text


def test_a_run_with_every_tool_present_says_nothing_about_tools(tmp_path):
    summary = report.build_run_summary(
        tmp_path, [], incomplete=None,
        tools=preflight.summary(preflight.check([], tmp_path), 0))
    text = (tmp_path / "run-summary.txt").read_text(encoding="utf-8")
    assert "External tools NOT installed" not in text
    assert summary["tools"]["tools_missing"] == 0


def test_the_installed_parsers_all_declare_a_findable_binary_shape():
    """Over the real manifests: every declared binary is a relative path with no
    drive letter, no leading slash and no backslash -- so `tools_dir / binary`
    means the same thing on both platforms."""
    from artifact_engine.registry import load_parsers

    cfg = cli.load_config()
    logging.getLogger("aeng").addHandler(logging.NullHandler())
    for p in load_parsers(cfg.all_parser_dirs):
        if not (p.tool and p.tool.binary):
            continue
        b = p.tool.binary
        assert "\\" not in b, f"{p.id}: backslash in {b!r}"
        assert not b.startswith("/"), f"{p.id}: absolute {b!r}"
        assert ":" not in b, f"{p.id}: drive letter in {b!r}"
        assert ".." not in Path(b).parts, f"{p.id}: parent reference in {b!r}"


# --------------------------------------------------------------------------- #
# A tool that is present and still cannot be started
# --------------------------------------------------------------------------- #
def test_a_script_whose_interpreter_is_missing_is_reported_with_that_reason(
        tmp_path, monkeypatch):
    """DeepBlueCLI is on disk on every platform -- it is a text file in a zip.

    So "is the file there" answers yes on a Linux host that cannot run a line of
    it, and the analyst is told the tool is ready and then sees the parser fail.
    What preflight has to print is the reason, which only the resolver knows.
    """
    from artifact_engine.core import toolchain

    monkeypatch.setattr(toolchain, "powershell",
                        lambda posix=None: toolchain.Launch(reason="no interpreter here"))
    _installed(tmp_path, "deepbluecli-master/DeepBlue.ps1")
    checks = preflight.check([_parser("deepblue", "deepbluecli-master/DeepBlue.ps1")],
                             tmp_path)
    assert [c.present for c in checks] == [False]
    assert checks[0].launch.reason == "no interpreter here"
    assert preflight.blocked(checks) == {"deepblue"}
    assert preflight.summary(checks, 1)["missing"][0]["reason"] == "no interpreter here"


def test_the_console_names_the_script_not_the_folder_it_sits_in(tmp_path, monkeypatch):
    """The manifest declares a subdirectory; `deepbluecli-master/DeepBlue.ps1` in
    a narrow column pushes the parser list off the screen."""
    from artifact_engine.core import toolchain

    monkeypatch.setattr(toolchain, "powershell",
                        lambda posix=None: toolchain.Launch(reason="no interpreter here"))
    _installed(tmp_path, "deepbluecli-master/DeepBlue.ps1")
    checks = preflight.check([_parser("deepblue", "deepbluecli-master/DeepBlue.ps1")],
                             tmp_path)
    assert checks[0].name == "DeepBlue.ps1"
    assert any("DeepBlue.ps1" in ln for ln in preflight.describe(checks, 1))


def test_one_missing_runtime_is_one_line_not_one_line_per_tool():
    """Seventeen EZ tools wait on a single .NET runtime.

    Every reason carries the binary's own name, so deduplicating the strings
    deduplicated nothing and the block printed seventeen near-identical lines --
    the exact repetition it was written to replace. What the analyst has to read
    is the ACTION, and there is one.
    """
    from artifact_engine.core import toolchain

    checks = [preflight.ToolCheck(
        binary=f"{stem}.exe",
        launch=toolchain.Launch(reason=(f"{stem}.exe is a .NET application and `dotnet` "
                                        f"is not on PATH (install the .NET 9 runtime)")),
        parsers=(stem.lower(),))
        for stem in ("AmcacheParser", "MFTECmd", "EvtxECmd", "RECmd")]
    reasons = [ln for ln in preflight.describe(checks, 40) if "dotnet" in ln]
    assert len(reasons) == 1
    assert "4 of them" in reasons[0]


def test_two_different_absences_are_two_different_lines():
    """A tool that was never downloaded, a runtime that is not installed and a
    tool this host can never run are three different things to do about it."""
    from artifact_engine.core import toolchain

    checks = [
        preflight.ToolCheck("MFTECmd.exe", toolchain.Launch(
            reason="MFTECmd.exe is a .NET application and `dotnet` is not on PATH"),
            ("mft",)),
        preflight.ToolCheck("deepbluecli-master/DeepBlue.ps1", toolchain.Launch(
            reason="a Windows host is required -- Get-WinEvent"), ("deepblue",)),
        preflight.ToolCheck("nowhere.exe", toolchain.Launch(
            reason="nowhere.exe is not installed (run `aeng setup`)"), ("nope",)),
    ]
    lines = preflight.describe(checks, 40)
    # Reason lines are indented 4; the per-tool rows above them are indented 8.
    assert sum(1 for ln in lines
               if ln.startswith("    ") and not ln.startswith("        ")
               and ": " in ln) == 2
    # The ordinary case is not repeated: the header already says `aeng setup`.
    assert not any("nowhere.exe: " in ln for ln in lines)


def test_the_header_does_not_promise_setup_can_fix_all_of_them():
    """`aeng setup` already downloaded DeepBlueCLI. Telling a Linux analyst to
    run it again sends them after the one action that cannot help."""
    from artifact_engine.core import toolchain

    checks = [preflight.ToolCheck("deepbluecli-master/DeepBlue.ps1", toolchain.Launch(
        reason="a Windows host is required -- Get-WinEvent"), ("deepblue",))]
    head = " ".join(preflight.describe(checks, 40)[:4])
    assert "fetches them" not in head
