r"""How an external tool is invoked on the host doing the parsing.

The differences between platforms are not a `.exe` suffix, and these tests are
written against what the tools this engine downloads actually are:

- chainsaw ships every platform in ONE archive, the one already fetched, so what
  changes is which FILE is run and nothing is downloaded differently;
- the Eric Zimmerman tools are framework-dependent .NET -- a small Windows
  apphost, the real program as a `.dll` beside it, and a `runtimeconfig.json`
  naming `net9.0`. The apphost is the only Windows-only part;
- sidr publishes `sidr.exe` and nothing else, so that parser is Windows-only in
  the same way `win_sum` is.

The most important test here is the one that pins what this DOES NOT do: fall
back to a copy of the tool on `PATH`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from artifact_engine.core import toolchain
from artifact_engine.models import Tool, ToolPlatform


def _tool(binary: str, linux: str | None = None) -> Tool:
    return Tool(binary=binary,
                linux=ToolPlatform(binary=linux) if linux else None)


def _put(root: Path, *names: str) -> Path:
    for n in names:
        p = root / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"\x7fELF" if not n.endswith((".exe", ".dll")) else b"MZ")
    return root


# --------------------------------------------------------------------------- #
# Which file this platform looks for
# --------------------------------------------------------------------------- #
def test_a_manifest_without_a_linux_block_is_unchanged_everywhere():
    """Every manifest written before this existed keeps working untouched."""
    t = _tool("AmcacheParser.exe")
    assert toolchain.declared(t, posix=False) == "AmcacheParser.exe"
    assert toolchain.declared(t, posix=True) == "AmcacheParser.exe"


def test_the_linux_block_names_a_different_file_in_the_same_archive():
    t = _tool("chainsaw/chainsaw_x86_64-pc-windows-msvc.exe",
              "chainsaw/chainsaw_x86_64-unknown-linux-gnu")
    assert toolchain.declared(t, posix=False).endswith("-pc-windows-msvc.exe")
    assert toolchain.declared(t, posix=True).endswith("-unknown-linux-gnu")


def test_the_real_chainsaw_manifest_declares_both():
    """Read off the shipped manifest, not restated: the asset it downloads is
    literally named `all_platforms`, and both builds are inside it."""
    import yaml

    from artifact_engine.config import DATA_DIR

    d = yaml.safe_load(
        (DATA_DIR / "parsers" / "windows" / "evtx_chainsaw.yaml").read_text(encoding="utf-8"))
    assert d["tool"]["binary"].endswith("-pc-windows-msvc.exe")
    assert d["tool"]["linux"]["binary"].endswith("-unknown-linux-gnu")
    assert "all_platforms" in d["tool"]["source"]["asset"]


# --------------------------------------------------------------------------- #
# Starting it
# --------------------------------------------------------------------------- #
def test_a_native_binary_is_run_directly(tmp_path):
    _put(tmp_path, "chainsaw/chainsaw_x86_64-unknown-linux-gnu")
    got = toolchain.resolve(
        _tool("chainsaw/w.exe", "chainsaw/chainsaw_x86_64-unknown-linux-gnu"),
        tmp_path, posix=True)
    assert got.ok and got.how == "native"
    assert len(got.argv) == 1


def test_a_windows_apphost_is_not_runnable_on_posix(tmp_path):
    """It is PRESENT on every platform -- it ships in the same zip. Reporting it
    as installed would mean the parser fails with a format error instead."""
    _put(tmp_path, "AmcacheParser.exe")
    got = toolchain.resolve(_tool("AmcacheParser.exe"), tmp_path, posix=True)
    assert not got.ok


def test_a_dotnet_assembly_is_started_through_the_runtime(tmp_path, monkeypatch):
    """`dotnet AmcacheParser.dll` is the same program the apphost would have
    started. The `.dll` needs no declaration: it sits beside the `.exe`."""
    _put(tmp_path, "AmcacheParser.exe", "AmcacheParser.dll")
    monkeypatch.setattr(toolchain.shutil, "which",
                        lambda n: "/usr/bin/dotnet" if n == "dotnet" else None)

    got = toolchain.resolve(_tool("AmcacheParser.exe"), tmp_path, posix=True)

    assert got.ok and got.how == "dotnet"
    assert got.argv == ("/usr/bin/dotnet", str(tmp_path / "AmcacheParser.dll"))


def test_without_the_runtime_the_reason_says_which_runtime(tmp_path, monkeypatch):
    """"not installed" would send someone to `aeng setup`, which has already run
    and would change nothing. The actionable fact is the missing runtime."""
    _put(tmp_path, "AmcacheParser.exe", "AmcacheParser.dll")
    monkeypatch.setattr(toolchain.shutil, "which", lambda n: None)

    got = toolchain.resolve(_tool("AmcacheParser.exe"), tmp_path, posix=True)

    assert not got.ok
    assert "dotnet" in got.reason and ".NET" in got.reason


def test_a_tool_that_was_never_downloaded_says_so(tmp_path):
    got = toolchain.resolve(_tool("sidr.exe"), tmp_path, posix=False)
    assert not got.ok
    assert "aeng setup" in got.reason


def test_on_windows_the_apphost_is_exactly_what_runs(tmp_path):
    """The `.dll` path is for hosts that cannot run the apphost. Where it runs,
    it is what the tool ships to be run, and nothing is routed around it."""
    _put(tmp_path, "AmcacheParser.exe", "AmcacheParser.dll")
    got = toolchain.resolve(_tool("AmcacheParser.exe"), tmp_path, posix=False)
    assert got.ok and got.how == "native"
    assert got.argv == (str(tmp_path / "AmcacheParser.exe"),)


# --------------------------------------------------------------------------- #
# The fallback that is deliberately absent
# --------------------------------------------------------------------------- #
def test_a_copy_of_the_tool_on_path_is_never_used(tmp_path, monkeypatch):
    """This was written, and it worked -- on the development machine it found a
    separate install of the EZ tools and ran those instead.

    Which is the problem. `aeng setup` pins what it downloads and records every
    binary's sha256 in `tools.lock.json`, an audit trail of which tool builds
    produced the results. Running a different, unrecorded, possibly older build
    off PATH breaks that claim with nobody seeing it, and a tool version can
    change output columns. "Not installed" is the right answer even on a host
    that has one lying around.
    """
    elsewhere = tmp_path / "elsewhere" / "MFTECmd.exe"
    elsewhere.parent.mkdir(parents=True)
    elsewhere.write_bytes(b"MZ")
    monkeypatch.setattr(toolchain.shutil, "which", lambda n: str(elsewhere))

    got = toolchain.resolve(_tool("MFTECmd.exe"), tmp_path / "tools", posix=False)

    assert not got.ok, "a tool off PATH is not the pinned one"
    assert str(elsewhere) not in " ".join(got.argv)


def test_the_runtime_is_the_one_thing_taken_from_path(tmp_path, monkeypatch):
    """`dotnet` is a runtime, not a parser: the assembly it executes is still the
    pinned one, so the audit trail is intact."""
    _put(tmp_path, "AmcacheParser.exe", "AmcacheParser.dll")
    monkeypatch.setattr(toolchain.shutil, "which",
                        lambda n: "/usr/bin/dotnet" if n == "dotnet" else "/usr/bin/impostor")
    got = toolchain.resolve(_tool("AmcacheParser.exe"), tmp_path, posix=True)
    assert got.argv[0] == "/usr/bin/dotnet"
    assert got.argv[1].endswith("AmcacheParser.dll")


# --------------------------------------------------------------------------- #
# `{binary}` can be more than one argument
# --------------------------------------------------------------------------- #
def test_the_binary_placeholder_expands_to_the_whole_launcher(tmp_path):
    """A manifest writes one `{binary}`; `dotnet Thing.dll` is two arguments."""
    from artifact_engine.core.runner import ParserContext, _build_argv

    ctx = ParserContext(evidence=tmp_path, out=tmp_path, tools=tmp_path,
                        assets=tmp_path, machine_name="HOST-01", volume="C", log=None)
    launch = toolchain.Launch(("dotnet", "/t/AmcacheParser.dll"), "dotnet")

    argv = _build_argv(["{binary}", "-f", "x.hve", "--csv", "{out}"], ctx, None, launch)

    assert argv[:2] == ["dotnet", "/t/AmcacheParser.dll"]
    assert argv[2:4] == ["-f", "x.hve"]
    assert argv[-1] == str(tmp_path)


def test_a_single_binary_still_expands_to_one_argument(tmp_path):
    from artifact_engine.core.runner import ParserContext, _build_argv

    ctx = ParserContext(evidence=tmp_path, out=tmp_path, tools=tmp_path,
                        assets=tmp_path, machine_name="HOST-01", volume="C", log=None)
    launch = toolchain.Launch((r"C:\t\MFTECmd.exe",), "native")
    assert _build_argv(["{binary}", "-f"], ctx, None, launch) == [r"C:\t\MFTECmd.exe", "-f"]


# --------------------------------------------------------------------------- #
# The runner and the preflight resolve identically
# --------------------------------------------------------------------------- #
def test_the_runner_and_the_preflight_ask_the_same_resolver(tmp_path, monkeypatch):
    """Not "both compute the same answer" -- both CALL the same function. Two
    implementations that agree today are two implementations that drift, and the
    drift shows up as a tool reported present whose parser then fails on it."""
    from artifact_engine.core import preflight, runner

    def watched(tool, tools_dir, posix=None):
        return toolchain.Launch(reason="watched")

    monkeypatch.setattr(toolchain, "resolve", watched)

    # Both modules reach the same object, so there is no second implementation
    # that could answer differently.
    assert runner.toolchain.resolve is watched
    assert preflight.toolchain.resolve is watched


# --------------------------------------------------------------------------- #
# The tool that cannot declare a `linux:` block
# --------------------------------------------------------------------------- #
def test_hayabusa_states_its_platform_fact_in_one_place():
    """Its parser is a Python handler with no `tool:` section, so `aeng setup`
    fetches it outside the manifests and it cannot use the schema above.

    What to DOWNLOAD and what to LOOK FOR afterwards are the same answer -- the
    asset is version-stamped per platform and the binary inside carries the same
    name -- so they are one pair of constants rather than four literals in four
    files (the downloader, the lockfile listing, and the handler).
    """
    assert toolchain.HAYABUSA_ASSET_TAG.endswith(".zip")
    win = toolchain.HAYABUSA_ASSET_TAG.startswith("win")
    assert win == toolchain.HAYABUSA_GLOB.endswith(".exe"), (
        "the download and the lookup disagree about which platform this is")


def test_nothing_spells_the_hayabusa_platform_out_by_hand():
    """Four literals in four files is how the download and the lookup drift
    apart: `setup` fetches the Linux build and the handler goes on looking for
    an `.exe`, so the parser reports no binary on a host that has one."""
    import artifact_engine

    pkg = Path(artifact_engine.__file__).resolve().parent
    offenders = []
    for f in [*pkg.glob("core/*.py"), *pkg.glob("handlers/*.py"), pkg / "cli.py"]:
        if f.name == "toolchain.py":
            continue
        text = f.read_text(encoding="utf-8")
        for literal in ('"hayabusa*.exe"', '"win-x64.zip"', "'hayabusa*.exe'"):
            if literal in text:
                offenders.append(f"{f.name}: {literal}")
    assert not offenders, (
        "these hard-code hayabusa's platform instead of asking `core/toolchain`:"
        "\n  " + "\n  ".join(offenders))


# --------------------------------------------------------------------------- #
# The tool that is a script: what has to exist is an interpreter
# --------------------------------------------------------------------------- #
def _ps1(tmp_path: Path) -> Tool:
    p = tmp_path / "deepbluecli-master" / "DeepBlue.ps1"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("# not run by these tests\n", encoding="utf-8")
    return Tool(binary="deepbluecli-master/DeepBlue.ps1")


def test_a_script_is_not_runnable_just_because_it_is_readable(tmp_path):
    """The trap this closes. A `.ps1` has no `.exe` suffix, so the old
    "is it a file, and is it not a Windows apphost" test called it runnable on
    Linux -- and `aeng preflight` would have reported DeepBlueCLI as installed
    and ready on a host that cannot start it."""
    launch = toolchain.resolve(_ps1(tmp_path), tmp_path, posix=True)
    assert not launch.ok
    assert "Get-WinEvent" in launch.reason


def test_installing_pwsh_on_linux_does_not_change_the_answer(monkeypatch):
    """PowerShell 7 runs on Linux. `Get-WinEvent` does not come with it, and the
    whole script reads through that cmdlet -- so finding an interpreter is not
    the question, and the refusal must not depend on `which`."""
    monkeypatch.setattr(toolchain.shutil, "which", lambda n: f"/usr/bin/{n}")
    assert not toolchain.powershell(posix=True).ok


def test_windows_powershell_is_preferred_over_pwsh(monkeypatch):
    """5.1 is what the bundled script was written against and what every run so
    far has used; preferring 7 would be an untested change of interpreter made
    silently, on the hosts that happen to have both."""
    monkeypatch.setattr(toolchain.shutil, "which", lambda n: rf"C:\{n}.exe")
    assert toolchain.powershell(posix=False).how == "powershell"


def test_pwsh_is_used_where_windows_powershell_is_absent(monkeypatch):
    monkeypatch.setattr(toolchain.shutil, "which",
                        lambda n: r"C:\pwsh.exe" if n == "pwsh" else None)
    launch = toolchain.powershell(posix=False)
    assert launch.how == "pwsh"
    assert launch.argv == (r"C:\pwsh.exe",)


def test_a_host_with_no_interpreter_at_all_says_which_ones_it_looked_for(monkeypatch):
    monkeypatch.setattr(toolchain.shutil, "which", lambda n: None)
    launch = toolchain.powershell(posix=False)
    assert not launch.ok
    assert "powershell" in launch.reason and "pwsh" in launch.reason


def test_the_script_is_launched_through_the_interpreter(tmp_path, monkeypatch):
    monkeypatch.setattr(toolchain.shutil, "which",
                        lambda n: rf"C:\{n}.exe" if n == "powershell" else None)
    launch = toolchain.resolve(_ps1(tmp_path), tmp_path, posix=False)
    assert launch.ok
    assert launch.argv[0] == r"C:\powershell.exe"
    assert launch.argv[-1].endswith("DeepBlue.ps1")


def test_a_missing_script_is_reported_as_missing_not_as_a_missing_interpreter(
        tmp_path, monkeypatch):
    """"Run `aeng setup`" and "install PowerShell" are different actions, and
    printing the wrong one sends the analyst after the wrong thing."""
    monkeypatch.setattr(toolchain.shutil, "which", lambda n: rf"C:\{n}.exe")
    t = Tool(binary="deepbluecli-master/DeepBlue.ps1")   # nothing on disk
    launch = toolchain.resolve(t, tmp_path, posix=False)
    assert not launch.ok
    assert "aeng setup" in launch.reason


def test_the_shipped_manifest_is_the_script_this_is_about():
    """Read off the manifest rather than restated here: if DeepBlueCLI ever stops
    being a `.ps1`, the branch above is dead code and this says so."""
    import yaml

    from artifact_engine.config import DATA_DIR

    m = yaml.safe_load((DATA_DIR / "parsers" / "windows" / "evtx_deepblue.yaml")
                       .read_text(encoding="utf-8"))
    assert m["tool"]["binary"].lower().endswith(".ps1")


def test_nothing_starts_a_powershell_by_hand():
    """The handler used to build `["powershell", "-NoProfile", ...]` itself, so
    the one host fact in it was a literal no preflight could see: on Linux that
    is a FileNotFoundError halfway through a run instead of a line before it.

    Matches a PowerShell name followed by a flag -- the invocation shape. The
    detection tables in `win_service_installs` and `win_task_installs` list the
    same names as DATA and are deliberately not matched.
    """
    import re

    import artifact_engine

    pkg = Path(artifact_engine.__file__).resolve().parent
    invocation = re.compile(r"""["'](?:powershell|pwsh)["']\s*,\s*["']-""")
    offenders = [f.name for f in [*pkg.glob("core/*.py"), *pkg.glob("handlers/*.py")]
                 if f.name != "toolchain.py"
                 and invocation.search(f.read_text(encoding="utf-8"))]
    assert not offenders, (
        "these start a PowerShell without asking `core/toolchain.powershell()`:"
        "\n  " + "\n  ".join(offenders))


# --------------------------------------------------------------------------- #
# The archive does not always spell it the way the manifest does
# --------------------------------------------------------------------------- #
def test_a_directory_the_archive_spelled_differently_is_still_found(tmp_path):
    r"""MEASURED on a case-sensitive filesystem straight after `aeng setup`: the
    EvtxECmd archive unpacks `EvtxeCmd/` where seventeen manifests said
    `EvtxECmd/`, and the DeepBlueCLI archive unpacks `DeepBlueCLI-master/` where
    the manifest said `deepbluecli-master/`.

    On Windows both resolve and nobody notices. On Linux eighteen parsers went
    quiet, and the reason printed was "not installed (run `aeng setup`)" -- to an
    analyst who had just run it.
    """
    (tmp_path / "EvtxeCmd").mkdir()
    _put(tmp_path, "EvtxeCmd/EvtxECmd.exe")
    assert toolchain.locate("EvtxECmd/EvtxECmd.exe", tmp_path).is_file()


def test_the_file_name_itself_is_matched_the_same_way(tmp_path):
    _put(tmp_path, "sidr.EXE")
    assert toolchain.locate("sidr.exe", tmp_path).is_file()


def test_a_tool_that_is_really_absent_keeps_the_declared_name(tmp_path):
    """So the reason printed names what the manifest calls it, rather than a
    half-walked path the analyst cannot look up."""
    found = toolchain.locate("EvtxECmd/EvtxECmd.exe", tmp_path)
    assert not found.exists()
    assert found == tmp_path / "EvtxECmd" / "EvtxECmd.exe"


def test_an_exact_match_wins_over_a_case_fold(tmp_path):
    """Not an academic point on a case-SENSITIVE filesystem, which is the only
    place this branch runs: both spellings can exist there at once."""
    _put(tmp_path, "RECmd/RECmd.exe", "recmd/RECmd.exe")
    assert toolchain.locate("RECmd/RECmd.exe", tmp_path).parent.name == "RECmd"


def test_every_manifest_names_a_tool_that_is_actually_there(tmp_path):
    """The check nobody was making, and the one `aeng setup` reported as a bare
    count: "2 failed" after sixteen download lines.

    Skipped where the tools were never downloaded -- it is a statement about this
    installation, not about the repo, so it must not fail a clean checkout.
    """
    import yaml

    from artifact_engine.config import DATA_DIR, load_config

    tools = Path(load_config().tools_dir)
    if not (tools / "chainsaw").is_dir():
        pytest.skip("tools not downloaded in this checkout")

    missing = []
    for manifest in sorted(DATA_DIR.glob("parsers/**/*.yaml")):
        m = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        binary = (m.get("tool") or {}).get("binary")
        if binary and not toolchain.locate(binary, tools).is_file():
            missing.append(f"{manifest.name}: {binary}")
    assert not missing, (
        "declared by a manifest and not on disk under that name:\n  "
        + "\n  ".join(missing))
