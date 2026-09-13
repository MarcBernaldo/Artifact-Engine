r"""How to invoke an external tool on the host doing the parsing.

The manifests name a file: `AmcacheParser.exe`,
`chainsaw/chainsaw_x86_64-pc-windows-msvc.exe`. That was never a portability
problem worth solving while the engine ran in one place, and it is not solved by
appending `.exe` conditionally either -- the differences are not a suffix:

MEASURED, from the tools this engine actually downloads.

- **chainsaw** ships every platform in ONE archive, the one already fetched:
  `chainsaw_x86_64-unknown-linux-gnu` sits beside the `-pc-windows-msvc.exe`.
  Nothing needs downloading differently; a different FILE in it has to be run.
- **The Eric Zimmerman tools are framework-dependent .NET**, not self-contained
  Windows binaries. Each ships a small apphost (`AmcacheParser.exe`, ~340 KB), the
  actual program as IL (`AmcacheParser.dll`, ~2.4 MB) and a
  `runtimeconfig.json` declaring `net9.0` / `Microsoft.NETCore.App 9.0.0`. The
  `.exe` is the part that only runs on Windows. `dotnet AmcacheParser.dll` is the
  same program, and that is how they are launched where the apphost cannot run.
- **sidr publishes `sidr.exe` and nothing else.** No Linux build exists, so
  `search_index` is Windows-only in the same way `win_sum` is: a row in the
  coverage table, not a bug to fix.
- **DeepBlueCLI is a `.ps1`, so what has to exist is an interpreter, not a file.**
  PowerShell 7 runs on Linux, which makes this look portable and it is not:
  `Get-WinEvent`, the cmdlet the whole script reads through, ships only on
  Windows. See `powershell()` -- the refusal is deliberate, not a missing case.

WHAT THIS DOES NOT CLAIM. That an EZ tool RUNS correctly on Linux is not
established by any of the above -- a portable assembly can still call a Windows
API or assume a drive letter, and the development machine has no .NET runtime
to try it on.

WHAT IT DOES CHECK, because a clean Linux host showed why it must: `dotnet` on
PATH is not the runtime the assembly asks for. MEASURED on a Kali with only
.NET 6.0.8 installed: `dotnet EvtxECmd.dll` exits 150 with "You must install or
update .NET to run this application", because every EZ tool's
`runtimeconfig.json` asks for `Microsoft.NETCore.App 9.0.0` -- and `aeng
preflight` had called all 36 of those parsers runnable on that host (35, plus
`sum`, which also needs `esentutl` and so stays Windows-only whatever the runtime). So the
assembly's own runtimeconfig is read, `dotnet --list-runtimes` is asked once,
and the tool is reported unavailable, both versions named, unless an installed
runtime satisfies the app's roll-forward policy.
What is established is the invocation: if the runtime is there, this is how the
tool is started, and if it then fails the parser reports its failure like any
other. The honest position is to make the attempt possible and let the result
speak, not to advertise a toolchain nobody has run.

Resolution order, and the same one for `_run_command` and for `aeng preflight` --
a preflight that looked somewhere the runner does not would call a tool present
and then watch the parser fail on it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from functools import cache
from pathlib import Path, PurePosixPath

from artifact_engine.models import Tool

# The launcher for a framework-dependent .NET assembly. Not configurable here:
# if it is not on PATH the tool is reported as unavailable, with the reason.
_DOTNET = "dotnet"
_ROLL_FORWARD_ENV = "DOTNET_ROLL_FORWARD"


def _version(text: str) -> tuple[int, int, int] | None:
    """`9.0.4` -> (9, 0, 4). A prerelease or build suffix is dropped; anything
    that is not a dotted version is None rather than a guess."""
    core = text.strip().split("-", 1)[0].split("+", 1)[0]
    parts = core.split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts[:3]):
        return None
    nums = [int(p) for p in parts[:3]]
    return (nums + [0, 0])[0], (nums + [0, 0])[1], (nums + [0, 0])[2]


@cache
def installed_runtimes(runtime: str) -> tuple[tuple[str, tuple[int, int, int]], ...] | None:
    """What `dotnet --list-runtimes` reports, or None when it cannot be asked.

    Cached per launcher: `aeng preflight` resolves 36 parsers through 13 tools, and
    asking once per parser would be 35 process starts for one answer. A launcher
    that cannot be asked is None, and None means "do not know" -- the caller then
    lets the attempt happen, because a failed launch is reported loudly per parser
    and refusing a tool on a guess would be the quiet failure instead.
    """
    try:
        done = subprocess.run([runtime, "--list-runtimes"], capture_output=True,
                              text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    found = []
    for line in done.stdout.splitlines():
        bits = line.split()
        version = _version(bits[1]) if len(bits) >= 2 else None
        if version:
            found.append((bits[0], version))
    return tuple(found)


def _accepts(policy: str, need: tuple[int, int, int], have: tuple[int, int, int]) -> bool:
    """Whether .NET would start an app asking for `need` on runtime `have`.

    The host never rolls BACKWARD, under any policy. The default, `Minor`, stays
    within the requested major version -- which is why a host with only .NET 10
    does not run a `net9.0` tool unless someone asked for `Major`.
    """
    if have < need:
        return False
    p = (policy or "Minor").strip().lower()
    if p == "disable":
        return have == need
    if p in ("latestpatch", "patch"):
        return have[:2] == need[:2]
    if p in ("major", "latestmajor"):
        return True
    return have[0] == need[0]          # Minor, LatestMinor, and anything unknown


def _unsatisfied(dll: Path, runtime: str) -> str:
    """Why the runtime cannot start this assembly, or "" when it can (or when
    there is nothing to check against)."""
    config = dll.with_name(dll.stem + ".runtimeconfig.json")
    try:
        options = json.loads(config.read_text(encoding="utf-8")).get("runtimeOptions") or {}
    except (OSError, ValueError, AttributeError):
        return ""
    declared_fw = options.get("frameworks") or (
        [options["framework"]] if options.get("framework") else [])
    # Both places a roll-forward policy can come from are read. The pinned EZ
    # tools declare none of their own, so which of the two wins when both are set
    # never arises for them.
    policy = options.get("rollForward") or os.environ.get(_ROLL_FORWARD_ENV) or "Minor"
    wanted = [(fw.get("name", ""), _version(str(fw.get("version", ""))))
              for fw in declared_fw if isinstance(fw, dict)]
    wanted = [(name, v) for name, v in wanted if name and v]
    if not wanted:
        return ""
    have = installed_runtimes(runtime)
    if have is None:
        return ""
    for name, need in wanted:
        versions = sorted(v for n, v in have if n == name)
        if not any(_accepts(policy, need, v) for v in versions):
            shown = ", ".join(".".join(map(str, v)) for v in versions) or "none"
            return (f"needs {name} {need[0]}.{need[1]} and this host's `{_DOTNET}` has "
                    f"{shown} (install the .NET {need[0]} runtime)")
    return ""

# Hayabusa is fetched outside the parser manifests (its parser is a Python
# handler with no `tool:` section), so it cannot express the `linux:` block above
# and states the same fact here instead. It publishes one asset per platform, all
# version-stamped -- `hayabusa-4.0.0-win-x64.zip`, `hayabusa-4.0.0-lin-x64-gnu.zip`
# -- and the binary inside carries the same name, so what to DOWNLOAD and what to
# look for afterwards are two faces of one answer and live together.
HAYABUSA_ASSET_TAG = "win-x64.zip" if os.name == "nt" else "lin-x64-gnu.zip"
HAYABUSA_GLOB = "hayabusa*.exe" if os.name == "nt" else "hayabusa*"

# The PowerShell editions that can run a bundled `.ps1`, most-preferred first.
# `powershell` is Windows PowerShell 5.1 -- on every Windows host since 2016 and
# what the one bundled script was written against; `pwsh` is PowerShell 7+.
_PS_EDITIONS = ("powershell", "pwsh")


@dataclass(frozen=True)
class Launch:
    """How to start one tool, or why it cannot be started."""

    argv: tuple[str, ...] = ()
    how: str = ""            # native | dotnet | powershell | pwsh
    reason: str = ""         # filled only when `argv` is empty

    @property
    def ok(self) -> bool:
        return bool(self.argv)


def declared(tool: Tool, posix: bool | None = None) -> str:
    """The file this platform should look for.

    `tool.binary` stays the default and the Windows answer, so every manifest
    written before this existed keeps working untouched; a `linux:` block
    overrides it where the same download holds a different file.
    """
    if posix is None:
        posix = os.name != "nt"
    if posix and tool.linux and tool.linux.binary:
        return tool.linux.binary
    return tool.binary


def locate(name: str, tools_dir: Path | str) -> Path:
    r"""Where the file a manifest declares actually is.

    Returns the exact join when it exists, and otherwise the same path walked
    case-insensitively -- which on Windows is the same answer and on Linux is the
    difference between a toolchain and an empty one.

    MEASURED on a case-sensitive filesystem, right after `aeng setup` finished:
    the EvtxECmd archive unpacks `EvtxeCmd/` where all seventeen manifests said
    `EvtxECmd/`, and the DeepBlueCLI archive unpacks `DeepBlueCLI-master/` where
    the manifest said `deepbluecli-master/`. On Windows both resolve and nobody
    ever notices. On Linux eighteen parsers went quiet and the reason printed was
    "not installed (run `aeng setup`)" -- to an analyst who had just run it.

    The manifests are corrected, and that is not enough on its own: upstream picks
    that capitalisation, rebuilds these tools constantly, and has already shipped
    two spellings of the same name. Matching it by hand is a promise this repo
    cannot keep.

    Safe here in a way it would NOT be for evidence, where two names differing
    only in case are two different files and `core/evidence.py` records the
    ambiguity: this directory holds what `setup` unpacked into it, and a toolchain
    with two tools whose names differ only in case is not a thing that exists. A
    path that matches nothing comes back as the exact join, so the caller reports
    it missing under the name the manifest uses.
    """
    base = Path(tools_dir)
    exact = base / name
    if exact.exists():
        return exact
    here = base
    for part in PurePosixPath(name.replace("\\", "/")).parts:
        nxt = here / part
        if nxt.exists():
            here = nxt
            continue
        try:
            match = next((c for c in here.iterdir() if c.name.lower() == part.lower()), None)
        except OSError:
            return exact
        if match is None:
            return exact
        here = match
    return here


def executable(path: Path) -> bool:
    """Whether the host would let this file be started, as far as its bits go.

    Only a question on POSIX; Windows has no execute bit to lose. MEASURED on Kali:
    `aeng setup` unpacked chainsaw's and hayabusa's Linux builds as `-rw-r--r--` --
    Python's zip reader writes a member's content, not the permissions it was
    recorded with -- so both parsers failed with `PermissionError` on every run,
    while `aeng preflight` called chainsaw runnable.
    """
    if os.name == "nt":
        return path.is_file()
    return path.is_file() and os.access(path, os.X_OK)


def ensure_executable(path: Path) -> bool:
    """Give a file the execute bits its read bits imply. True when it changed.

    Adds and never removes, and only where a read bit already is: `r` without `x`
    is exactly the state an unpack leaves, and nothing here can make a file
    runnable by someone who could not already read it.
    """
    if os.name == "nt" or not path.is_file() or os.access(path, os.X_OK):
        return False
    mode = path.stat().st_mode
    path.chmod(mode | ((mode & 0o444) >> 2))
    return True


def _runs_here(path: Path, posix: bool) -> bool:
    """Whether this file is something the host can execute directly.

    A `.exe` on POSIX is the case that matters: the EZ tools' apphost is present
    on disk, is the wrong architecture entirely, and would otherwise be reported
    as a tool that is installed and then fail with a format error per parser.
    The execute bit is asked only when the POSIX rules apply (see `executable`).
    """
    if not path.is_file():
        return False
    if posix and path.suffix.lower() == ".exe":
        return False
    return not posix or executable(path)


def powershell(posix: bool | None = None) -> Launch:
    """The interpreter for a bundled `.ps1`, or why this host has none.

    OFF WINDOWS THIS ALWAYS REFUSES, and installing `pwsh` would not change it.
    The only `.ps1` this engine ships is DeepBlueCLI, and every event it examines
    arrives through `Get-WinEvent` -- a cmdlet whose PowerShell 7 reference opens
    its description with "This cmdlet is only available on the Windows platform"
    (Microsoft.PowerShell.Diagnostics, learn.microsoft.com, checked against 7.6).
    PowerShell 7 itself runs on Linux; that one cmdlet does not come with it.

    So a `pwsh` found on a Linux host would start the script and then fail at its
    first data access -- once per log, once per volume, a screenful of errors that
    all mean the same sentence. The sentence is said here instead, once, and
    `aeng preflight` prints it before the evidence is touched.
    """
    if posix is None:
        posix = os.name != "nt"
    if posix:
        return Launch(reason=("a Windows host is required -- the bundled script reads "
                              "events with Get-WinEvent, which PowerShell provides only "
                              "on Windows"))
    for edition in _PS_EDITIONS:
        found = shutil.which(edition)
        if found:
            return Launch((found,), edition)
    return Launch(reason=("no PowerShell interpreter on PATH "
                          f"(looked for {' and '.join(_PS_EDITIONS)})"))


def resolve(tool: Tool, tools_dir: Path | str, posix: bool | None = None) -> Launch:
    """How to invoke `tool` here, or why it cannot be invoked."""
    if posix is None:
        posix = os.name != "nt"
    name = declared(tool, posix)
    path = locate(name, tools_dir)

    # A script is not started, an interpreter is -- and which interpreters exist
    # is a property of the HOST, not of the file, so `_runs_here` cannot answer it:
    # a `.ps1` is readable everywhere and runnable in one place.
    if PurePosixPath(name).suffix.lower() == ".ps1":
        if not path.is_file():
            return Launch(reason=f"{PurePosixPath(name).name} is not installed "
                                 f"(run `aeng setup`)")
        shell = powershell(posix)
        if not shell.ok:
            return Launch(reason=shell.reason)
        return Launch((*shell.argv, str(path)), shell.how)

    if _runs_here(path, posix):
        return Launch((str(path),), "native")

    # Framework-dependent .NET: the apphost cannot run here, the assembly can.
    dll = path.with_suffix(".dll")
    if path.suffix.lower() == ".exe" and dll.is_file():
        runtime = shutil.which(_DOTNET)
        if not runtime:
            return Launch(reason=(f"{PurePosixPath(name).name} is a .NET application and "
                                  f"`{_DOTNET}` is not on PATH (install the .NET 9 runtime)"))
        # The launcher existing is not the runtime existing -- see the module
        # docstring for the host where the difference was 35 parsers.
        why = _unsatisfied(dll, runtime)
        if why:
            return Launch(reason=f"{PurePosixPath(name).name} {why}")
        return Launch((runtime, str(dll)), "dotnet")

    # NO `PATH` FALLBACK, and that is a deliberate reversal of the plan this came
    # from. It was written, and it worked: on the development machine `shutil.which`
    # found a separate copy of the EZ tools and happily ran those instead.
    #
    # Which is exactly the problem. `aeng setup` pins what it downloads and records
    # the sha256 of every binary in `tools.lock.json` -- an audit trail of which
    # tool builds produced the results, which is the point of keeping it. Silently
    # running a different, unrecorded, possibly older build off PATH breaks that
    # claim without anyone seeing it happen, and a tool version can change output
    # columns. "Not installed, run `aeng setup`" is the right answer even on a host
    # that has one lying around.
    #
    # `dotnet` above is not an exception to this: it is a RUNTIME, not a parser, and
    # the assembly it executes is still the pinned one.
    if path.is_file():
        if posix and path.suffix.lower() != ".exe" and not executable(path):
            return Launch(reason=(f"{PurePosixPath(name).name} is present but not "
                                  f"executable (run `aeng setup` again to repair it)"))
        return Launch(reason=f"{PurePosixPath(name).name} is present but not runnable here")
    return Launch(reason=f"{PurePosixPath(name).name} is not installed (run `aeng setup`)")
