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
API or assume a drive letter, and this machine has no .NET runtime to try it on.
What is established is the invocation: if the runtime is there, this is how the
tool is started, and if it then fails the parser reports its failure like any
other. The honest position is to make the attempt possible and let the result
speak, not to advertise a toolchain nobody has run.

Resolution order, and the same one for `_run_command` and for `aeng preflight` --
a preflight that looked somewhere the runner does not would call a tool present
and then watch the parser fail on it.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from artifact_engine.models import Tool

# The launcher for a framework-dependent .NET assembly. Not configurable here:
# if it is not on PATH the tool is reported as unavailable, with the reason.
_DOTNET = "dotnet"

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


def _runs_here(path: Path, posix: bool) -> bool:
    """Whether this file is something the host can execute directly.

    A `.exe` on POSIX is the case that matters: the EZ tools' apphost is present
    on disk, is the wrong architecture entirely, and would otherwise be reported
    as a tool that is installed and then fail with a format error per parser.
    """
    if not path.is_file():
        return False
    return not (posix and path.suffix.lower() == ".exe")


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
    base = Path(tools_dir)
    path = base / name

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
        if runtime:
            return Launch((runtime, str(dll)), "dotnet")
        return Launch(reason=(f"{PurePosixPath(name).name} is a .NET application and "
                              f"`{_DOTNET}` is not on PATH (install the .NET 9 runtime)"))

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
        return Launch(reason=f"{PurePosixPath(name).name} is present but not runnable here")
    return Launch(reason=f"{PurePosixPath(name).name} is not installed (run `aeng setup`)")
