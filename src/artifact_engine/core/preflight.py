"""What this installation can actually run, answered before evidence is touched.

Thirty-eight of the parsers drive an external binary. A binary that was never
fetched is reported today by the parser that needed it, as an error, once per
parser and per volume -- halfway through a run, after the acquisitions have been
extracted and the machines detected.

On the host the engine was built for that is a handful of lines. On a host where
a whole toolchain is missing -- a Linux box triaging a Windows acquisition, or a
fresh install where `aeng setup` has not run -- it is dozens of identical errors
scattered through the output, each one true and none of them the point. The point
is a single sentence: *this installation can run 75 of the 113 parsers, and here
is what the other 38 are waiting for.*

WHAT THIS IS NOT. It does not abort a run. Nothing in this engine is a mandatory
tool: every parser self-gates, the ones that can run still run, and a triage of
the artifacts that ARE reachable is worth having. Inventing a required/optional
split would add a failure mode the engine does not otherwise have. What a missing
tool must never do is go unsaid -- which is why this lands in the console before
phase 3 and in `run-summary.json` afterwards, rather than only in the per-parser
errors where thirty of them look like noise.

RESOLUTION IS THE RUNNER'S, and literally so since v0.7.40: both call
`core/toolchain.resolve`. A preflight that looked somewhere `_run_command` does
not would report a tool as present and then watch the parser fail on it, which is
worse than not checking at all.

That resolver is also why the answer here is no longer just present/absent. A
tool can be on disk and unrunnable -- the EZ tools' Windows apphost sits in the
tools directory on every platform -- and the useful thing to print is not "not
installed" but "this is a .NET application and `dotnet` is not on PATH". So each
check carries the reason it could not be started.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from artifact_engine.core import toolchain
from artifact_engine.models import ParserManifest


@dataclass(frozen=True)
class ToolCheck:
    """One external binary, and the parsers that cannot run without it."""

    binary: str                  # as this platform declares it
    launch: toolchain.Launch     # how it would be started, or why it would not be
    parsers: tuple[str, ...]     # parser ids gated on it

    @property
    def present(self) -> bool:
        return self.launch.ok

    @property
    def path(self) -> Path | None:
        return Path(self.launch.argv[-1]) if self.launch.ok else None

    @property
    def name(self) -> str:
        """The file name, without the subdirectory a manifest may declare."""
        return PurePosixPath(self.binary).name


def find(binary: str, tools_dir: Path | str) -> Path | None:
    """Where a plainly-named binary is, or None.

    Kept for the simple question. Anything deciding whether a PARSER can run goes
    through `toolchain.resolve`, which also knows about the launcher.
    """
    p = toolchain.locate(binary, tools_dir)
    return p if p.is_file() else None


def check(parsers: list[ParserManifest], tools_dir: Path | str) -> list[ToolCheck]:
    """Every binary the given parsers need, runnable here or not.

    Grouped by binary rather than listed per parser: EvtxECmd is one download and
    seventeen parsers, and seventeen lines saying so is a report nobody reads to
    the end.
    """
    needed: dict[str, tuple[object, list[str]]] = {}
    for p in parsers:
        if not (p.tool and p.tool.binary):
            continue
        name = toolchain.declared(p.tool)
        needed.setdefault(name, (p.tool, []))[1].append(p.id)
    return [ToolCheck(binary=b, launch=toolchain.resolve(tool, tools_dir),
                      parsers=tuple(sorted(ids)))
            for b, (tool, ids) in sorted(needed.items())]


def blocked(checks: list[ToolCheck]) -> set[str]:
    """Ids of the parsers that cannot run, because their binary is not here."""
    return {pid for c in checks if not c.present for pid in c.parsers}


def summary(checks: list[ToolCheck], total_parsers: int) -> dict:
    """The machine-readable form, for `run-summary.json`."""
    absent = [c for c in checks if not c.present]
    return {
        "tools_needed": len(checks),
        "tools_missing": len(absent),
        "parsers_total": total_parsers,
        "parsers_blocked": sorted(blocked(checks)),
        "missing": [{"binary": c.binary, "parsers": list(c.parsers),
                     "reason": c.launch.reason} for c in absent],
    }


def _without_name(check: ToolCheck) -> str:
    """A reason with the binary's own name taken off the front.

    `_run_command` reports a failure per parser and needs the name in it; this
    report lists the names in their own column two lines up, so repeating them
    here is what stops identical reasons from collapsing into one.
    """
    reason, name = check.launch.reason, check.name
    for prefix in (f"{name} is ", f"{name} "):
        if reason.startswith(prefix):
            return reason[len(prefix):]
    return reason


def describe(checks: list[ToolCheck], total_parsers: int) -> list[str]:
    """Console lines. Empty when every tool a parser needs is here."""
    absent = [c for c in checks if not c.present]
    if not absent:
        return []
    gated = blocked(checks)
    lines = [
        (f"[!] {len(absent)} external tool(s) cannot be run here; "
         f"{len(gated)} of {total_parsers} parser(s) cannot run on this host."),
        "    They will not be tried. Everything else still runs -- this is not an",
        "    error, but it IS a limit on what the run can find. `aeng setup`",
        "    fetches whatever was simply never downloaded.",
    ]
    width = max(len(c.name) for c in absent)
    for c in absent:
        ids = ", ".join(c.parsers[:4]) + ("..." if len(c.parsers) > 4 else "")
        lines.append(f"        {c.name:<{width}}  {len(c.parsers):>2} parser(s): {ids}")
    # The REASONS, once each -- and "once" has to mean it. Every reason carries
    # the binary's own name, so deduplicating the strings deduplicates nothing:
    # sixteen EZ tools waiting on one missing .NET runtime printed sixteen nearly
    # identical lines, which is the repetition this block exists to avoid. The
    # name comes off first, and what is left is the ACTION -- install a runtime,
    # or stop expecting this tool on this host at all.
    #
    # "not installed" is the one reason not repeated here: the header above
    # already says `aeng setup` fetches those, and it is the common case.
    groups: dict[str, list[str]] = {}
    for c in absent:
        if not c.launch.reason or "is not installed" in c.launch.reason:
            continue
        groups.setdefault(_without_name(c), []).append(c.name)
    for shape, names in sorted(groups.items()):
        who = names[0] if len(names) == 1 else f"{len(names)} of them"
        lines.append(f"    {who}: {shape}")
    return lines
