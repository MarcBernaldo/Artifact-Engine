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

RESOLUTION IS DELIBERATELY THE RUNNER'S RULE, verbatim: `<tools_dir>/<binary>`,
the same join `_run_command` makes. A preflight that looked somewhere the runner
does not would report a tool as present and then watch the parser fail on it,
which is worse than not checking. When that rule grows a `PATH` fallback and
per-platform assets, both move together.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from artifact_engine.models import ParserManifest


@dataclass(frozen=True)
class ToolCheck:
    """One external binary, and the parsers that cannot run without it."""

    binary: str                  # as the manifest declares it
    path: Path | None            # where it is, or None
    parsers: tuple[str, ...]     # parser ids gated on it

    @property
    def present(self) -> bool:
        return self.path is not None

    @property
    def name(self) -> str:
        """The file name, without the subdirectory a manifest may declare."""
        return PurePosixPath(self.binary).name


def find(binary: str, tools_dir: Path | str) -> Path | None:
    """Where `binary` is, or None. The runner's rule, and nothing else."""
    p = Path(tools_dir) / binary
    return p if p.is_file() else None


def check(parsers: list[ParserManifest], tools_dir: Path | str) -> list[ToolCheck]:
    """Every binary the given parsers need, present or not.

    Grouped by binary rather than listed per parser: EvtxECmd is one download and
    seventeen parsers, and seventeen lines saying so is a report nobody reads to
    the end.
    """
    needed: dict[str, list[str]] = {}
    for p in parsers:
        if p.tool and p.tool.binary:
            needed.setdefault(p.tool.binary, []).append(p.id)
    return [ToolCheck(binary=b, path=find(b, tools_dir), parsers=tuple(sorted(ids)))
            for b, ids in sorted(needed.items())]


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
        "missing": [{"binary": c.binary, "parsers": list(c.parsers)} for c in absent],
    }


def describe(checks: list[ToolCheck], total_parsers: int) -> list[str]:
    """Console lines. Empty when every tool a parser needs is here."""
    absent = [c for c in checks if not c.present]
    if not absent:
        return []
    gated = blocked(checks)
    lines = [
        (f"[!] {len(absent)} external tool(s) are not installed; "
         f"{len(gated)} of {total_parsers} parser(s) cannot run on this host."),
        "    They will not be tried. Everything else still runs -- this is not an",
        "    error, but it IS a limit on what the run can find. `aeng setup`",
        "    fetches them.",
    ]
    width = max(len(c.name) for c in absent)
    for c in absent:
        ids = ", ".join(c.parsers[:4]) + ("..." if len(c.parsers) > 4 else "")
        lines.append(f"        {c.name:<{width}}  {len(c.parsers):>2} parser(s): {ids}")
    return lines
