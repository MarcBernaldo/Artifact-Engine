r"""Conventions that only break on the OTHER host.

This file exists because the engine is developed on Windows and is meant to run on
Linux too, and the defects that gap produces share one shape: nothing raises, a
parser simply stops recognising things and reports an empty table. That is the
project's worst failure mode -- zero rows reading as no attack -- reached without
a single error in the log.

So these are enforced as conventions, checked on every platform, rather than left
to a CI leg to notice on one of them.
"""
from __future__ import annotations

import re
from pathlib import Path

import artifact_engine

_PKG = Path(artifact_engine.__file__).resolve().parent

# `Path(x).name` and friends. The negative lookbehind keeps `PureWindowsPath(x)`
# and `PurePosixPath(x)` out: naming the flavour explicitly is the fix, not the
# defect.
_HOST_PATH_PARSE = re.compile(
    r"(?<![A-Za-z_])Path\(\s*[A-Za-z_][\w.\[\]\"' ]*\)\s*\.(name|stem|suffix|parent|parts)\b")

# The escape hatch, on the line directly above: some `Path(...)` in a win_ handler
# really is a path on the host filesystem (an `os.walk` result, a temp dir), where
# the host's flavour is the correct one.
_HOST_OK = "host path"


def test_windows_evidence_paths_are_never_parsed_with_the_host_flavour():
    r"""A `$MFT` path, an Amcache image path or an event-log command line uses `\`
    as its separator whatever machine reads it. `pathlib.Path` is the HOST's
    flavour, so on Linux -- where a backslash is an ordinary filename character --
    `Path(r".\Users\jdoe\Desktop\KAPE").name` is the entire string rather than
    `KAPE`.

    Nothing errors. The collector is not identified, the LOLBAS name never matches
    its list, and the table comes out empty on a case that was full of them. Two
    tests in test_collection_artifacts.py caught this on a case-sensitive
    filesystem; `win_lolbas` had nobody watching it at all.

    The reverse direction is safe and deliberately not checked: Windows accepts `/`
    as a separator, so a Linux evidence path read by `WindowsPath` still splits
    correctly. The asymmetry only runs one way.
    """
    offenders: list[str] = []
    for f in sorted(_PKG.glob("handlers/win_*.py")):
        lines = f.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines, start=1):
            if not _HOST_PATH_PARSE.search(line):
                continue
            # Same window as the `suspicious`-column convention: the exemption is
            # a comment sitting directly above the line it explains.
            if any(_HOST_OK in c for c in lines[max(0, n - 3):n]):
                continue
            offenders.append(f"{f.name}:{n}: {line.strip()}")

    assert not offenders, (
        "these parse a Windows evidence path with the host's `Path` flavour, which "
        "silently returns the whole string off Windows. Use `PureWindowsPath`, or "
        f"note `{_HOST_OK}` in a comment directly above if it really is a path on "
        "the machine doing the reading:\n  " + "\n  ".join(offenders))
