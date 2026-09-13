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

import ast
import re
from pathlib import Path, PurePosixPath

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


# The joins this bans are the ones that reach into the ACQUISITION. Joining a
# constant like `_MFT_CSV` is left alone on purpose: those name `CSVs/...`, which
# this engine wrote itself in an earlier phase and whose spelling it controls.
_EVIDENCE_JOIN = re.compile(
    r"""(?:Path\(\s*ctx\.evidence\s*\)|ctx\.evidence)\s*/\s*["']""")


def test_windows_handlers_do_not_join_a_cased_path_onto_the_evidence():
    r"""A literal `ctx.evidence / "Windows" / "System32"` is the case-sensitivity
    defect in its original form.

    On NTFS it works whatever the acquisition spelled, which is why it survived
    everywhere. On a case-sensitive filesystem the directory is simply not found:
    the handler self-gates with `HandlerSkip`, lands in `skipped` next to every
    artifact the host genuinely lacks, and the run reads as a quiet host.

    `core.evidence.in_tree` resolves against the tree instead, and returns a plain
    path either way so the caller's own `is_dir()` stays the gate.
    """
    offenders: list[str] = []
    for f in sorted(_PKG.glob("handlers/win_*.py")):
        lines = f.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines, start=1):
            if not _EVIDENCE_JOIN.search(line):
                continue
            if any(_HOST_OK in c for c in lines[max(0, n - 3):n]):
                continue
            offenders.append(f"{f.name}:{n}: {line.strip()}")

    assert not offenders, (
        "these join a hard-coded spelling onto the evidence root, which finds "
        "nothing on a case-sensitive filesystem and self-gates in silence. Use "
        "`core.evidence.in_tree(ctx.evidence, \"A/B/C\")`:\n  " + "\n  ".join(offenders))


# --------------------------------------------------------------------------- #
# How work is started
# --------------------------------------------------------------------------- #
_POOL = re.compile(r"ProcessPoolExecutor\(")


def test_every_process_pool_pins_its_start_method():
    r"""Left to the platform, `ProcessPoolExecutor` forks on Linux -- and by the
    time the scheduler builds it, the thread pool beside it is already running.
    CPython says what that is worth itself:

        DeprecationWarning: This process (pid=N) is multi-threaded,
        use of fork() may lead to deadlocks in the child.

    A deadlock here is the worst failure this engine can have: not an error and
    not a wrong answer, a run that never finishes, on evidence, with the progress
    bars still on screen. And the code was already written for spawn semantics --
    `_worker_init` exists because "a spawned worker gets its own copy" of
    `procs._active`, which a forked child does not get.
    """
    offenders: list[str] = []
    for f in sorted(_PKG.glob("core/*.py")):
        text = f.read_text(encoding="utf-8")
        for m in _POOL.finditer(text):
            tail = text[m.start():m.start() + 400]
            if "mp_context" not in tail:
                line = text[:m.start()].count("\n") + 1
                offenders.append(f"{f.name}:{line}")
    assert not offenders, (
        "these build a process pool without pinning the start method, so it forks "
        "on Linux out of a process that already has threads:\n  " + "\n  ".join(offenders))


def test_the_pinned_start_method_is_spawn():
    from artifact_engine.core import scheduler

    assert scheduler._MP_CONTEXT.get_start_method() == "spawn"


def test_no_handler_looks_up_a_tool_its_manifest_already_declares():
    r"""One decision, one place -- and handlers were the half that escaped it.

    `_run_command` has asked `core/toolchain` how to start a tool since v0.7.40,
    and so has `aeng preflight`. The Python handlers did not: they joined
    `ctx.tools` to a hardcoded `X.exe` and ran that. On a host where the Windows
    apphost cannot execute but the assembly can, the preflight reported the tool
    as available through `dotnet` and the parser then failed on it -- the exact
    disagreement `core/preflight.py` says must never exist.

    The declared binary now reaches the handler already resolved, as
    `ctx.tool`. Matching a QUOTED basename so prose and comments naming the tool
    are untouched; it is the string built into a path that is the defect.
    """
    import yaml

    from artifact_engine.config import DATA_DIR

    offenders = []
    for manifest in sorted(DATA_DIR.glob("parsers/**/*.yaml")):
        m = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        binary = (m.get("tool") or {}).get("binary")
        handler = m.get("handler")
        if not binary or not handler:
            continue
        mod = handler.partition(":")[0].rpartition(".")[2]
        src = _PKG / "handlers" / f"{mod}.py"
        if not src.is_file():
            continue
        text = src.read_text(encoding="utf-8")
        name = PurePosixPath(binary).name
        if f'"{name}"' in text or f"'{name}'" in text:
            offenders.append(f"{mod}.py hardcodes {name}, which {manifest.name} declares")
    assert not offenders, (
        "these look their tool up instead of using the resolved `ctx.tool`:"
        "\n  " + "\n  ".join(offenders))


# --------------------------------------------------------------------------- #
# The portability lint (CROSS-PLATFORM.md, Wave 8)
# --------------------------------------------------------------------------- #
# Calls that reach THIS HOST's filesystem. Deliberately narrow, and the exclusions
# carry the whole meaning of the rule below:
#
#   `<hive>.open(r"Microsoft\Windows NT\CurrentVersion")` is a REGISTRY key, whose
#   separator is a backslash by definition and has nothing to do with the host.
#   `PureWindowsPath(...)` and `PurePosixPath(...)` name their flavour on purpose
#   -- that is the fix for evidence paths, not a defect (see the top of this file).
#
# So only the bare builtins and the explicitly host-facing helpers count.
_HOST_CALLS = {"Path", "open"}
_HOST_DOTTED = {
    "os.stat", "os.listdir", "os.scandir", "os.makedirs", "os.mkdir", "os.remove",
    "os.walk", "os.path.join", "os.path.exists", "os.path.isfile", "os.path.isdir",
    "shutil.which", "shutil.copy", "shutil.copy2", "shutil.rmtree", "shutil.move",
}

# A literal only ONE platform can hold: a drive letter, or a top-level FHS
# directory. Anything relative is fine -- it is joined onto a root that the
# caller chose.
_ONE_PLATFORM_ONLY = re.compile(
    r"^(?:[A-Za-z]:[\\/]"
    r"|/(?:etc|var|usr|bin|sbin|opt|proc|sys|root|home|tmp|lib|lib64|dev|run|boot|mnt|srv)(?:/|$))")

# How a function says "I already know which platform I am on".
_PLATFORM_TEST = ("os.name", "sys.platform", "platform.system")


def _first_party() -> list[Path]:
    """Every .py this repository actually wrote.

    `tools/` is gitignored third-party payload that `aeng setup` downloads -- it
    holds a Python 2 script that will not even parse, and none of it is ours to
    lint.
    """
    return [p for p in sorted(_PKG.rglob("*.py")) if "tools" not in p.relative_to(_PKG).parts]


def _calls(tree: ast.AST, text: str):
    """Every call, paired with whether any enclosing function tested the platform."""
    lines = text.splitlines()

    def guarded(fn) -> bool:
        body = "\n".join(lines[fn.lineno - 1:(fn.end_lineno or fn.lineno)])
        return any(t in body for t in _PLATFORM_TEST)

    def walk(node, inside: bool):
        for child in ast.iter_child_nodes(node):
            here = inside
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                here = inside or guarded(child)
            if isinstance(child, ast.Call):
                yield child, here
            yield from walk(child, here)

    yield from walk(tree, False)


def _callee(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    parts = []
    node = call.func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _strings_in(call: ast.Call) -> list[str]:
    return [n.value for n in ast.walk(call)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def test_no_single_platform_path_reaches_the_filesystem_unguarded():
    r"""The defect this lint exists for, found twice on real hosts.

    `find_7z` built `C:\Program Files\7-Zip\7z.exe` as a candidate on every host,
    and the `sum` handler fell back to `%SystemRoot%\System32\esentutl.exe`. On
    Linux both are two guaranteed misses dressed up as a search: nothing raises,
    the tool is simply "not found", and the parser reports nothing. Which is this
    project's worst failure mode reached without an error in the log.

    Building one is fine -- `C:\Program Files` is exactly where 7-Zip goes -- as
    long as the function has established which platform it is on first. The rule
    is about the GUARD, not about the literal.
    """
    offenders = []
    for path in _first_party():
        text = path.read_text(encoding="utf-8")
        for call, guarded in _calls(ast.parse(text), text):
            if guarded:
                continue
            name = _callee(call)
            if name not in _HOST_CALLS and name not in _HOST_DOTTED:
                continue
            for value in _strings_in(call):
                if _ONE_PLATFORM_ONLY.match(value):
                    offenders.append(
                        f"{path.name}:{call.lineno}  {name}(... {value!r} ...)")
    assert not offenders, (
        "a path only one platform can hold, handed to the host's filesystem with "
        "nothing establishing the platform first:\n  " + "\n  ".join(offenders))


def test_no_backslash_path_is_handed_to_the_host_unguarded():
    r"""The narrow half of "no literal backslash separators", and the only half
    that survives contact with this codebase.

    MEASURED before it was written: the broad rule flags 40-odd sites and every
    one of them is CORRECT. A backslash here is almost always the separator of the
    thing being parsed, not of a path being built -- `HKLM\SOFTWARE\...` is a
    registry key, `\Microsoft\Windows\...` is a Task Scheduler namespace,
    `\A`/`\Z`/`\x00` are regex anchors, and the banner is ASCII art. A lint
    everyone suppresses is worse than no lint.

    What IS a defect is a backslash-separated string reaching THIS host's
    filesystem without the platform being established first -- `open(f"{base}\
    {name}")` finds nothing on Linux, where a backslash is an ordinary filename
    character, and reports missing rather than wrong. Evidence paths never go
    through here: they are parsed with `PureWindowsPath`, which this rule does not
    look at, for the reason at the top of this file.
    """
    offenders = []
    for path in _first_party():
        text = path.read_text(encoding="utf-8")
        for call, guarded in _calls(ast.parse(text), text):
            if guarded:
                continue
            name = _callee(call)
            if name not in _HOST_CALLS and name not in _HOST_DOTTED:
                continue
            for value in _strings_in(call):
                if chr(92) in value:
                    offenders.append(
                        f"{path.name}:{call.lineno}  {name}(... {value!r} ...)")
    assert not offenders, (
        "a backslash-separated path handed to the host's filesystem with nothing "
        "establishing the platform first:\n  " + "\n  ".join(offenders))
