"""Everything CI checks, on this machine, before a push.

    python scripts/check.py                  lint, the suite on this Python and on 3.10
    python scripts/check.py --fast           lint and the suite on this Python only
    python scripts/check.py --real C:\\Cases  ...and the engine over every case there

CI runs ruff and pytest on Windows with Python 3.10 and 3.13, after the push. This
runs the same three things before it, and says READY or NOT READY in one line. A
step that could not run counts as not ready: an unchecked 3.10 is the leg that has
failed in CI before.

The 3.10 leg lives in `.venv310/` at the repository root (gitignored), built with
uv on first use and reused after: `uv venv --python 3.10`, then the package with
the same extras CI installs. `--rebuild` starts it again.

`--real` runs `aeng run` over every folder of the given root (or of `AENG_CASES`),
one after another, and prints figures only, read from each case's
`run-summary.json`: status, machines, parsers ok / skipped / errors. Nothing a case
holds is printed, and each run's console goes to a log under the temp folder. A
case that ends `incomplete` with no parser error is reported and does not block:
an acquisition known to be truncated ends that way on every run.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VENV310 = REPO / ".venv310"
EXTRAS = ".[dev,mcp]"          # what .github/workflows/ci.yml installs
VERSION_FILES = {"src/artifact_engine/__init__.py": '__version__ = "',
                 "pyproject.toml": 'version = "'}


class Step:
    def __init__(self, name: str) -> None:
        self.name, self.state, self.note, self.seconds = name, "not run", "", 0.0

    @property
    def ok(self) -> bool:
        return self.state == "ok"


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, check=False,
                          encoding="utf-8", errors="replace", **kw)


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    return lines[-1] if lines else "(no output)"


def _timed(step: Step, fn) -> Step:
    print(f"[+] {step.name} ...", flush=True)
    start = time.monotonic()
    try:
        step.state, step.note = fn()
    except (OSError, subprocess.SubprocessError) as e:
        step.state, step.note = "not run", f"{type(e).__name__}: {e}"
    step.seconds = time.monotonic() - start
    print(f"    {step.state}: {step.note}  ({step.seconds:.0f}s)", flush=True)
    return step


def lint() -> tuple[str, str]:
    r = _run([sys.executable, "-m", "ruff", "check", "src/", "tests/"])
    return ("ok" if r.returncode == 0 else "FAILED"), _last_line(r.stdout or r.stderr)


def suite(python: str) -> tuple[str, str]:
    r = _run([python, "-m", "pytest", "-q", "-p", "no:cacheprovider"])
    return ("ok" if r.returncode == 0 else "FAILED"), _last_line(r.stdout or r.stderr)


def _healthy(py: Path) -> bool:
    return py.is_file() and _run(
        [str(py), "-c", "import pytest, pandas, xlsxwriter, pydantic, artifact_engine"]
    ).returncode == 0


def suite_310(rebuild: bool) -> tuple[str, str]:
    if sys.version_info[:2] == (3, 10):
        return "ok", "this Python is 3.10: the leg above is this one"
    py = VENV310 / "Scripts" / "python.exe"
    if rebuild or not _healthy(py):
        uv = shutil.which("uv")
        if not uv:
            return "not run", "uv is not on PATH: it builds the 3.10 environment"
        shutil.rmtree(VENV310, ignore_errors=True)
        made = _run([uv, "venv", "--native-tls", "--python", "3.10", str(VENV310)])
        if made.returncode != 0:
            return "not run", "no 3.10 environment: " + _last_line(made.stderr)
        got = _run([uv, "pip", "install", "-q", "--native-tls", "--python", str(py),
                    "-e", EXTRAS])
        if got.returncode != 0:
            return "not run", "the 3.10 environment did not install: " + _last_line(got.stderr)
    return suite(str(py))


def versions() -> tuple[str, str]:
    found = {}
    for rel, marker in VERSION_FILES.items():
        text = (REPO / rel).read_text(encoding="utf-8")
        line = next((ln for ln in text.splitlines() if ln.startswith(marker)), "")
        found[rel] = line[len(marker):].split('"')[0]
    if len(set(found.values())) != 1 or not all(found.values()):
        return "FAILED", f"the version is not one value in both files: {found}"
    version = next(iter(found.values()))
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    pushed = _run(["git", "show", "origin/main:src/artifact_engine/__init__.py"]).stdout
    marker = VERSION_FILES["src/artifact_engine/__init__.py"]
    before = next((ln[len(marker):].split('"')[0] for ln in pushed.splitlines()
                   if ln.startswith(marker)), "?")
    changed = _run(["git", "diff", "--name-only", "origin/main", "--", "src", "tests"]).stdout
    note = f"{version} on {branch} (origin/main is {before})"
    if changed.strip() and version == before:
        note += "; src/ or tests/ changed and no bump yet: the release commit bumps it"
    return "ok", note


def real_cases(root: Path, only: list[str], skip: list[str]) -> tuple[str, str]:
    if not root.is_dir():
        return "not run", f"{root} is not a folder"
    cases = sorted(p for p in root.iterdir() if p.is_dir()
                   and (not only or p.name in only) and p.name not in skip)
    if not cases:
        return "not run", f"no case folder under {root}"
    errors = odd = incomplete = 0
    for n, case in enumerate(cases, 1):
        log = Path(tempfile.gettempdir()) / f"aeng-check-case{n}.log"
        start = time.monotonic()
        with log.open("w", encoding="utf-8", errors="replace") as fh:
            rc = subprocess.run([sys.executable, "-m", "artifact_engine", "run", "-p", str(case)],
                                stdout=fh, stderr=subprocess.STDOUT, cwd=REPO,
                                check=False).returncode
        took = time.monotonic() - start
        try:
            summary = json.loads((case / "run-summary.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            summary = {}
        totals = summary.get("totals", {})
        fresh = summary.get("finished_at", "") and (case / "run-summary.json").stat().st_mtime \
            >= time.time() - took - 60
        if rc not in (0, 2) or not fresh:
            odd += 1
        errors += int(totals.get("errors", 0) or 0)
        incomplete += summary.get("status") == "incomplete"
        print(f"    case {n}/{len(cases)}: exit {rc} | {summary.get('status', 'no summary')} | "
              f"machines {summary.get('machines', '?')} | ok {totals.get('ok', '?')} | "
              f"skipped {totals.get('skipped', '?')} | errors {totals.get('errors', '?')} | "
              f"{took:.0f}s | log {log}", flush=True)
    note = (f"{len(cases)} case(s), {errors} parser error(s), {incomplete} incomplete, "
            f"{odd} that did not finish a run")
    return ("ok" if not errors and not odd else "FAILED"), note


def main() -> int:
    ap = argparse.ArgumentParser(description="Everything CI checks, before a push.")
    ap.add_argument("--fast", action="store_true", help="skip the Python 3.10 leg")
    ap.add_argument("--rebuild", action="store_true", help="build .venv310 again")
    ap.add_argument("--real", nargs="?", const=os.environ.get("AENG_CASES", ""), default=None,
                    metavar="ROOT", help="also run the engine over every case folder under "
                                         "ROOT (default: the AENG_CASES variable)")
    ap.add_argument("--only", default="", help="with --real: these case folders (comma list)")
    ap.add_argument("--skip", default="", help="with --real: not these case folders")
    a = ap.parse_args()

    here = f"{sys.version_info.major}.{sys.version_info.minor}"
    steps = [_timed(Step("version"), versions),
             _timed(Step("lint"), lint),
             _timed(Step(f"tests on {here}"), lambda: suite(sys.executable))]
    if not a.fast:
        steps.append(_timed(Step("tests on 3.10"), lambda: suite_310(a.rebuild)))
    if a.real is not None:
        if not a.real:
            steps.append(Step("real cases"))
            steps[-1].note = "give a folder: --real <ROOT>, or set AENG_CASES"
        else:
            steps.append(_timed(Step("real cases"), lambda: real_cases(
                Path(a.real), [x for x in a.only.split(",") if x],
                [x for x in a.skip.split(",") if x])))

    print()
    for s in steps:
        print(f"  {s.name:<16} {s.state:<8} {s.seconds:>5.0f}s  {s.note}")
    bad = [s.name for s in steps if not s.ok]
    left_out = [n for n, on in (("the 3.10 leg", a.fast), ("the real cases", a.real is None)) if on]
    if bad:
        print(f"\nNOT READY: {', '.join(bad)}")
        return 1
    print("\nREADY" + (f" (without {' and '.join(left_out)})" if left_out else " to push"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
