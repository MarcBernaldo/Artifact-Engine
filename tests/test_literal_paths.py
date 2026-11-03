"""A `[` or `]` in a path is a character class to glob, which then matches
nothing and raises nothing: the artifact is skipped without a word. UAC writes
every file under `[root]`, and a case folder can carry brackets in its name.

pathlib takes the BASE of `base.glob(pattern)` literally; what it parses is the
pattern. So the rule here is: no `glob.glob`/`glob.iglob` (they parse the whole
path), and a pattern built at run time interpolates only names this engine
defines, never text read from the evidence.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "artifact_engine"

# Where a glob pattern is built with an f-string, and why what it interpolates is
# the engine's own name, not the evidence's.
_INTERPOLATED_OK = {
    "handlers/_tables.py": "a table name the caller passes (engine constant)",
    "handlers/mem_findings.py": "a table name (engine constant)",
    "handlers/lin_logins.py": 'the log stem, "wtmp" or "btmp"',
    "handlers/lin_log_integrity.py": "a log name from the handler's own list",
}

_WHOLE_PATH_GLOB = re.compile(r"\bglob\.i?glob\(")
_FSTRING_PATTERN = re.compile(r"\.r?glob\(\s*f[\"']")


def _sources():
    return sorted(p for p in SRC.rglob("*.py") if "tools" not in p.relative_to(SRC).parts)


def test_bases_with_brackets_are_literal_and_patterns_are_not(tmp_path):
    """What the rule rests on, on this interpreter."""
    import glob
    import os

    etc = tmp_path / "[root]" / "etc"
    etc.mkdir(parents=True)
    (etc / "a.conf").write_text("x", encoding="utf-8")
    assert len(list((tmp_path / "[root]").glob("etc/*.conf"))) == 1
    assert list(tmp_path.glob("[root]/etc/*.conf")) == []
    assert glob.glob(os.path.join(str(tmp_path / "[root]"), "etc", "*.conf")) == []


@pytest.mark.parametrize("path", _sources(), ids=lambda p: p.relative_to(SRC).as_posix())
def test_no_glob_parses_a_path_from_the_evidence(path):
    rel = path.relative_to(SRC).as_posix()
    text = path.read_text(encoding="utf-8")
    assert not _WHOLE_PATH_GLOB.search(text), (
        f"{rel}: glob.glob/iglob parses the whole path, so a bracket in the case or "
        f"evidence path matches nothing; use Path(base).glob(pattern)")
    if rel not in _INTERPOLATED_OK:
        assert not _FSTRING_PATTERN.search(text), (
            f"{rel}: a glob pattern built at run time; if what it interpolates can come "
            f"from the evidence, pass it through glob.escape(), else list the file in "
            f"_INTERPOLATED_OK with the reason")


def test_the_exceptions_still_exist():
    """An entry for a file that no longer builds a pattern is a hole for the next one."""
    for rel in _INTERPOLATED_OK:
        assert _FSTRING_PATTERN.search((SRC / rel).read_text(encoding="utf-8")), rel
