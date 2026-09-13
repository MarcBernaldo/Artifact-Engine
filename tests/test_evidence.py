r"""Resolving a declared path against the tree that is actually on disk.

The defect this guards is the quietest one in the engine: a `requires:` that does
not match means the parser is never SELECTED, so it does not error and does not
run -- it is counted as `skipped`, next to every artifact the host genuinely does
not have. "OK 2 | skipped 37 | errors 0" is what that looks like, and it is also
what a clean triage of a quiet host looks like.

Two kinds of test here, deliberately:

- the ones that assert the same outcome on both platforms, because that IS the
  contract -- a declared path resolves whatever the tree's spelling. On Windows
  they pass through the fast path, on Linux through the component walk, and on
  Linux they fail if the walk is removed.
- the ones that pin the WIRING: that `detector` and `runner` actually go through
  this module. Those bite on every platform, which matters because the tree that
  forgives is the one the suite is usually developed on.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from artifact_engine.core import evidence


@pytest.fixture(autouse=True)
def _clean_cache():
    evidence.forget()
    yield
    evidence.forget()


def _tree(root: Path, *rel: str) -> Path:
    for r in rel:
        p = root / r
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x")
    return root


# --------------------------------------------------------------------------- #
# Reading a declared path
# --------------------------------------------------------------------------- #
def test_a_path_spelled_exactly_as_it_is_on_disk_resolves(tmp_path):
    _tree(tmp_path, "Windows/System32/config/SYSTEM")
    got = evidence.resolve(tmp_path, "Windows/System32/config/SYSTEM")
    assert got == tmp_path / "Windows" / "System32" / "config" / "SYSTEM"


def test_a_path_spelled_differently_from_the_tree_still_resolves(tmp_path):
    """The contract, and the same assertion on both platforms: on NTFS the first
    attempt already answers, on a case-sensitive filesystem the component walk
    does. What must never happen is `None`."""
    _tree(tmp_path, "windows/system32/config/system")
    got = evidence.resolve(tmp_path, "Windows/System32/config/SYSTEM")
    assert got is not None
    assert got.read_bytes() == b"x"


def test_the_real_spelling_is_what_comes_back_not_the_declared_one(tmp_path):
    """The caller hands this to an external tool, which will open it literally."""
    _tree(tmp_path, "windows/System32/CONFIG/system")
    got = evidence.resolve(tmp_path, "Windows/System32/config/SYSTEM")
    assert got is not None and got.exists()
    # Resolved against the tree, so every component is one that is really there.
    rel = got.relative_to(tmp_path).parts
    assert rel == ("windows", "System32", "CONFIG", "system") or os.name == "nt"


def test_an_absent_artifact_is_absent(tmp_path):
    _tree(tmp_path, "Windows/System32/config/SYSTEM")
    assert evidence.resolve(tmp_path, "Windows/AppCompat/Programs/Amcache.hve") is None
    assert not evidence.exists(tmp_path, "Windows/AppCompat/Programs/Amcache.hve")


def test_a_missing_middle_component_stops_the_walk(tmp_path):
    _tree(tmp_path, "Windows/System32/config/SYSTEM")
    assert evidence.resolve(tmp_path, "Windows/Nope/config/SYSTEM") is None


def test_a_file_where_a_directory_was_expected_is_not_a_match(tmp_path):
    _tree(tmp_path, "Windows/System32")
    assert evidence.resolve(tmp_path, "Windows/System32/config/SYSTEM") is None


def test_both_separators_mean_the_same_artifact(tmp_path):
    """Manifests are written with `/` and handlers reach for `\\`."""
    _tree(tmp_path, "Windows/System32/config/SYSTEM")
    assert (evidence.resolve(tmp_path, r"Windows\System32\config\SYSTEM")
            == evidence.resolve(tmp_path, "Windows/System32/config/SYSTEM"))


def test_a_dot_prefix_and_empty_components_are_dropped(tmp_path):
    _tree(tmp_path, "Windows/System32/config/SYSTEM")
    assert evidence.parts_of("./Windows//System32/") == ["Windows", "System32"]
    assert evidence.exists(tmp_path, "./Windows/System32")


def test_a_parent_reference_is_never_resolved_away(tmp_path):
    r"""Nothing in this engine declares `..`, so a manifest that grew one is a
    typo -- and quietly walking it would turn that typo into a read outside the
    volume being parsed."""
    _tree(tmp_path, "Windows/System32/config/SYSTEM")
    (tmp_path.parent / "outside.txt").write_bytes(b"secret")
    assert evidence.parts_of("Windows/../../outside.txt") == [
        "Windows", "..", "..", "outside.txt"]
    assert evidence.resolve(tmp_path, "Windows/../../outside.txt") is None


# --------------------------------------------------------------------------- #
# The guarantees this module makes about the tree
# --------------------------------------------------------------------------- #
def test_resolving_never_writes_anything_into_the_evidence(tmp_path):
    """Phase 1 probes its DESTINATION by creating a file, which is fine in a
    directory being extracted into. The evidence tree is not that, and a
    resolver that leaves a marker in it has contaminated what it was reading."""
    _tree(tmp_path, "Windows/System32/config/SYSTEM", "Users/jdoe/NTUSER.DAT")
    before = {p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*")}

    for rel in ("Windows/System32/config/SYSTEM", "nope/at/all",
                "WINDOWS/system32", "Users/JDOE/ntuser.dat"):
        evidence.resolve(tmp_path, rel)

    assert {p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*")} == before


def test_a_directory_is_read_once_however_many_lookups_miss(tmp_path):
    """A KAPE machine asks about a hundred artifacts, most of them absent. Each
    miss walks; only the first of them may pay for a listing."""
    _tree(tmp_path, "windows/system32/config/system")
    calls: list[str] = []
    real = os.scandir

    def counting(path=".", *a, **k):
        calls.append(str(path))
        return real(path, *a, **k)

    evidence.forget()
    import artifact_engine.core.evidence as mod
    mod.os.scandir = counting
    try:
        for _ in range(5):
            evidence.resolve(tmp_path, "Windows/Nope")
            evidence.resolve(tmp_path, "Windows/Other")
    finally:
        mod.os.scandir = real

    # Listed at most once despite ten misses through it. The first version of
    # this module re-scanned the directory every time a component resolved by
    # case -- which on a consistently lowercased acquisition is every component
    # of every lookup, so the cache it claimed to have did nothing.
    assert calls.count(str(tmp_path)) <= 1


# --------------------------------------------------------------------------- #
# Two spellings of one name, side by side
# --------------------------------------------------------------------------- #
def test_a_declared_path_matching_two_real_files_is_recorded_not_decided_quietly(tmp_path):
    d = tmp_path / "Users" / "jdoe"
    d.mkdir(parents=True)
    (d / "NTUSER.DAT").write_bytes(b"upper")
    try:
        (d / "ntuser.dat").write_bytes(b"lower")
    except OSError:
        pytest.skip("this filesystem folds case")
    if len(list(d.iterdir())) < 2:
        pytest.skip("this filesystem folds case")

    got = evidence.resolve(tmp_path, "Users/jdoe/Ntuser.Dat")

    assert got is not None
    assert "Users/jdoe/Ntuser.Dat" in evidence.ambiguous()
    assert sorted(evidence.ambiguous()["Users/jdoe/Ntuser.Dat"]) == [
        "NTUSER.DAT", "ntuser.dat"]


def test_an_exact_spelling_is_never_ambiguous(tmp_path):
    """Asking for the name that is really there is not a guess, even when a
    sibling differs from it only in case."""
    d = tmp_path / "Users" / "jdoe"
    d.mkdir(parents=True)
    (d / "NTUSER.DAT").write_bytes(b"upper")
    evidence.resolve(tmp_path, "Users/jdoe/NTUSER.DAT")
    assert evidence.ambiguous() == {}


# --------------------------------------------------------------------------- #
# Globs
# --------------------------------------------------------------------------- #
def test_a_glob_matches_whatever_case_the_extension_was_written_in(tmp_path):
    _tree(tmp_path, "drop/Security.EVTX")
    assert evidence.any_match(tmp_path, "**/*.evtx")


def test_a_glob_that_matches_nothing_says_so(tmp_path):
    _tree(tmp_path, "drop/notes.txt")
    assert not evidence.any_match(tmp_path, "**/*.evtx")


def test_the_case_insensitive_pattern_keeps_the_globbing_syntax(tmp_path):
    """Built as character classes rather than by lowercasing and comparing, so
    pathlib's own `**` still means what the profiles rely on."""
    assert evidence._ci_pattern("**/*.evtx") == "**/*.[eE][vV][tT][xX]"
    assert evidence._ci_pattern("$MFT") == "$[mM][fF][tT]"


# --------------------------------------------------------------------------- #
# The wiring: the three surfaces that resolve a declared path
# --------------------------------------------------------------------------- #
# These pin that `detector` and `runner` go THROUGH this module. They matter more
# than they look: on NTFS a direct `base / declared` join works, so every one of
# the tests above passes with the wiring torn out. The tree the suite is usually
# developed on is the one that forgives.
def _spy(monkeypatch):
    seen: list[tuple] = []
    real = evidence.exists

    def watched(root, rel):
        seen.append((Path(root), rel))
        return real(root, rel)

    monkeypatch.setattr(evidence, "exists", watched)
    return seen


def test_parser_selection_resolves_its_requires_through_this_module(tmp_path, monkeypatch):
    from artifact_engine.core.detector import Machine, parsers_for
    from artifact_engine.models import ParserManifest

    _tree(tmp_path, "windows/appcompat/programs/amcache.hve")
    seen = _spy(monkeypatch)
    m = Machine(name="HOST-01", os="windows", collector="kape",
                profile_id="windows_kape", path=tmp_path)
    p = ParserManifest(id="amcache", os="windows", handler="x:y",
                       requires=["Windows/AppCompat/Programs/Amcache.hve"])

    chosen = parsers_for(m, [p])

    assert [x.id for x in chosen] == ["amcache"]
    assert (tmp_path, "Windows/AppCompat/Programs/Amcache.hve") in seen


def test_machine_detection_resolves_its_exists_clause_through_this_module(tmp_path, monkeypatch):
    from artifact_engine.core.detector import _clause_matches
    from artifact_engine.models import DetectClause

    _tree(tmp_path, "uac.log")
    seen = _spy(monkeypatch)

    assert _clause_matches(tmp_path, DetectClause(exists="uac.log"))
    assert (tmp_path, "uac.log") in seen


def test_running_a_parser_resolves_its_requires_through_this_module(tmp_path, monkeypatch):
    """MEASURED: the same KAPE acquisition, OK 61 on Windows and OK 35 on Linux.
    Selection went through this module, but `run_parser` checked `requires` again
    with a direct join, and the tree spelled `winevt/logs` in lower case -- so every
    event-log parser was `skipped: artifact missing`, beside the artifacts the
    host genuinely did not have."""
    from artifact_engine.core import runner
    from artifact_engine.core.runner import ParserContext, run_parser
    from artifact_engine.models import ParserManifest

    _tree(tmp_path, "windows/system32/winevt/logs/Security.evtx")
    seen = _spy(monkeypatch)
    monkeypatch.setattr(runner, "_run_handler", lambda parser, pctx: ("error", "reached"))
    ctx = ParserContext(evidence=tmp_path, out=tmp_path / "o", tools=tmp_path,
                        assets=tmp_path, machine_name="HOST-01", volume="C", log=None)
    p = ParserManifest(id="evtx_security", os="windows", handler="x:y",
                       requires=["Windows/System32/winevt/Logs/Security.evtx"])

    run = run_parser(p, ctx)

    assert (run.status, run.detail) == ("error", "reached")
    assert (tmp_path, "Windows/System32/winevt/Logs/Security.evtx") in seen


def test_a_command_template_is_resolved_against_the_tree(tmp_path):
    """The tail of `{evidence}/...` goes to an EXTERNAL tool, which opens it
    literally -- so substituting the declared spelling hands it a path that is
    not there, on evidence that is."""
    from artifact_engine.core.runner import ParserContext, _fmt

    _tree(tmp_path, "windows/system32/winevt/logs/Security.evtx")
    ctx = ParserContext(evidence=tmp_path, out=tmp_path / "o", tools=tmp_path,
                        assets=tmp_path, machine_name="HOST-01", volume="C",
                        log=None)

    got = _fmt("{evidence}/Windows/System32/winevt/Logs", ctx, None)

    assert Path(got).is_dir()
    assert Path(got) == evidence.resolve(tmp_path, "Windows/System32/winevt/Logs")


def test_a_command_template_for_an_absent_artifact_is_left_alone(tmp_path):
    """The tool's own "no such file" is a better message than anything invented
    here, and inventing one would hide which path it actually wanted."""
    from artifact_engine.core.runner import ParserContext, _fmt

    ctx = ParserContext(evidence=tmp_path, out=tmp_path / "o", tools=tmp_path,
                        assets=tmp_path, machine_name="HOST-01", volume="C",
                        log=None)

    got = _fmt("{evidence}/Windows/AppCompat/Programs/Amcache.hve", ctx, None)

    # Plain substitution, tail untouched -- exactly what it did before there was
    # a resolver at all.
    assert got == str(tmp_path) + "/Windows/AppCompat/Programs/Amcache.hve"


def test_the_other_placeholders_still_substitute(tmp_path):
    from artifact_engine.core.runner import ParserContext, _fmt

    ctx = ParserContext(evidence=tmp_path, out=tmp_path / "o", tools=tmp_path / "t",
                        assets=tmp_path / "a", machine_name="HOST-01", volume="C",
                        log=None)
    assert _fmt("{out}", ctx, None) == str(tmp_path / "o")
    assert _fmt("{machine}", ctx, None) == "HOST-01"
    assert _fmt("--csv", ctx, None) == "--csv"
    assert _fmt("{evidence}", ctx, None) == str(tmp_path)


def test_a_character_class_already_in_the_pattern_is_left_alone(tmp_path):
    r"""`PSRead[Ll]ine` was written by hand in a handler long before this module
    existed. Expanding the letters inside it gives `[[lL][lL]]` -- a different
    pattern, and not one that looks wrong at a glance."""
    assert evidence._ci_pattern("PSRead[Ll]ine") == "[pP][sS][rR][eE][aA][dD][Ll][iI][nN][eE]"


def test_iglob_finds_the_per_user_registry_whatever_case_it_is_in(tmp_path):
    """Three handlers find users with `*/NTUSER.DAT`. On a lowercased tree that
    matched nothing at all -- no error, no empty directory, just a parser
    reporting no users on a machine full of them."""
    _tree(tmp_path, "Users/jdoe/ntuser.dat", "Users/asmith/NTUSER.DAT",
          "Users/bjones/notes.txt")
    hits = evidence.iglob(tmp_path / "Users", "*/NTUSER.DAT")
    assert {p.parent.name for p in hits} == {"jdoe", "asmith"}


def test_iglob_returns_each_file_once_and_in_a_stable_order(tmp_path):
    """The exact pattern and the case-insensitive one both match a correctly
    cased file, and a handler that reports it twice is reporting a duplicate
    artifact."""
    _tree(tmp_path, "Users/asmith/NTUSER.DAT", "Users/jdoe/NTUSER.DAT")
    hits = evidence.iglob(tmp_path / "Users", "*/NTUSER.DAT")
    assert len(hits) == 2
    assert hits == sorted(hits)


def test_iglob_on_a_missing_directory_is_empty_not_an_error(tmp_path):
    assert evidence.iglob(tmp_path / "nope", "*/NTUSER.DAT") == []
