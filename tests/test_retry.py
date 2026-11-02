"""A tool that fails saying a manifest's `retry.when` runs once more with `retry.add`."""

import logging
from pathlib import Path

import pytest

from artifact_engine.config import Config
from artifact_engine.core import runner
from artifact_engine.core.runner import ParserContext, run_parser
from artifact_engine.models import ParserManifest
from artifact_engine.registry import load_parsers

_ABORT = ("Registry hive is dirty and no transaction logs were found in the same "
          "directory! LOGs should have same base name as the hive. Aborting!!")


def _manifest(**extra) -> ParserManifest:
    return ParserManifest(id="art_hive", tool={"binary": "tool.exe"},
                          command=["{binary}", "-f", "{evidence}/SYSTEM", "--csv", "{out}"],
                          **extra)


@pytest.fixture
def tool(tmp_path, monkeypatch):
    """A fake tool that aborts unless given --nl; returns the argv of every call."""
    (tmp_path / "tool.exe").write_bytes(b"")
    calls: list[list[str]] = []

    def fake_run(argv, timeout=None, cwd=None):
        calls.append(list(argv))
        out = Path(argv[argv.index("--csv") + 1])
        if "--nl" not in argv:
            (out / "partial.csv").write_text("a\n", encoding="utf-8")
            return 1, f"Processing hive\n{_ABORT}\n", ""
        (out / "art_hive.csv").write_text("a\n1\n", encoding="utf-8")
        return 0, "", ""

    monkeypatch.setattr(runner.procs, "run", fake_run)
    return calls


def _run(tmp_path, parser):
    out = tmp_path / "CSVs" / "Registry"
    ctx = ParserContext(evidence=tmp_path, out=out, tools=tmp_path, assets=tmp_path,
                        machine_name="HOST-01", volume="C", log=logging.getLogger("aeng.test"))
    return run_parser(parser, ctx, force=True), out


def test_the_failure_it_names_runs_again_with_its_arguments(tmp_path, tool, monkeypatch):
    # as in a pool worker: no handlers, so the run carries its log back
    monkeypatch.setattr(logging.getLogger("aeng"), "handlers", [])
    p = _manifest(retry={"when": "No Transaction Logs were found", "add": ["--nl"]})
    r, out = _run(tmp_path, p)
    assert r.status == "ok"
    assert len(tool) == 2 and tool[1] == tool[0] + ["--nl"]
    # the first run's leftovers do not reach the case
    assert {f.name for f in out.glob("*.csv")} == {"art_hive.csv"}
    # and the run log and the machine report say the logs were not replayed
    assert any("ran again with --nl" in m for _, m in r.logs)
    assert "ran again with --nl" in r.detail


def test_leftovers_that_cannot_be_cleared_fail_the_run(tmp_path, tool, monkeypatch):
    """A first-run file held open (antivirus) must not be merged as the retry's."""
    monkeypatch.setattr(runner.shutil, "rmtree", lambda *a, **k: None)
    p = _manifest(retry={"when": "no transaction logs were found", "add": ["--nl"]})
    r, out = _run(tmp_path, p)
    assert r.status == "error" and "could not clear" in r.detail
    # not retried, and no marker: the next run tries again
    assert len(tool) == 1 and not list(out.glob("*.done"))


def test_a_retry_that_fails_again_says_both(tmp_path, monkeypatch):
    (tmp_path / "tool.exe").write_bytes(b"")
    monkeypatch.setattr(runner.procs, "run", lambda argv, timeout=None, cwd=None:
                        (1, _ABORT if "--nl" not in argv else "", "still broken"))
    p = _manifest(retry={"when": "no transaction logs were found", "add": ["--nl"]})
    r, _ = _run(tmp_path, p)
    assert r.status == "error"
    assert "ran again with --nl" in r.detail and "still broken" in r.detail


def test_any_other_failure_is_not_retried_and_says_why(tmp_path, tool):
    p = _manifest(retry={"when": "some other message", "add": ["--nl"]})
    r, _ = _run(tmp_path, p)
    assert r.status == "error" and len(tool) == 1
    assert "Aborting!!" in r.detail                       # the tool said it on stdout


def test_without_retry_one_run(tmp_path, tool):
    r, _ = _run(tmp_path, _manifest())
    assert r.status == "error" and len(tool) == 1


def test_a_changed_retry_re_parses():
    """A marker a retried run wrote must not outlive a change to the retry."""
    fp = runner.parser_fingerprint
    a = _manifest(retry={"when": "x", "add": ["--nl"]})
    assert fp(a) != fp(_manifest(retry={"when": "x", "add": ["--nl", "true"]}))
    assert fp(a) != fp(_manifest())


def test_bundled_hive_parsers_survive_a_dirty_hive_without_logs():
    """The EZ hive tools abort on a dirty hive with no transaction logs beside it;
    their --nl is added only then, since AppCompatCacheParser's and AmcacheParser's
    ignores logs that ARE there (RECmd's `--nl true` only allows them absent)."""
    ps = {p.id: p for p in load_parsers(Config().parser_dirs)}
    recmd = [p.id for p in ps.values() if p.tool and p.tool.binary.startswith("RECmd/")]
    assert len(recmd) >= 7
    for pid in recmd + ["art_reg_shimcache", "art_amcache"]:
        assert "--nl" not in ps[pid].command, pid
        assert ps[pid].retry.when.lower() in _ABORT.lower(), pid
        assert ps[pid].retry.add == (["--nl", "true"] if pid in recmd else ["--nl"]), pid
