"""`aeng update`: the git guards that protect a working checkout, and the rule
sync that has to remove what upstream withdrew without touching anyone else's files.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from artifact_engine import cli
from artifact_engine.core import downloader as dl


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def test_the_lock_reports_a_binary_whose_hash_moved(tmp_path, caplog):
    """tools.lock.json recorded hashes and was rewritten wholesale every time, so
    a binary whose bytes changed looked exactly like one that had not. Pinning is
    still wrong here -- the EZ tools ship from rolling `latest` URLs and a real
    release would fail every setup -- but a hash that moves has to be SAID: the
    operator knows whether they asked for it and the file cannot."""
    import json

    from artifact_engine import cli as climod

    key = "hayabusa/hayabusa-1.0.0-win-x64.exe"     # _EXTRA_BINARIES globs the subdir
    exe = tmp_path / "hayabusa" / "hayabusa-1.0.0-win-x64.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"original build")
    (tmp_path / "tools.lock.json").write_text(json.dumps({
        key: {"sha256": "0" * 64, "size": 3, "source": "x"},
    }), encoding="utf-8")

    with caplog.at_level("WARNING"):
        climod._write_tools_lock(tmp_path, [])
    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert "changed since the last lock" in msgs, "a moved hash was recorded in silence"
    assert key in msgs

    written = json.loads((tmp_path / "tools.lock.json").read_text(encoding="utf-8"))
    assert written[key]["sha256"] != "0" * 64, "lock not refreshed"


def test_an_unchanged_binary_produces_no_warning(tmp_path, caplog):
    """The report must stay quiet when nothing moved, or it becomes noise the
    analyst learns to scroll past."""
    import json

    from artifact_engine import cli as climod
    from artifact_engine.core.downloader import file_sha256

    exe = tmp_path / "hayabusa" / "hayabusa-1.0.0-win-x64.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"original build")
    (tmp_path / "tools.lock.json").write_text(json.dumps({
        "hayabusa/hayabusa-1.0.0-win-x64.exe": {
            "sha256": file_sha256(exe), "size": exe.stat().st_size, "source": "x"},
    }), encoding="utf-8")

    with caplog.at_level("WARNING"):
        climod._write_tools_lock(tmp_path, [])
    assert "changed since the last lock" not in "\n".join(
        r.getMessage() for r in caplog.records)


def test_the_signature_base_commit_is_parsed_from_the_etag():
    """The rules come from a BRANCH head and the sync deletes what upstream
    withdrew, so without the commit there is no answer to "which version of this
    rule produced this hit, and can you show me its text as it stood that day?"."""
    from artifact_engine.core.downloader import _etag_commit

    sha = "bbcae2453a6f396790272e82a357ba3779950a00"
    assert _etag_commit(f'W/"{sha}"') == sha
    assert _etag_commit(f'"{sha}"') == sha
    assert _etag_commit('W/"not-a-sha"') == ""
    assert _etag_commit("") == ""


def test_max_workers_from_yaml_is_clamped(tmp_path, monkeypatch):
    """A hand-edited config went straight through unchecked, and `_plan_pools` can
    hand back max_workers process workers AND max_workers thread workers in the
    same run -- so the live count reaches twice the number written here. The
    3.10/Windows fault was reproduced around 128."""
    from artifact_engine import config as cfgmod

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("max_workers: 512\n", encoding="utf-8")
    cfg = cfgmod.load_config(cfg_file)
    assert cfg.max_workers == cfgmod.MAX_WORKERS_CEILING, (
        f"512 workers survived the load as {cfg.max_workers}")


def test_a_sane_max_workers_is_left_alone(tmp_path):
    from artifact_engine import config as cfgmod

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("max_workers: 24\n", encoding="utf-8")
    assert cfgmod.load_config(cfg_file).max_workers == 24


def test_the_crash_prone_interpreter_loses_the_process_pool(monkeypatch):
    """The detection existed and only ever printed a warning, leaving the flag
    that avoids the fault for the analyst to find among hundreds of startup
    lines -- for a failure whose whole signature is the run dying with no error
    at all."""
    from artifact_engine import cli as climod
    from artifact_engine.config import Config

    monkeypatch.setattr(climod, "interpreter_risks_memoryview_crash", lambda: True)
    cfg = Config()
    cfg.parse_processes = True
    climod._warn_interpreter(cfg)
    assert cfg.parse_processes is False, "the process pool survived on a known-bad interpreter"


def test_a_healthy_interpreter_keeps_the_process_pool(monkeypatch):
    from artifact_engine import cli as climod
    from artifact_engine.config import Config

    monkeypatch.setattr(climod, "interpreter_risks_memoryview_crash", lambda: False)
    cfg = Config()
    cfg.parse_processes = True
    climod._warn_interpreter(cfg)
    assert cfg.parse_processes is True


def _run(cwd: Path, *args: str) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0",
               GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")
    p = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True,
                       text=True, env=env, check=False)
    return (p.stdout + p.stderr).strip()


def _checkout(tmp_path: Path, version: str = "0.1.0") -> tuple[Path, Path]:
    """An `origin` repo and a clone of it, laid out like a real install."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _run(origin, "init", "-q", "-b", "main")
    pkg = origin / "src" / "artifact_engine"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (origin / "pyproject.toml").write_text(f'version = "{version}"\n', encoding="utf-8")
    _run(origin, "add", "-A")
    _run(origin, "commit", "-qm", "base")

    clone = tmp_path / "clone"
    _run(tmp_path, "clone", "-q", str(origin), str(clone))
    return origin, clone


def _push_upstream(origin: Path, version: str) -> None:
    """A new release lands on origin (committed on its default branch)."""
    (origin / "src" / "artifact_engine" / "__init__.py").write_text(
        f'__version__ = "{version}"\n', encoding="utf-8")
    _run(origin, "add", "-A")
    _run(origin, "commit", "-qm", f"v{version}")


@pytest.fixture
def at_checkout(monkeypatch):
    """Point `_update_engine` at a throwaway clone instead of the real install."""
    def _use(path: Path):
        monkeypatch.setattr(cli, "_install_root", lambda: path)
    return _use


# --------------------------------------------------------------------------- #
# Engine update: the guards
# --------------------------------------------------------------------------- #
def test_an_install_that_is_not_a_checkout_is_reported_not_guessed_at(monkeypatch):
    monkeypatch.setattr(cli, "_install_root", lambda: None)
    status, detail = cli._update_engine(check_only=False)
    assert status == "skipped"
    assert "not a git checkout" in detail


def test_uncommitted_work_stops_the_update_and_nothing_is_touched(tmp_path, at_checkout):
    origin, clone = _checkout(tmp_path)
    _push_upstream(origin, "0.2.0")
    scratch = clone / "src" / "artifact_engine" / "notes.py"
    scratch.write_text("# work in progress\n", encoding="utf-8")
    at_checkout(clone)

    status, detail = cli._update_engine(check_only=False)

    assert status == "blocked"
    assert "uncommitted change" in detail
    assert cli._disk_version(clone) == "0.1.0", "the checkout must not have moved"
    assert scratch.read_text(encoding="utf-8") == "# work in progress\n"


def test_local_commits_are_never_silently_overwritten(tmp_path, at_checkout):
    origin, clone = _checkout(tmp_path)
    _push_upstream(origin, "0.2.0")
    (clone / "mine.txt").write_text("local\n", encoding="utf-8")
    _run(clone, "add", "-A")
    _run(clone, "commit", "-qm", "local work")
    _run(clone, "fetch", "-q", "origin")
    at_checkout(clone)

    status, detail = cli._update_engine(check_only=False)

    assert status == "blocked"
    assert "not on origin" in detail
    assert (clone / "mine.txt").is_file()


def test_a_detached_head_is_refused(tmp_path, at_checkout):
    _origin, clone = _checkout(tmp_path)
    _run(clone, "checkout", "-q", "--detach", "HEAD")
    at_checkout(clone)

    status, detail = cli._update_engine(check_only=False)

    assert status == "blocked"
    assert "detached" in detail


def test_a_clean_checkout_fast_forwards_and_reports_the_version_move(tmp_path, at_checkout):
    origin, clone = _checkout(tmp_path)
    _push_upstream(origin, "0.2.0")
    at_checkout(clone)

    status, detail = cli._update_engine(check_only=False)

    assert status == "updated"
    assert "v0.1.0 -> v0.2.0" in detail
    assert cli._disk_version(clone) == "0.2.0"


def test_check_only_reports_what_is_pending_without_moving_anything(tmp_path, at_checkout):
    origin, clone = _checkout(tmp_path)
    _push_upstream(origin, "0.2.0")
    at_checkout(clone)

    status, detail = cli._update_engine(check_only=True)

    assert status == "available"
    assert "1 commit(s) behind" in detail
    assert cli._disk_version(clone) == "0.1.0", "--check must not change the checkout"


def test_an_up_to_date_checkout_says_so(tmp_path, at_checkout):
    _origin, clone = _checkout(tmp_path)
    at_checkout(clone)

    status, detail = cli._update_engine(check_only=False)

    assert status == "current"
    assert "up to date" in detail


def test_a_dependency_change_asks_for_the_reinstall_it_will_not_do_itself(tmp_path, at_checkout):
    origin, clone = _checkout(tmp_path)
    (origin / "pyproject.toml").write_text('version = "0.2.0"\ndeps = ["new"]\n', encoding="utf-8")
    _push_upstream(origin, "0.2.0")
    at_checkout(clone)

    status, detail = cli._update_engine(check_only=False)

    assert status == "updated"
    assert "pip install -e ." in detail


# --------------------------------------------------------------------------- #
# Rule sync
# --------------------------------------------------------------------------- #
def _fake_sigbase(monkeypatch, names: list[str]):
    """Stand in for the signature-base zip so the sync can be tested offline."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n in names:
            zf.writestr(f"signature-base-master/yara/{n}", f"rule R_{n.split('.')[0]} {{ }}")

    class _Resp:
        content = buf.getvalue()

        def __init__(self):
            # codeload returns the commit in the ETag; without it the sync falls
            # back to an API call, which in a test would be a real network request.
            self.headers = {"ETag": 'W/"bbcae2453a6f396790272e82a357ba3779950a00"'}

        def raise_for_status(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: _Resp())


def test_a_rule_upstream_withdrew_does_not_survive_the_sync(tmp_path, monkeypatch):
    _fake_sigbase(monkeypatch, ["apt_a.yar", "apt_b.yar"])
    first = dl.fetch_yara_rules(tmp_path)
    assert (first.total, first.added, first.removed) == (2, 2, 0)

    _fake_sigbase(monkeypatch, ["apt_a.yar"])          # apt_b retired upstream
    second = dl.fetch_yara_rules(tmp_path)

    sig = tmp_path / "yara" / "signature-base"
    assert (second.total, second.added, second.removed) == (1, 0, 1)
    assert not (sig / "apt_b.yar").exists(), "a withdrawn rule keeps firing if it is left"
    assert (sig / "apt_a.yar").exists()


def test_the_sync_never_deletes_a_rule_the_analyst_put_there(tmp_path, monkeypatch):
    _fake_sigbase(monkeypatch, ["apt_a.yar"])
    dl.fetch_yara_rules(tmp_path)
    sig = tmp_path / "yara" / "signature-base"
    mine = sig / "my_hunt.yar"
    mine.write_text("rule Mine { condition: true }", encoding="utf-8")

    _fake_sigbase(monkeypatch, [])                      # upstream returns nothing usable
    dl.fetch_yara_rules(tmp_path)

    assert mine.is_file(), "only files a previous sync wrote may be removed"


def test_an_unchanged_ruleset_is_reported_as_unchanged(tmp_path, monkeypatch):
    _fake_sigbase(monkeypatch, ["apt_a.yar", "apt_b.yar"])
    dl.fetch_yara_rules(tmp_path)
    again = dl.fetch_yara_rules(tmp_path)

    assert again.ok and not again.changed
    assert (again.added, again.removed) == (0, 0)


def test_the_manifest_only_claims_what_the_sync_wrote(tmp_path, monkeypatch):
    _fake_sigbase(monkeypatch, ["apt_a.yar"])
    dl.fetch_yara_rules(tmp_path)
    manifest = tmp_path / "yara" / "signature-base" / dl._SIGBASE_MANIFEST
    assert json.loads(manifest.read_text(encoding="utf-8"))["files"] == ["apt_a.yar"]


def test_the_manifest_records_which_commit_the_rules_came_from(tmp_path, monkeypatch):
    """The rules come from a branch head and the sync deletes what upstream
    withdrew, so a hit months later cannot otherwise be traced to a rule version
    -- the rule may have been removed by the sync itself."""
    _fake_sigbase(monkeypatch, ["apt_a.yar"])
    sync = dl.fetch_yara_rules(tmp_path)
    manifest = tmp_path / "yara" / "signature-base" / dl._SIGBASE_MANIFEST
    data = json.loads(manifest.read_text(encoding="utf-8"))

    assert data["commit"] == "bbcae2453a6f396790272e82a357ba3779950a00"
    assert data["repo"] == "Neo23x0/signature-base"
    assert data["retrieved_utc"].endswith("Z")
    assert sync.commit == data["commit"]


def test_a_pre_provenance_manifest_is_still_understood(tmp_path, monkeypatch):
    """Manifests written before provenance existed are a bare list. Misreading one
    would make every rule look new and delete nothing that was withdrawn."""
    sig = tmp_path / "yara" / "signature-base"
    sig.mkdir(parents=True)
    (sig / dl._SIGBASE_MANIFEST).write_text(json.dumps(["apt_a.yar", "apt_old.yar"]),
                                            encoding="utf-8")
    (sig / "apt_old.yar").write_text("rule Old { }", encoding="utf-8")

    _fake_sigbase(monkeypatch, ["apt_a.yar"])
    sync = dl.fetch_yara_rules(tmp_path)

    assert (sync.added, sync.removed) == (0, 1), "the old manifest was not read"
    assert not (sig / "apt_old.yar").exists()


# --------------------------------------------------------------------------- #
# Version comparison
# --------------------------------------------------------------------------- #
def test_a_matching_version_is_not_downloaded_again():
    calls = []
    row = cli._bump("hayabusa", "3.10.0", "3.10.0", False, lambda: calls.append(1) or True)
    assert row == ("hayabusa", "current", "3.10.0")
    assert not calls, "nothing to fetch when the installed version already matches"


def test_an_unknown_local_version_counts_as_out_of_date():
    row = cli._bump("chainsaw", "", "2.16.2", False, lambda: True)
    assert row[1] == "updated"
    assert "unknown -> 2.16.2" in row[2]


def test_check_mode_compares_but_never_fetches():
    calls = []
    row = cli._bump("hayabusa", "3.9.0", "3.10.0", True, lambda: calls.append(1) or True)
    assert row == ("hayabusa", "available", "3.9.0 -> 3.10.0")
    assert not calls


def test_an_unreadable_upstream_is_a_failure_not_a_silent_skip():
    row = cli._bump("hayabusa", "3.9.0", "", False, lambda: True)
    assert row[1] == "failed"
    assert "3.9.0" in row[2]


def test_a_failed_download_is_reported_as_failed():
    row = cli._bump("chainsaw", "2.16.0", "2.16.2", False, lambda: False)
    assert row[1] == "failed"


def test_digest_tells_absent_from_present(tmp_path):
    f = tmp_path / "x.bin"
    assert cli._digest(f) == ""
    f.write_bytes(b"abc")
    assert cli._digest(f) not in ("", None)


# --------------------------------------------------------------------------- #
# The interpreter is part of the report
# --------------------------------------------------------------------------- #
def test_the_risky_interpreter_is_reported_as_pending_not_as_all_clear(monkeypatch, caplog, tmp_path):
    monkeypatch.setattr(cli, "interpreter_risks_memoryview_crash", lambda: True)
    monkeypatch.setattr(cli, "_update_engine", lambda check_only: ("current", "up to date"))
    monkeypatch.setattr(cli, "_update_content", lambda *a, **k: [("rules", "current", "x")])
    args = argparse.Namespace(check=True, tools=False, config=None)

    with caplog.at_level("INFO", logger="aeng"):
        rc = cli.cmd_update(args)

    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert rc == 0
    assert "at risk" in msgs
    assert "end a RUN with no error" in msgs
    assert "1 pending" in msgs, "an at-risk interpreter must not be counted as fine"


def test_a_healthy_interpreter_adds_no_noise(monkeypatch, caplog):
    monkeypatch.setattr(cli, "interpreter_risks_memoryview_crash", lambda: False)
    monkeypatch.setattr(cli, "_update_engine", lambda check_only: ("current", "up to date"))
    monkeypatch.setattr(cli, "_update_content", lambda *a, **k: [("rules", "current", "x")])
    args = argparse.Namespace(check=True, tools=False, config=None)

    with caplog.at_level("INFO", logger="aeng"):
        cli.cmd_update(args)

    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert "at risk" not in msgs
    assert "0 pending" in msgs


# --------------------------------------------------------------------------- #
# The right-click menu must not freeze in a bad interpreter
# --------------------------------------------------------------------------- #
class _FakeKey:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeWinreg:
    """Stands in for `winreg` and records what WOULD have been written.

    Not optional politeness: `cmd_install_menu` writes to HKCU for real, and a
    test that exercises the success path without this leaves a shell integration
    on the machine that ran the suite.
    """

    HKEY_CURRENT_USER = 0
    REG_SZ = 1
    REG_EXPAND_SZ = 2

    def __init__(self):
        self.writes: list[tuple] = []

    def CreateKey(self, _root, path):
        self.writes.append(("CreateKey", path))
        return _FakeKey()

    def SetValueEx(self, _key, name, _r, _t, value):
        self.writes.append(("SetValueEx", name, value))


@pytest.fixture
def fake_registry(monkeypatch):
    import sys as _sys
    fake = _FakeWinreg()
    monkeypatch.setitem(_sys.modules, "winreg", fake)
    monkeypatch.setattr(cli, "_require_windows", lambda: True)
    return fake


def test_the_menu_refuses_to_freeze_in_an_interpreter_that_kills_runs(
        monkeypatch, caplog, fake_registry):
    monkeypatch.setattr(cli, "interpreter_risks_memoryview_crash", lambda: True)

    with caplog.at_level("ERROR", logger="aeng"):
        rc = cli.cmd_install_menu(argparse.Namespace(force=False))

    assert rc == 1
    assert not fake_registry.writes, "nothing may reach the registry"
    assert "refusing to register" in "\n".join(r.getMessage() for r in caplog.records)


def test_force_still_lets_you_register_it(monkeypatch, caplog, fake_registry):
    monkeypatch.setattr(cli, "interpreter_risks_memoryview_crash", lambda: True)

    with caplog.at_level("ERROR", logger="aeng"):
        rc = cli.cmd_install_menu(argparse.Namespace(force=True))

    assert rc == 0, "--force is the documented override"
    assert fake_registry.writes, "with --force it does register"
    assert "refusing" not in "\n".join(r.getMessage() for r in caplog.records)


def test_a_healthy_interpreter_registers_without_a_flag(monkeypatch, fake_registry):
    monkeypatch.setattr(cli, "interpreter_risks_memoryview_crash", lambda: False)

    rc = cli.cmd_install_menu(argparse.Namespace(force=False))

    assert rc == 0
    commands = [v for kind, name, v in
                (w for w in fake_registry.writes if w[0] == "SetValueEx") if name == ""]
    assert any("-m artifact_engine run" in c for c in commands if "cmd /k" in c)


# --------------------------------------------------------------------------- #
# Which config a run used, and where it was found
# --------------------------------------------------------------------------- #
def _fake_checkout(tmp_path, monkeypatch, body: str):
    """A tool folder laid out like a real checkout, with `body` as its config."""
    from artifact_engine import config as cfgmod

    tool = tmp_path / "tool"
    (tool / "src" / "artifact_engine").mkdir(parents=True)
    (tool / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    if body is not None:
        (tool / "config.yaml").write_text(body, encoding="utf-8")
    monkeypatch.setattr(cfgmod, "PACKAGE_DIR", tool / "src" / "artifact_engine")
    return tool


def test_load_config_records_every_file_it_read(tmp_path):
    from artifact_engine.config import load_config

    cfg = load_config(tmp_path / "nope.yaml")
    assert cfg.sources == [], "nothing read -> no sources"

    f = tmp_path / "config.yaml"
    f.write_text("avoid_vss: false\nemit_xlsx: false\n", encoding="utf-8")
    cfg = load_config(f)
    assert cfg.sources == [f]
    assert cfg.avoid_vss is False and cfg.emit_xlsx is False


def test_the_config_beside_the_tool_is_found_from_anywhere(tmp_path, monkeypatch):
    """The whole point: launched from a case folder -- or the right-click menu,
    where the working directory is not yours at all -- the tool's own settings
    must still apply instead of silently falling back to the defaults."""
    from artifact_engine import config as cfgmod

    tool = _fake_checkout(tmp_path, monkeypatch, "avoid_vss: false\nmax_workers: 32\n")
    case = tmp_path / "case"
    case.mkdir()
    monkeypatch.chdir(case)

    cfg = cfgmod.load_config()

    assert cfg.avoid_vss is False, "the tool's config must be found from a case folder"
    assert cfg.max_workers == 32
    assert cfg.sources == [tool / "config.yaml"]


def test_a_config_in_the_current_directory_still_wins(tmp_path, monkeypatch):
    from artifact_engine import config as cfgmod

    _fake_checkout(tmp_path, monkeypatch, "avoid_vss: false\nemit_xlsx: false\n")
    case = tmp_path / "case"
    case.mkdir()
    (case / "config.yaml").write_text("emit_xlsx: true\n", encoding="utf-8")
    monkeypatch.chdir(case)

    cfg = cfgmod.load_config()

    assert cfg.emit_xlsx is True, "the per-case file overrides"
    assert cfg.avoid_vss is False, "and inherits what it does not mention"
    assert len(cfg.sources) == 2, "both are recorded, not just the winner"


def test_running_from_the_checkout_applies_its_config_once(tmp_path, monkeypatch):
    from artifact_engine import config as cfgmod

    tool = _fake_checkout(tmp_path, monkeypatch, "avoid_vss: false\n")
    monkeypatch.chdir(tool)

    cfg = cfgmod.load_config()

    assert len(cfg.sources) == 1, "cwd and the tool folder are the same file here"
    assert cfg.avoid_vss is False


def test_an_installed_wheel_does_not_adopt_a_random_parent_folder(tmp_path, monkeypatch):
    """Without a pyproject beside it the engine is not in a checkout, so nothing
    above `site-packages` may be mistaken for the tool's own config."""
    from artifact_engine import config as cfgmod

    site = tmp_path / "site-packages"
    (site / "artifact_engine").mkdir(parents=True)
    (tmp_path / "config.yaml").write_text("avoid_vss: false\n", encoding="utf-8")
    monkeypatch.setattr(cfgmod, "PACKAGE_DIR", site / "artifact_engine")
    case = tmp_path / "case"
    case.mkdir()
    monkeypatch.chdir(case)

    cfg = cfgmod.load_config()

    assert cfg.sources == []
    assert cfg.avoid_vss is True, "untouched default"


def test_the_log_names_the_config_or_says_it_is_using_defaults(tmp_path, monkeypatch, caplog):
    from artifact_engine import config as cfgmod

    _fake_checkout(tmp_path, monkeypatch, None)          # a checkout with no config
    case = tmp_path / "case"
    case.mkdir()
    monkeypatch.chdir(case)

    with caplog.at_level("INFO", logger="aeng"):
        cli._log_config(cfgmod.load_config())
    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert "built-in defaults" in msgs, "silent defaulting is the bug being fixed"
    assert str(case) in msgs, "say WHERE it looked"

    caplog.clear()
    f = case / "config.yaml"
    f.write_text("avoid_vss: false\n", encoding="utf-8")
    with caplog.at_level("INFO", logger="aeng"):
        cli._log_config(cfgmod.load_config())
    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert str(f) in msgs
    assert "built-in defaults" not in msgs


def test_the_log_shows_both_files_when_they_layer(tmp_path, monkeypatch, caplog):
    from artifact_engine import config as cfgmod

    tool = _fake_checkout(tmp_path, monkeypatch, "avoid_vss: false\n")
    case = tmp_path / "case"
    case.mkdir()
    (case / "config.yaml").write_text("emit_xlsx: false\n", encoding="utf-8")
    monkeypatch.chdir(case)

    with caplog.at_level("INFO", logger="aeng"):
        cli._log_config(cfgmod.load_config())

    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert str(tool / "config.yaml") in msgs
    assert str(case / "config.yaml") in msgs, "naming only the winner hides half of it"


def test_the_log_carries_the_flags_that_change_what_gets_parsed(caplog):
    from artifact_engine.config import Config

    cfg = Config(avoid_vss=False, merge_vss=True, emit_xlsx=False, max_workers=32)
    with caplog.at_level("INFO", logger="aeng"):
        cli._log_config(cfg)

    msgs = "\n".join(r.getMessage() for r in caplog.records)
    for expected in ("workers 32", "avoid_vss false", "merge_vss true", "xlsx false"):
        assert expected in msgs, f"missing {expected!r}"


# --------------------------------------------------------------------------- #
# `aeng setup`: the only command that had no test, and the one whose internals
# changed when fetch_yara_rules started returning a RuleSync instead of an int.
# --------------------------------------------------------------------------- #
@pytest.fixture
def offline_setup(monkeypatch, tmp_path):
    """`cmd_setup` with every download stubbed out, recording what it asked for."""
    from artifact_engine.core import downloader as dlmod

    calls: dict[str, object] = {}
    monkeypatch.setattr(dlmod, "fetch_tool",
                        lambda tool, tools_dir, **k: calls.setdefault("tools", []).append(
                            tool.binary) or True)
    monkeypatch.setattr(dlmod, "fetch_web_assets",
                        lambda assets_dir, force=False: calls.setdefault("assets", assets_dir) and 3)
    monkeypatch.setattr(dlmod, "fetch_yara_rules",
                        lambda assets_dir: dlmod.RuleSync(total=7, added=7, ok=True))
    monkeypatch.setattr(dlmod, "fetch_hayabusa",
                        lambda tools_dir, force=False: calls.setdefault("hayabusa", True))
    return calls


def test_setup_completes_and_reports_the_rule_count(tmp_path, monkeypatch, caplog,
                                                    offline_setup):
    """Regression guard: fetch_yara_rules returns a RuleSync now, and setup has to
    read `.total` off it. Formatting the object itself would not raise -- it would
    just print a dataclass repr into the summary line."""
    from artifact_engine import cli
    from artifact_engine import config as cfgmod

    tool = tmp_path / "tool"
    (tool / "src" / "artifact_engine").mkdir(parents=True)
    (tool / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    monkeypatch.setattr(cfgmod, "PACKAGE_DIR", tool / "src" / "artifact_engine")
    monkeypatch.chdir(tmp_path)

    with caplog.at_level("INFO", logger="aeng"):
        rc = cli.cmd_setup(argparse.Namespace())

    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert rc == 0
    assert "7 yara rule file(s)" in msgs, "the count must be the number, not a repr"
    assert "RuleSync(" not in msgs


def test_setup_writes_the_config_where_the_engine_will_find_it(tmp_path, monkeypatch,
                                                               offline_setup):
    """Written beside the tool, not in the directory setup happened to run from --
    otherwise `aeng setup` in a case folder produces settings every later run
    ignores."""
    from artifact_engine import cli
    from artifact_engine import config as cfgmod

    tool = tmp_path / "tool"
    (tool / "src" / "artifact_engine").mkdir(parents=True)
    (tool / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    monkeypatch.setattr(cfgmod, "PACKAGE_DIR", tool / "src" / "artifact_engine")
    elsewhere = tmp_path / "some_case"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    cli.cmd_setup(argparse.Namespace())

    assert (tool / "config.yaml").is_file(), "beside the tool"
    assert not (elsewhere / "config.yaml").exists(), "not where setup was launched"
    # and what it wrote is loadable from anywhere
    assert cfgmod.load_config().sources == [tool / "config.yaml"]


def test_setup_never_overwrites_settings_that_are_already_there(tmp_path, monkeypatch,
                                                               offline_setup):
    from artifact_engine import cli
    from artifact_engine import config as cfgmod

    tool = tmp_path / "tool"
    (tool / "src" / "artifact_engine").mkdir(parents=True)
    (tool / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    mine = tool / "config.yaml"
    mine.write_text("avoid_vss: false\nmax_workers: 99\n", encoding="utf-8")
    monkeypatch.setattr(cfgmod, "PACKAGE_DIR", tool / "src" / "artifact_engine")
    monkeypatch.chdir(tmp_path)

    cli.cmd_setup(argparse.Namespace())

    assert mine.read_text(encoding="utf-8") == "avoid_vss: false\nmax_workers: 99\n"


def test_an_installed_wheel_still_gets_its_config_in_the_working_folder(tmp_path,
                                                                       monkeypatch,
                                                                       offline_setup):
    """No checkout means no tool folder, so the cwd is the only sensible place."""
    from artifact_engine import cli
    from artifact_engine import config as cfgmod

    site = tmp_path / "site-packages" / "artifact_engine"
    site.mkdir(parents=True)
    monkeypatch.setattr(cfgmod, "PACKAGE_DIR", site)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)

    cli.cmd_setup(argparse.Namespace())

    assert (work / "config.yaml").is_file()


# --------------------------------------------------------------------------- #
# assets_dir, like tools_dir, is relocatable
# --------------------------------------------------------------------------- #
def test_assets_dir_can_be_moved_off_the_system_disk(tmp_path, monkeypatch):
    from artifact_engine import config as cfgmod

    monkeypatch.chdir(tmp_path)
    elsewhere = tmp_path / "D_drive" / "aeng-assets"
    (tmp_path / "config.yaml").write_text(
        f"assets_dir: {elsewhere.as_posix()}\ntools_dir: {(tmp_path / 'bin').as_posix()}\n",
        encoding="utf-8")

    cfg = cfgmod.load_config()

    assert cfg.assets_dir == elsewhere
    assert cfg.tools_dir == tmp_path / "bin"


def test_assets_dir_left_alone_keeps_the_bundled_location(tmp_path, monkeypatch):
    from artifact_engine import config as cfgmod

    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("max_workers: 2\n", encoding="utf-8")

    assert cfgmod.load_config().assets_dir == cfgmod.DATA_DIR / "assets"
