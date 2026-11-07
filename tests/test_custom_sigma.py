"""Custom Sigma rules repository: sync, loaders, and re-run on change."""

from __future__ import annotations

import subprocess
import uuid

from artifact_engine.core import asset_state
from artifact_engine.core.downloader import sync_custom_sigma
from artifact_engine.core.sigma_engine import load_rules
from artifact_engine.core.sigma_windows import load_process_rules
from artifact_engine.registry import load_parsers

LIN = """title: Custom linux rule
id: {id}
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        CommandLine|contains: 'evil-tool-01'
    condition: sel
level: high
"""
WIN = """title: Custom windows rule
id: {id}
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        Image|endswith: 'evil01.exe'
    condition: sel
level: high
"""
WEB = """title: Custom web rule
id: {id}
status: test
logsource:
    category: webserver
detection:
    sel:
        cs-uri-query|contains: 'evil01'
    condition: sel
level: high
"""


def _git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.local",
                    "-C", str(repo), *args], check=True, capture_output=True)


def _put(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text.format(id=uuid.uuid4()), encoding="utf-8")


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _put(repo, "rules/linux/auditd/x.yml", LIN)
    _put(repo, "rules/web/y.yml", WEB)
    _put(repo, "rules/windows/process_creation/z.yml", WIN)
    (repo / "rules/web/notes.txt").write_text("not a rule", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "rules")
    return repo


def test_sync_mirrors_and_withdraws(tmp_path):
    repo = _repo(tmp_path)
    assets, hay = tmp_path / "assets", tmp_path / "hay_rules"
    hay.mkdir()
    s = sync_custom_sigma(str(repo), assets, hay)
    assert s.ok and s.total == 3 and s.added == 3 and s.removed == 0
    assert (assets / "sigma_custom/linux/auditd/x.yml").is_file()
    assert (assets / "sigma_custom/web/y.yml").is_file()
    assert not (assets / "sigma_custom/web/notes.txt").exists()
    assert (hay / "aeng_custom/process_creation/z.yml").is_file()
    assert not (hay / "aeng_custom/linux").exists()

    _git(repo, "rm", "-q", "rules/web/y.yml")
    _git(repo, "commit", "-q", "-m", "withdraw")
    s = sync_custom_sigma(str(repo), assets, hay)
    assert s.ok and s.removed == 1 and s.total == 2
    assert not (assets / "sigma_custom/web/y.yml").exists()
    assert (assets / "sigma_custom/windows/process_creation/z.yml").is_file()
    assert (hay / "aeng_custom/process_creation/z.yml").is_file()

    edited = WIN.replace("evil01.exe", "evil02.exe")
    _put(repo, "rules/windows/process_creation/z.yml", edited)
    _git(repo, "commit", "-q", "-am", "edit")
    s = sync_custom_sigma(str(repo), assets, hay)
    assert s.ok and s.changed and s.modified == 1 and s.added == s.removed == 0
    for d in (assets / "sigma_custom/windows", hay / "aeng_custom"):
        assert "evil02.exe" in (d / "process_creation/z.yml").read_text(encoding="utf-8")

    _git(repo, "rm", "-q", "rules/windows/process_creation/z.yml")
    _git(repo, "commit", "-q", "-m", "withdraw windows")
    s = sync_custom_sigma(str(repo), assets, hay)
    assert s.removed == 1
    assert not (hay / "aeng_custom/process_creation/z.yml").exists()


def test_bad_repo_leaves_mirror(tmp_path):
    repo = _repo(tmp_path)
    assets = tmp_path / "assets"
    assert sync_custom_sigma(str(repo), assets, None).ok
    s = sync_custom_sigma(str(tmp_path / "missing"), assets, None)
    assert not s.ok
    assert (assets / "sigma_custom/linux/auditd/x.yml").is_file()
    fresh = tmp_path / "assets2"
    assert not sync_custom_sigma(str(tmp_path / "missing"), fresh, None).ok
    assert not (fresh / "sigma_custom").exists()


def test_loaders_read_custom(tmp_path):
    load_rules.cache_clear()
    load_process_rules.cache_clear()
    custom = tmp_path / "sigma_custom"
    _put(custom, "linux/auditd/x.yml", LIN)
    _put(custom, "windows/process_creation/z.yml", WIN)
    try:
        assert len(load_rules(custom)) == len(load_rules(None)) + 1
        assert len(load_process_rules(custom)) == len(load_process_rules(None)) + 1
    finally:
        load_rules.cache_clear()
        load_process_rules.cache_clear()


def test_parsers_follow_custom_folder(tmp_path):
    from artifact_engine.config import load_config
    cfg = load_config()
    (tmp_path / "sigma_custom").mkdir()
    parsers = {p.id: p for p in load_parsers(cfg.all_parser_dirs)}
    for i in ("alert_log_sigma", "alert_web", "alert_mem_sigma", "alert_hayabusa_timeline"):
        assert "sigma_custom" in asset_state.used(parsers[i], tmp_path), i


def test_default_is_the_public_repo_and_empty_turns_it_off(tmp_path):
    from artifact_engine.config import SIGMA_RULES_REPO, Config, load_config
    assert Config().sigma_rules_repo == SIGMA_RULES_REPO
    assert SIGMA_RULES_REPO.startswith("https://github.com/")
    cfgfile = tmp_path / "config.yaml"
    cfgfile.write_text('sigma_rules_repo: ""\n', encoding="utf-8")
    assert load_config(cfgfile).sigma_rules_repo == ""


def test_update_row_reports_the_sync(tmp_path, monkeypatch):
    from artifact_engine import cli
    from artifact_engine.config import Config
    from artifact_engine.core import downloader as dl

    repo = _repo(tmp_path)
    for name in ("fetch_yara_rules", "fetch_yara_forge"):
        monkeypatch.setattr(dl, name, lambda *a, **k: dl.RuleSync(ok=True))
    monkeypatch.setattr(dl, "installed_hayabusa_version", lambda t: "1")
    monkeypatch.setattr(dl, "latest_tag", lambda r: "1")
    monkeypatch.setattr(dl, "sync_custom_sigma", sync_custom_sigma)
    monkeypatch.setattr(cli, "load_parsers", lambda dirs: [])
    cfg = Config(assets_dir=tmp_path / "a", tools_dir=tmp_path / "t",
                 sigma_rules_repo=str(repo))
    rows = cli._update_content(cfg, check_only=False, with_tools=False)
    assert ("custom Sigma rules", "updated",
            "3 rule file(s)  (+3 new, -0 withdrawn, ~0 edited)") in rows
    rows = cli._update_content(cfg, check_only=False, with_tools=False)
    assert ("custom Sigma rules", "current", "3 rule file(s)") in rows
    cfg.sigma_rules_repo = ""
    rows = cli._update_content(cfg, check_only=False, with_tools=False)
    assert ("custom Sigma rules", "removed", "sigma_rules_repo is empty") in rows
    assert not (tmp_path / "a/sigma_custom").exists()
    assert not (tmp_path / "a/.sigma_custom_repo").exists()
    rows = cli._update_content(cfg, check_only=False, with_tools=False)
    assert not [r for r in rows if r[0] == "custom Sigma rules"]


def test_failed_fetch_restores_hayabusa_mirror(tmp_path):
    repo = _repo(tmp_path)
    assets, hay = tmp_path / "assets", tmp_path / "hay_rules"
    hay.mkdir()
    assert sync_custom_sigma(str(repo), assets, hay).ok
    import shutil
    shutil.rmtree(hay / "aeng_custom")          # what a hayabusa rules refresh does
    s = sync_custom_sigma(str(tmp_path / "missing"), assets, hay)
    assert not s.ok and s.total == 3
    assert (hay / "aeng_custom/process_creation/z.yml").is_file()
    assert (assets / "sigma_custom/linux/auditd/x.yml").is_file()
