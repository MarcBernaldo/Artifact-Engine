"""The fork of SigmaHQ adapted to the engine's tables (v0.7.194): sync and use."""

from __future__ import annotations

import subprocess
import uuid

from artifact_engine.core import asset_state
from artifact_engine.core.downloader import drop_disk_sigma, sync_disk_sigma
from artifact_engine.core.sigma_wincat import load_category
from artifact_engine.registry import load_parsers

RULE = """title: {title}
id: {id}
status: test
logsource:
    product: windows
    category: {category}
detection:
    sel:
        {field}|endswith: '{value}'
    condition: sel
level: high
"""


def _git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.local",
                    "-C", str(repo), *args], check=True, capture_output=True)


def _put(root, rel, title, category, field, value):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(RULE.format(title=title, id=uuid.uuid4(), category=category, field=field,
                             value=value), encoding="utf-8")


def _hayabusa(root, rel, title, category, field, value):
    """hayabusa's converted copy: a channel selection wrapping the condition."""
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(RULE.format(title=title, id=uuid.uuid4(), category=category, field=field,
                             value=value).replace(
        "    condition: sel",
        "    ev:\n        Channel: Microsoft-Windows-Sysmon/Operational\n"
        "    condition: ev and sel"), encoding="utf-8")


def _fork(tmp_path):
    """A SigmaHQ-shaped repository: master as SigmaHQ wrote it, `aeng` with an
    adaptation and a folder alert_win_sigma does not read."""
    repo = tmp_path / "fork"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "master")
    _put(repo, "rules/windows/file/file_event/a.yml", "Original", "file_event",
         "TargetFilename", "\\original.txt")
    _put(repo, "rules/windows/image_load/i.yml", "Image Load", "image_load",
         "ImageLoaded", "\\x.dll")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "upstream")
    _git(repo, "checkout", "-q", "-b", "aeng")
    _put(repo, "rules/windows/file/file_event/a.yml", "Adapted", "file_event",
         "TargetFilename", "\\adapted.txt")
    _put(repo, "rules/windows/process_creation/p.yml", "Proc", "process_creation",
         "Image", "\\evil.exe")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "adapt")
    return repo


def test_the_branch_is_mirrored_with_only_the_folders_the_parser_reads(tmp_path):
    repo = _fork(tmp_path)
    assets = tmp_path / "assets"
    r = sync_disk_sigma(str(repo), "aeng", assets)
    assert (r.ok, r.total, r.added) == (True, 2, 2)
    files = sorted(p.relative_to(assets / "sigma_disk").as_posix()
                   for p in (assets / "sigma_disk").rglob("*.yml"))
    assert files == ["file/file_event/a.yml", "process_creation/p.yml"]
    assert "Adapted" in (assets / "sigma_disk" / "file/file_event/a.yml").read_text("utf-8")

    _git(repo, "rm", "-q", "rules/windows/process_creation/p.yml")
    _git(repo, "commit", "-q", "-m", "withdraw")
    r = sync_disk_sigma(str(repo), "aeng", assets)
    assert (r.ok, r.total, r.removed) == (True, 1, 1)
    assert not (assets / "sigma_disk" / "process_creation").exists()


def test_a_git_failure_keeps_the_last_rules_and_says_so(tmp_path):
    repo = _fork(tmp_path)
    assets = tmp_path / "assets"
    sync_disk_sigma(str(repo), "aeng", assets)
    r = sync_disk_sigma(str(tmp_path / "gone"), "aeng", assets)
    assert not r.ok and r.total == 2
    assert (assets / "sigma_disk" / "file/file_event/a.yml").is_file()
    assert drop_disk_sigma(assets)
    assert not (assets / "sigma_disk").exists() and not (assets / ".sigma_disk_repo").exists()


def test_the_fork_replaces_hayabusas_copy_for_its_categories(tmp_path):
    disk = tmp_path / "sigma_disk"
    _put(disk, "file/file_event/a.yml", "Adapted", "file_event", "TargetFilename",
         "\\adapted.txt")
    haya = tmp_path / "haya"
    _hayabusa(haya, "file/file_event/h.yml", "From Hayabusa", "file_event", "TargetFilename",
         "\\h.txt")
    load_category.cache_clear()
    try:
        titles = [r.title for r in load_category("file_event", None, haya, disk).rules]
        assert titles == ["Adapted"]
        # a category the fork does not hold still comes from hayabusa
        _hayabusa(haya, "registry/registry_set/r.yml", "Reg", "registry_set", "TargetObject",
             "\\Run\\x")
        assert [r.title for r in load_category("registry_set", None, haya, disk).rules] \
            == ["Reg"]
        proc = load_category("process_creation", None, None, disk).rules
        assert proc == ()
    finally:
        load_category.cache_clear()


def test_alert_win_sigma_reruns_when_the_fork_changes():
    from artifact_engine.config import DATA_DIR
    parser = {p.id: p for p in load_parsers([DATA_DIR / "parsers"])}["alert_win_sigma"]
    assert b"sigma_disk" in asset_state._tokens(parser)


def test_the_forks_own_files_are_mirrored_beside_the_rules(tmp_path):
    repo = _fork(tmp_path)
    (repo / "aeng").mkdir()
    (repo / "aeng" / "not-adaptable.txt").write_text("id-1  rules/x.yml  why\n", "utf-8")
    (repo / "aeng" / "registry_baseline.tsv").write_text("HKLM\\X\tDWORD (0x00000000)\n",
                                                         "utf-8")
    (repo / "aeng" / "notes.md").write_text("not for the engine", "utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "aeng files")
    assets = tmp_path / "assets"
    assert sync_disk_sigma(str(repo), "aeng", assets).ok
    aeng = assets / "sigma_disk" / "aeng"
    assert sorted(p.name for p in aeng.iterdir()) == ["not-adaptable.txt",
                                                      "registry_baseline.tsv"]
    _git(repo, "rm", "-q", "aeng/registry_baseline.tsv")
    _git(repo, "commit", "-q", "-m", "drop baseline")
    assert sync_disk_sigma(str(repo), "aeng", assets).ok
    assert not (aeng / "registry_baseline.tsv").exists()


WEB_RULE = """title: {title}
id: {id}
status: test
logsource:
    category: webserver
detection:
    sel:
        cs-uri-query|contains: '{value}'
    condition: sel
level: high
"""


def _web(root, rel, title, value, rule_id=None):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(WEB_RULE.format(title=title, id=rule_id or uuid.uuid4(), value=value),
                 encoding="utf-8")


def test_the_forks_web_rules_are_mirrored_apart_with_their_own_not_adaptable(tmp_path):
    repo = _fork(tmp_path)
    _web(repo, "rules/web/webserver_generic/w.yml", "Web", "../etc/passwd")
    (repo / "aeng").mkdir()
    (repo / "aeng" / "not-adaptable.txt").write_text(
        "# header\nid-win  rules/windows/file/x.yml  why\nid-web  rules/web/webserver_generic/y.yml  why\n",
        "utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "web")
    assets = tmp_path / "assets"
    r = sync_disk_sigma(str(repo), "aeng", assets)
    assert (r.ok, r.total, r.added) == (True, 3, 3)
    web = assets / "sigma_disk_web"
    assert [p.relative_to(web).as_posix() for p in web.rglob("*.yml")] \
        == ["webserver_generic/w.yml"]
    assert not list((assets / "sigma_disk").rglob("w.yml"))
    # only the web line: a Windows entry changes nothing alert_web reads
    assert (web / "aeng" / "not-adaptable.txt").read_text("utf-8") \
        == "id-web  rules/web/webserver_generic/y.yml  why\n"

    _git(repo, "rm", "-q", "-r", "rules/web")
    _git(repo, "commit", "-q", "-m", "no web")
    r = sync_disk_sigma(str(repo), "aeng", assets)
    assert (r.ok, r.total, r.removed) == (True, 2, 1)
    assert not web.exists()
    sync_disk_sigma(str(repo), "aeng", assets)
    _web(repo, "rules/web/webserver_generic/w.yml", "Web", "x")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "web again")
    sync_disk_sigma(str(repo), "aeng", assets)
    assert drop_disk_sigma(assets) and not web.exists()


def test_alert_web_reads_the_fork_less_its_not_adaptable_else_the_bundled_copy(tmp_path):
    from artifact_engine.core import sigma_engine
    fork = tmp_path / "sigma_disk_web"
    keep, skip = str(uuid.uuid4()), str(uuid.uuid4())
    _web(fork, "webserver_generic/a.yml", "Fork Rule", "aaa", keep)
    _web(fork, "webserver_generic/b.yml", "Not Adaptable", "bbb", skip)
    (fork / "aeng").mkdir()
    (fork / "aeng" / "not-adaptable.txt").write_text(
        f"{skip}  rules/web/webserver_generic/b.yml  noise\n", "utf-8")
    sigma_engine.load_web_rules.cache_clear()
    try:
        titles = {r.title for r in sigma_engine.load_web_rules(None, fork)}
        assert titles == {"Fork Rule"}
        sigma_engine.load_web_rules.cache_clear()
        bundled = {r.title for r in sigma_engine.load_web_rules(None, tmp_path / "empty")}
        assert bundled and "Fork Rule" not in bundled
    finally:
        sigma_engine.load_web_rules.cache_clear()


def test_alert_web_reruns_on_the_forks_web_rules_only():
    from artifact_engine.config import DATA_DIR
    from artifact_engine.core import downloader
    from artifact_engine.handlers import lin_web_sigma
    assert downloader.DISK_WEB_DIR == lin_web_sigma.DISK_WEB_DIR
    parsers = {p.id: p for p in load_parsers([DATA_DIR / "parsers"])}
    web = asset_state._tokens(parsers["alert_web"])
    assert b"sigma_disk_web" in web and b"sigma_disk" not in web
    assert b"sigma_disk_web" not in asset_state._tokens(parsers["alert_win_sigma"])


def test_scanner_ua_covers_sigmahqs_recon_tool_user_agents():
    """The fork lists SigmaHQ's recon-tool UA rule not-adaptable (v0.7.198): every
    tool it names must be in web_suspicious.txt's scanner_ua, with its real UA."""
    from artifact_engine.config import DATA_DIR
    from artifact_engine.handlers._indicators import load_indicators, match_labels
    rules = load_indicators(DATA_DIR / "assets" / "web_suspicious.txt")
    for ua in ("commix/v4.0-stable (https://commixproject.com)", "Fuzz Faster U Fool v2.1.0",
               "Wfuzz/3.1.0", "Recon-ng/v5", "GIS - AppSec Team - Project Vision",
               "sqlmap/1.8", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "zgrab/0.x",
               "gobuster/3.6", "feroxbuster/2.10", "Nikto/2.5", "WhatWeb/0.5", "WPScan v3.8"):
        assert "scanner_ua" in match_labels(rules, ua.lower()), ua
