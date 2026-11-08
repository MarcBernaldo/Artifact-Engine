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
