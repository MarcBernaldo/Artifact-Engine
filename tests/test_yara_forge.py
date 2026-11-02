"""YARA-Forge sync: only repositories with a reviewed licence reach the rule
folder, one file per repository, and the sync removes what it wrote before and
nothing else. Offline: the release package is synthesised."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import zipfile

import pytest

from artifact_engine import cli
from artifact_engine.core import downloader as dl

_TAG = "20260101"
_RL = "https://github.com/reversinglabs/reversinglabs-yara-rules/"
_ESET = "https://github.com/eset/malware-ioc"
_NOLIC = "https://github.com/example-org/unlicensed-rules"
_SIGBASE = "https://github.com/Neo23x0/signature-base"


def _set(name: str, url: str, rules: bytes) -> bytes:
    return (f"/*\n * YARA Rule Set\n * Repository Name: {name}\n * Repository: {url}\n"
            f" * Number of Rules: 1\n *\n * LICENSE\n *\n * licence text\n */\n").encode() + rules


def _package(*sets: bytes) -> bytes:
    """A package laid out like YARA-Forge's: header comment, imports, then sets."""
    return (b"/*\n * YARA-Forge YARA Rule Package\n */\n\nimport \"pe\"\nimport \"hash\"\n\n"
            + b"\n".join(sets))


def _rule(name: str) -> bytes:
    # Uses the `pe` module: a set written without the package's imports would not compile.
    return (f"rule {name} : FILE {{\n meta:\n  author = \"jdoe\"\n  score = 70\n"
            f" condition:\n  pe.number_of_sections > 1000\n}}\n").encode()


_DEFAULT = _package(
    _set("ReversingLabs", _RL, _rule("REVERSINGLABS_A") + _rule("REVERSINGLABS_B")),
    _set("ESET", _ESET, _rule("ESET_A")),
    _set("Nobody", _NOLIC, _rule("NOBODY_A") + _rule("NOBODY_B") + _rule("NOBODY_C")),
    _set("Signature Base", _SIGBASE, _rule("SIGNATURE_BASE_A")),
)


class _Hop:
    def __init__(self, location: str):
        self.headers = {"Location": location}


class _Resp:
    def __init__(self, content: bytes, tag: str):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("packages/extended/yara-rules-extended.yar", content)
        self.content = buf.getvalue()
        self.history = [_Hop(f"https://github.com/YARAHQ/yara-forge/releases/download/{tag}/"
                             f"yara-forge-rules-extended.zip")]
        self.url = "https://release-assets.example.local/blob"
        self.headers = {}

    def raise_for_status(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def forge(monkeypatch):
    """Serve `state["package"]` as release `state["tag"]`; count the downloads."""
    import requests

    state = {"package": _DEFAULT, "tag": _TAG, "gets": 0}

    def _get(*a, **k):
        state["gets"] += 1
        return _Resp(state["package"], state["tag"])

    def _head(*a, **k):
        return _Hop(f"https://github.com/YARAHQ/yara-forge/releases/download/{state['tag']}/x")

    monkeypatch.setattr(requests, "get", _get)
    monkeypatch.setattr(requests, "head", _head)
    return state


def _dest(tmp_path):
    return tmp_path / "yara" / "yara-forge"


def test_only_repositories_with_a_reviewed_licence_are_written(tmp_path, forge):
    sync = dl.fetch_yara_forge(tmp_path)

    files = sorted(p.name for p in _dest(tmp_path).glob("*.yar"))
    assert files == ["eset.yar", "reversinglabs.yar"]
    assert (sync.ok, sync.total, sync.rules, sync.left_out) == (True, 2, 3, 3)
    text = b"".join(p.read_bytes() for p in _dest(tmp_path).glob("*.yar"))
    assert b"NOBODY_" not in text, "a repository with no licence must not be loaded"
    assert b"SIGNATURE_BASE_" not in text, "signature-base is synced in full on its own"


def test_the_manifest_records_release_package_and_licences(tmp_path, forge):
    dl.fetch_yara_forge(tmp_path)
    data = json.loads((_dest(tmp_path) / dl._FORGE_MANIFEST).read_text(encoding="utf-8"))

    assert data["release"] == _TAG
    assert data["package"] == "extended"
    assert data["files"]["reversinglabs.yar"] == {"repo": _RL, "licence": "MIT", "rules": 2}
    assert data["left_out"] == {_NOLIC: 3}
    zipped = _Resp(_DEFAULT, _TAG).content
    assert data["sha256"] == hashlib.sha256(zipped).hexdigest()
    assert dl.installed_forge_release(tmp_path) == _TAG


def test_each_file_compiles_and_one_bad_repository_costs_only_itself(tmp_path, forge):
    """The package is one file; written whole, a single rule this yara cannot
    compile would cost every rule in it."""
    yara = pytest.importorskip("yara")
    from artifact_engine.handlers.lin_yara import _compile_rules

    forge["package"] = _package(
        _set("ReversingLabs", _RL, _rule("REVERSINGLABS_A")),
        _set("ESET", _ESET, b"rule ESET_BROKEN { condition: no_such_identifier }\n"),
    )
    dl.fetch_yara_forge(tmp_path)
    for p in _dest(tmp_path).glob("*.yar"):
        if p.name == "reversinglabs.yar":
            yara.compile(filepath=str(p))           # carries the package's imports

    rules = _compile_rules(tmp_path, None)
    assert {r.identifier for r in rules} == {"REVERSINGLABS_A"}


def test_rule_bytes_reach_the_disk_unchanged(tmp_path, forge):
    raw = b'rule REVERSINGLABS_RAW { strings: $a = "\xe9\xff\x00" condition: $a }\r\n'
    forge["package"] = _package(_set("ReversingLabs", _RL, raw))
    dl.fetch_yara_forge(tmp_path)

    assert raw in (_dest(tmp_path) / "reversinglabs.yar").read_bytes()


def test_a_withdrawn_repository_is_removed_and_the_analysts_file_is_not(tmp_path, forge):
    dl.fetch_yara_forge(tmp_path)
    mine = _dest(tmp_path) / "my_hunt.yar"
    mine.write_text("rule Mine { condition: true }", encoding="utf-8")

    forge["tag"] = "20260108"
    forge["package"] = _package(_set("ReversingLabs", _RL, _rule("REVERSINGLABS_A")))
    sync = dl.fetch_yara_forge(tmp_path)

    assert not (_dest(tmp_path) / "eset.yar").exists()
    assert mine.is_file(), "only files a previous sync wrote may be removed"
    assert (sync.removed, sync.release, sync.changed) == (1, "20260108", True)


def test_the_release_on_disk_is_not_downloaded_again(tmp_path, forge):
    dl.fetch_yara_forge(tmp_path)
    again = dl.fetch_yara_forge(tmp_path)

    assert forge["gets"] == 1
    assert again.ok and not again.changed
    assert (again.total, again.rules, again.left_out) == (2, 3, 3)


def test_a_new_release_with_the_same_files_is_still_a_change(tmp_path, forge):
    """Rules are edited inside a repository's file far more often than a
    repository comes or goes; `update` must not call that "current"."""
    dl.fetch_yara_forge(tmp_path)
    forge["tag"] = "20260108"
    sync = dl.fetch_yara_forge(tmp_path)

    assert forge["gets"] == 2
    assert (sync.added, sync.removed) == (0, 0)
    assert sync.changed


def test_a_package_with_no_reviewed_repository_leaves_the_rules_alone(tmp_path, forge):
    dl.fetch_yara_forge(tmp_path)
    forge["tag"] = "20260108"
    forge["package"] = _package(_set("Nobody", _NOLIC, _rule("NOBODY_A")))
    sync = dl.fetch_yara_forge(tmp_path)

    assert not sync.ok
    assert (_dest(tmp_path) / "eset.yar").is_file()
    assert dl.installed_forge_release(tmp_path) == _TAG


def test_a_failed_download_leaves_the_rules_alone(tmp_path, forge, monkeypatch):
    import requests

    dl.fetch_yara_forge(tmp_path)

    def _offline(*a, **k):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(requests, "get", _offline)
    monkeypatch.setattr(requests, "head", _offline)
    sync = dl.fetch_yara_forge(tmp_path)

    assert not sync.ok
    assert sorted(p.name for p in _dest(tmp_path).glob("*.yar")) == ["eset.yar",
                                                                       "reversinglabs.yar"]


@pytest.mark.parametrize("handler", ["win_yara", "lin_yara"])
def test_a_rule_folder_in_the_evidence_is_not_scanned(tmp_path, handler):
    """A copy of these rules on the examined machine matches itself."""
    pytest.importorskip("yara")
    import importlib
    import shutil

    from artifact_engine.config import DATA_DIR
    from artifact_engine.core.runner import ParserContext

    rules = tmp_path / "assets" / "yara"
    rules.mkdir(parents=True)
    for yar in (DATA_DIR / "assets" / "yara").glob("*.yar"):
        shutil.copy(yar, rules / yar.name)
    ev = tmp_path / "ev"
    stage = ev / ("ProgramData" if handler == "win_yara" else "[root]/tmp")
    (stage / "kit" / "yara-forge").mkdir(parents=True)
    shell = "<?php @system($_GET['c']); ?>"
    (stage / "evil.php").write_text(shell, encoding="utf-8")
    (stage / "kit" / "yara-forge" / "copy.php").write_text(shell, encoding="utf-8")

    ctx = ParserContext(evidence=ev, out=tmp_path / "out", tools=tmp_path,
                        assets=tmp_path / "assets", machine_name="h", volume="C", log=None)
    importlib.import_module(f"artifact_engine.handlers.{handler}").run(ctx)
    out = (tmp_path / "out" / "alert_yara.csv").read_text(encoding="utf-8")
    assert "evil.php" in out
    assert "yara-forge" not in out


def test_split_keeps_the_imports_and_every_set():
    imports, sets = dl.split_forge(_DEFAULT)

    assert imports == b'import "pe"\nimport "hash"\n'
    assert [(n, u) for n, u, _ in sets] == [("ReversingLabs", _RL), ("ESET", _ESET),
                                            ("Nobody", _NOLIC), ("Signature Base", _SIGBASE)]
    assert dl.split_forge(b"rule A { condition: true }") == (b"", [])


def test_update_reports_a_new_release(tmp_path, monkeypatch):
    from artifact_engine.config import Config

    cfg = Config(assets_dir=tmp_path, tools_dir=tmp_path)
    monkeypatch.setattr(dl, "fetch_yara_rules", lambda a: dl.RuleSync(total=1, ok=True))
    monkeypatch.setattr(dl, "fetch_yara_forge", lambda a: dl.RuleSync(
        total=2, ok=True, release=_TAG, rules=3, left_out=3, new_release=True))
    monkeypatch.setattr(dl, "installed_hayabusa_version", lambda t: "1")
    monkeypatch.setattr(dl, "latest_tag", lambda r: "1")
    monkeypatch.setattr(cli, "load_parsers", lambda dirs: [])
    rows = cli._update_content(cfg, check_only=False, with_tools=False)

    assert ("YARA-Forge", "updated",
            f"{_TAG}: 3 rule(s) in 2 file(s), 3 left out (no reviewed licence)") in rows


def test_update_check_compares_releases_without_downloading(tmp_path, monkeypatch):
    from artifact_engine.config import Config

    cfg = Config(assets_dir=tmp_path, tools_dir=tmp_path)
    monkeypatch.setattr(dl, "fetch_yara_forge", lambda a: pytest.fail("check must not fetch"))
    monkeypatch.setattr(dl, "installed_forge_release", lambda a: "20260101")
    monkeypatch.setattr(dl, "forge_release", lambda: "20260108")
    monkeypatch.setattr(dl, "installed_hayabusa_version", lambda t: "1")
    monkeypatch.setattr(dl, "latest_tag", lambda r: "1")
    monkeypatch.setattr(cli, "load_parsers", lambda dirs: [])
    rows = cli._update_content(cfg, check_only=True, with_tools=False)

    assert ("YARA-Forge", "available", "20260101 -> 20260108") in rows


def test_setup_reports_the_forge_rule_count(tmp_path, monkeypatch, caplog):
    from artifact_engine import config as cfgmod

    for name in ("fetch_web_assets", "fetch_awesome_lists"):
        monkeypatch.setattr(dl, name, lambda assets_dir, force=False: 0)
    monkeypatch.setattr(dl, "fetch_lottunnels", lambda assets_dir, force=False: True)
    monkeypatch.setattr(dl, "fetch_yara_rules", lambda a: dl.RuleSync(total=7, ok=True))
    monkeypatch.setattr(dl, "fetch_yara_forge", lambda a: dl.RuleSync(total=2, rules=42, ok=True))
    monkeypatch.setattr(dl, "fetch_hayabusa", lambda tools_dir, force=False: True)
    monkeypatch.setattr(dl, "fetch_tool", lambda tool, tools_dir, **k: True)
    monkeypatch.setattr(cli, "_write_tools_lock", lambda *a, **k: None)
    tool = tmp_path / "tool"
    (tool / "src" / "artifact_engine").mkdir(parents=True)
    (tool / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    monkeypatch.setattr(cfgmod, "PACKAGE_DIR", tool / "src" / "artifact_engine")
    monkeypatch.chdir(tmp_path)

    with caplog.at_level("INFO", logger="aeng"):
        cli.cmd_setup(argparse.Namespace())

    assert "YARA-Forge 42 rule(s)" in "\n".join(r.getMessage() for r in caplog.records)
