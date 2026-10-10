"""LOL catalog import (v0.7.100): LOLRMM's JSON -> the asset win_rmm reads."""

from pathlib import Path

import yaml

from artifact_engine.config import DATA_DIR
from artifact_engine.core import lol_import as L


def _tool(name, files=(), paths=(), domains=()):
    return {"Name": name,
            "Details": {"PEMetadata": [{"Filename": f, "OriginalFileName": ""} for f in files],
                        "InstallationPaths": list(paths)},
            "Artifacts": {"Network": [{"Domains": list(domains)}]}}


def test_names_paths_and_domains_are_kept_narrow():
    catalog = [
        _tool("Alpha Remote", ["alpharemote.exe", "agent.exe", "shared.exe"],
              ["C:\\Program Files\\Alpha Remote\\*", "%ProgramData%\\AlphaR-*\\x.exe"],
              ["relay.alpha.example"]),
        _tool("Beta Desk", ["shared.exe", "svchost.exe"],
              ["C:\\Program Files (x86)\\Common Files\\beta\\b.exe",
               "C:\\Users\\jdoe\\AppData\\Local\\Beta Desk (<id>)\\b.exe",
               "C:\\Program Files\\Lvl\\b.exe"]),
        _tool("Empty"),
    ]
    tools = {t["name"]: t for t in L.rmm(catalog)}
    assert set(tools) == {"Alpha Remote", "Beta Desk"}       # nothing to match: dropped
    a, b = tools["Alpha Remote"], tools["Beta Desk"]
    # claimed by two tools, or too generic: left out
    assert a["files"] == ["alpharemote.exe"] and b["files"] == []
    # a whole folder is closed; a wildcard or placeholder leaves it open
    assert a["paths"] == ["\\alpha remote\\", "\\alphar-"]
    # a shared folder, and one too short to be distinctive, give nothing
    assert b["paths"] == ["\\beta desk"]
    assert a["domains"] == ["relay.alpha.example"]


def test_render_leaves_out_what_the_publication_filter_blocks():
    tools = L.rmm([_tool("Alpha Remote", ["alpharemote.exe"]),
                   _tool("Gamma Blocked", ["gamma.exe"])])
    text = L.render(tools, "2026-01-01", blocked=lambda s: ["x"] if "Gamma" in s else [])
    data = yaml.safe_load(text)
    assert [t["name"] for t in data["tools"]] == ["Alpha Remote"]
    assert "1 catalog tool(s) left out" in text and "Gamma" not in text


def test_the_bundled_catalog_follows_the_rules():
    data = yaml.safe_load((DATA_DIR / "assets" / L.ASSET).read_text(encoding="utf-8"))
    tools = data["tools"]
    assert len(tools) > 200
    files = [f for t in tools for f in t["files"]]
    assert not set(files) & L._GENERIC
    assert len(files) == len(set(files))                   # one tool per name
    for t in tools:
        for p in t["paths"]:
            assert p.startswith("\\") and p.strip("\\").split("\\")[0] not in L._SHARED


def test_win_rmm_reads_the_curated_list_then_the_catalog(tmp_path):
    from artifact_engine.handlers import win_rmm
    (tmp_path / "rmm_tools.yaml").write_text(yaml.safe_dump({"tools": [
        {"name": "Curated Name", "files": ["alpharemote.exe"]}]}), encoding="utf-8")
    (tmp_path / "rmm_lolrmm.yaml").write_text(yaml.safe_dump({"tools": [
        {"name": "Catalog Name", "files": ["alpharemote.exe"]},
        {"name": "Only In Catalog", "paths": ["\\onlycat\\"]}]}), encoding="utf-8")
    tools = win_rmm._load_rmm(Path(tmp_path))
    assert win_rmm._match("AlphaRemote.exe", "", tools)[0] == "Curated Name"
    assert win_rmm._match("x.exe", "C:\\Program Files\\OnlyCat\\x.exe", tools)[0] == \
        "Only In Catalog"


def test_the_bundled_lists_together_name_a_catalog_only_tool():
    from artifact_engine.handlers import win_rmm
    tools = win_rmm._load_rmm(DATA_DIR / "assets")
    curated = yaml.safe_load((DATA_DIR / "assets" / "rmm_tools.yaml").read_text(
        encoding="utf-8"))["tools"]
    # ~136 catalog tools carry a file name or install folder; the rest only domains
    assert len(tools) > len(curated) + 100
