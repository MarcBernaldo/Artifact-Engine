"""The EZ tools' builds do not carry their .NET runtime, and a tool without it
exits at launch on every run, reported as that parser failing (v0.7.174: the
site moved its builds from .NET 9 to .NET 10). Each build names what it needs
in `<Tool>.runtimeconfig.json`; `aeng setup` and `aeng run` say so beforehand."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import yaml

from artifact_engine import cli
from artifact_engine.config import DATA_DIR
from artifact_engine.core import downloader


def _tool(tools: Path, name: str, version: str | None) -> str:
    tools.mkdir(parents=True, exist_ok=True)
    (tools / f"{name}.exe").write_bytes(b"MZ")
    if version is not None:
        (tools / f"{name}.runtimeconfig.json").write_text(json.dumps({"runtimeOptions": {
            "tfm": f"net{version.split('.')[0]}.0",
            "framework": {"name": "Microsoft.NETCore.App", "version": version}}}),
            encoding="utf-8")
    return f"{name}.exe"


def test_each_tool_says_which_runtime_it_needs(tmp_path):
    assert downloader.required_dotnet_major(tmp_path / _tool(tmp_path, "PECmd", "10.0.0")) == 10
    assert downloader.required_dotnet_major(tmp_path / _tool(tmp_path, "hayabusa", None)) is None
    (tmp_path / "Bad.runtimeconfig.json").write_text("{", encoding="utf-8")
    assert downloader.required_dotnet_major(tmp_path / "Bad.exe") is None


def test_a_missing_major_is_a_gap_even_with_a_newer_one(tmp_path, monkeypatch):
    """.NET rolls forward within a major only: a .NET 9 build does not run on a
    host that has .NET 10 alone."""
    bins = [_tool(tmp_path, "PECmd", "10.0.0"), _tool(tmp_path, "AmcacheParser", "10.0.0"),
            _tool(tmp_path, "LECmd", "9.0.0"), _tool(tmp_path, "hayabusa", None)]
    monkeypatch.setattr(downloader, "dotnet_runtime_majors", lambda: {8, 10})
    assert downloader.missing_dotnet(tmp_path, bins) == {9: ["LECmd.exe"]}
    monkeypatch.setattr(downloader, "dotnet_runtime_majors", lambda: {9})
    assert downloader.missing_dotnet(tmp_path, bins) == {10: ["AmcacheParser.exe", "PECmd.exe"]}


def test_dotnet_is_not_asked_when_no_tool_needs_it(tmp_path, monkeypatch):
    def boom():
        raise AssertionError("dotnet asked for nothing")
    monkeypatch.setattr(downloader, "dotnet_runtime_majors", boom)
    assert downloader.missing_dotnet(tmp_path, [_tool(tmp_path, "hayabusa", None)]) == {}


def test_the_installed_runtimes_are_read_from_dotnet(monkeypatch):
    out = ("Microsoft.AspNetCore.App 9.0.1 [C:\\dotnet\\shared\\Microsoft.AspNetCore.App]\n"
           "Microsoft.NETCore.App 8.0.26 [C:\\dotnet\\shared\\Microsoft.NETCore.App]\n"
           "Microsoft.NETCore.App 10.0.0 [C:\\dotnet\\shared\\Microsoft.NETCore.App]\n"
           "Microsoft.WindowsDesktop.App 6.0.36 [C:\\dotnet\\shared\\Microsoft.WindowsDesktop.App]\n")
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=out))
    assert downloader.dotnet_runtime_majors() == {8, 10}

    def missing(*a, **k):
        raise FileNotFoundError("dotnet")
    monkeypatch.setattr(subprocess, "run", missing)
    assert downloader.dotnet_runtime_majors() == set()


def test_the_warning_names_the_runtime_the_tools_and_where_to_get_it(tmp_path, monkeypatch):
    tools = tmp_path / "tools"
    _tool(tools, "PECmd", "10.0.0")
    monkeypatch.setattr(downloader, "dotnet_runtime_majors", lambda: {9})
    parsers = [SimpleNamespace(tool=SimpleNamespace(binary="PECmd.exe", source=object()))]
    lines = cli._dotnet_warning(SimpleNamespace(tools_dir=tools), parsers)
    assert len(lines) == 1
    assert ".NET 10 runtime" in lines[0] and "PECmd.exe" in lines[0]
    assert "https://dotnet.microsoft.com/download/dotnet/10.0" in lines[0]
    monkeypatch.setattr(downloader, "dotnet_runtime_majors", lambda: {9, 10})
    assert cli._dotnet_warning(SimpleNamespace(tools_dir=tools), parsers) == []


def test_every_ez_tool_comes_from_the_current_download_path():
    """The site served its builds from `/net9/` until it moved to `/net/`; a fresh
    `aeng setup` then fetched nothing. One path for all of them, so the next move
    is one search and replace."""
    urls = []
    for f in sorted((DATA_DIR / "parsers").rglob("*.yaml")):
        src = (yaml.safe_load(f.read_text(encoding="utf-8")).get("tool") or {}).get("source") or {}
        if "ericzimmermanstools" in (src.get("url") or ""):
            urls.append(src["url"])
    assert len(urls) >= 12
    assert [u for u in urls
            if not u.startswith("https://download.ericzimmermanstools.com/net/")] == []

def test_run_says_it_before_phase_zero_and_setup_fails_on_it():
    """Said once the parse is under way it is a hundred parser errors; said before
    phase 0, it is one installer."""
    import inspect
    src = inspect.getsource(cli.cmd_run)
    assert "_dotnet_warning(cfg)" in src
    assert src.index("_dotnet_warning(cfg)") < src.index("Computing integrity")
    setup = inspect.getsource(cli.cmd_setup)
    assert "return 0 if fail == 0 and not runtime else 1" in setup
