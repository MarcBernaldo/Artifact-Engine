"""LOTTunnels fetched into a local list, and the remote-access domain matcher (v0.7.102).

Every page, host and URL is synthetic."""

import csv
import json
import logging
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
import yaml

from artifact_engine.config import DATA_DIR
from artifact_engine.core import lol_tunnels as T
from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import _domains

ROOT = Path(__file__).resolve().parents[1]


def _page(name, commands=(), filenames=(), domains=()):
    fm = {"Name": name,
          "Commands": [{"Command": c, "Category": "Access"} for c in commands],
          "Full_Path": [{"Filename": f} for f in filenames] + [{"Path": "Downloaded and run anywhere."}],
          "Detection": [{"Domain": d} for d in domains] + [{"Sigma": "https://example.local/r.yml"}]}
    return "---\n" + yaml.safe_dump(fm) + "---\n"


def test_pages_become_entries_with_the_programs_they_run():
    pages = [_page("TunnelX", ["tunnelx http 8080", "ssh -R 80:localhost:8080 tunnelx.example"],
                   ["tunnelx-agent.exe"], ["*.tunnelx.example"]),
             _page("ScriptTun", ["python st.py -l 1080", "st.py serve"], [], ["st.example"]),
             _page("Twin A", ["twinbin up"]), _page("Twin B", ["twinbin up"], [], ["*.twinb.example"]),
             _page("Nothing", ["curl https://x.example | sh"])]
    by = {e["name"]: e for e in T.tunnels(pages)}
    assert by["TunnelX"]["files"] == ["tunnelx-agent.exe", "tunnelx.exe"]   # ssh is a carrier
    assert by["ScriptTun"]["files"] == []                     # python and a .py script
    assert by["Twin B"]["files"] == [] and "Twin A" not in by    # a shared name is no one's
    assert "Nothing" not in by                                # neither files nor domains
    assert by["TunnelX"]["domains"] == ["*.tunnelx.example"]


def test_the_archive_is_read_for_tool_pages_only_and_rendered(tmp_path):
    z = tmp_path / "repo.zip"
    with zipfile.ZipFile(z, "w") as w:
        w.writestr("repo-main/_lottunnels/Binaries/tunnelx.md",
                   _page("TunnelX", ["tunnelx http 80"], [], ["*.tunnelx.example"]))
        w.writestr("repo-main/YML-TEMPLATE.md", _page("Template", ["template run"]))
    entries = T.from_zip(z)
    assert [e["name"] for e in entries] == ["TunnelX"]
    data = yaml.safe_load(T.render(entries, "2026-01-01"))
    assert data["tools"] == [{"name": "TunnelX", "files": ["tunnelx.exe"], "paths": [],
                              "domains": ["*.tunnelx.example"]}]


def test_the_matcher_normalises_what_catalogs_write():
    m = _domains.Matcher()
    assert m.add("*.tunnelx.example", "TunnelX", "LOTTunnels")
    assert m.add("*.*.multi.example", "Multi", "LOTTunnels")
    assert m.add("relay-*.net.remotex.example", "RemoteX", "LOLRMM")
    assert m.add("bore.example:*", "Bore", "LOTTunnels")
    assert m.add("*shell.hostx.example*", "HostX", "LOTTunnels")
    assert m.add("tunnelx.example", "Other", "LOLRMM")             # added, but claimed already
    for left_out in ("user_managed", "<operator-configured server>", "10.0.0.5:443",
                     "github.com", "*.amazonaws.com", "x*.ab.cd"):
        assert not m.add(left_out, "T", "C"), left_out
    assert m.match("abc.tunnelx.example")[0] == "TunnelX"
    assert m.match("TUNNELX.example.")[0] == "TunnelX"              # the base, any case
    assert m.match("a.b.multi.example")[0] == "Multi"
    assert m.match("multi.example")[0] == "Multi"                   # *.*.x is *.x
    assert m.match("relay-7.net.remotex.example")[0] == "RemoteX"
    assert m.match("relay-7.x.net.remotex.example") is None         # one label only
    assert m.match("bore.example")[0] == "Bore"
    assert m.match("myshell.hostx.example")[0] == "HostX"
    assert m.match("nottunnelx.example") is None
    assert m.match("github.com") is None and m.match("") is None


def _ctx(evidence: Path, out: Path, assets: Path, volume="live") -> ParserContext:
    return ParserContext(evidence=evidence, out=out, tools=evidence, assets=assets,
                         machine_name="HOST-01", volume=volume, log=logging.getLogger("aeng.test"))


def _assets(tmp_path: Path) -> Path:
    a = tmp_path / "assets"
    (a / "lottunnels").mkdir(parents=True)
    (a / "lottunnels" / "tunnels.yaml").write_text(T.render(
        [{"name": "TunnelX", "files": ["tunnelx.exe"], "paths": [],
          "domains": ["*.tunnelx.example"]}], "2026-01-01"), encoding="utf-8")
    (a / "rmm_lolrmm.yaml").write_text(
        'tools:\n  - name: "RemoteX"\n    files: []\n    paths: []\n'
        '    domains: ["relay-*.net.remotex.example"]\n', encoding="utf-8")
    return a


def _write(path: Path, header, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def _read(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_remote_access_domains_from_browser_and_dns_cache(tmp_path):
    from artifact_engine.handlers import win_remote_access_domains as H
    assets = _assets(tmp_path)
    machine = tmp_path / "HOST-01"
    _write(machine / "CSVs" / "Browser" / "browser_history.csv",
           ["user", "browser", "profile", "url", "title", "visit_count", "last_visit_utc"],
           [["jdoe", "chrome", "Default", "https://a1.tunnelx.example/x", "", 1, "2026-01-02 10:00:00"],
            ["jdoe", "chrome", "Default", "https://a1.tunnelx.example/y", "", 1, "2026-01-03 10:00:00"],
            ["jdoe", "chrome", "Default", "https://www.example.local/", "", 9, "2026-01-04 10:00:00"]])
    _write(machine / "CSVs" / "Browser" / ".work_browser" / "browser_history.csv",
           ["user", "url", "last_visit_utc"], [["jdoe", "https://b.tunnelx.example/", ""]])
    res = tmp_path / "Velociraptor" / "LiveResponse" / "results"
    res.mkdir(parents=True)
    (res / "Eiffel.LiveResponse.Windows%2FWindows.System.DNSCache.json").write_text(
        json.dumps({"Name": "relay-3.net.remotex.example", "Record": "10.0.0.5"}) + "\n"
        + json.dumps({"Name": "www.example.local", "Record": "10.0.0.6"}), encoding="utf-8")
    out = machine / "CSVs" / "Network" / ".work_remote_access_domains"
    H.run(_ctx(tmp_path, out, assets))
    rows = _read(out / H.TABLE)
    assert [(r["tool"], r["host"], r["source"], r["hits"], r["last_utc"]) for r in rows] == [
        ("RemoteX", "relay-3.net.remotex.example", "dns_cache", "1", ""),
        ("TunnelX", "a1.tunnelx.example", "browser_history", "2", "2026-01-03 10:00:00")]
    assert rows[1]["example"].endswith("/y") and rows[1]["catalog"] == "LOTTunnels"
    # a VSS snapshot never reads the live host's DNS cache
    out2 = tmp_path / "HOST-01-VSS1" / "CSVs" / "Network" / ".work_x"
    shutil.copytree(machine / "CSVs" / "Browser", tmp_path / "HOST-01-VSS1" / "CSVs" / "Browser")
    H.run(_ctx(tmp_path, out2, assets, volume="VSS1"))
    assert {r["source"] for r in _read(out2 / H.TABLE)} == {"browser_history"}


def test_rmm_reads_the_tunnel_list(tmp_path):
    from artifact_engine.handlers import win_exec_hunt
    exe = tmp_path / "CSVs" / "Execution"
    _write(exe / "amcache_UnassociatedFileEntries.csv",
           ["Name", "FullPath", "SHA1", "FileKeyLastWriteTimestamp"],
           [["tunnelx.exe", r"c:\users\jdoe\downloads\tunnelx.exe", "ab" * 20, "2026-01-02"]])
    out = tmp_path / "CSVs" / "Detections"
    win_exec_hunt.run(_ctx(tmp_path, out, _assets(tmp_path)))
    assert [r["tool"] for r in _read(out / "rmm.csv")] == ["TunnelX"]


def test_the_fetched_list_never_reaches_git_or_a_build():
    if not (ROOT / ".git").exists() or not shutil.which("git"):
        pytest.skip("not a git checkout")
    probe = "src/artifact_engine/data/assets/" + T.ASSET
    r = subprocess.run(["git", "check-ignore", "-q", probe], cwd=ROOT, check=False)
    assert r.returncode == 0
    toml = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'artifact_engine = ["data/assets/lottunnels/*"]' in toml.split(
        "[tool.setuptools.exclude-package-data]", 1)[1]


def test_the_bundled_lolrmm_domains_load():
    m = _domains.load(DATA_DIR / "assets")
    assert len(m) > 500
    assert m.match("raw.githubusercontent.com") is None


def test_a_refetch_that_only_moves_the_date_keeps_the_file(tmp_path, monkeypatch):
    from artifact_engine.core import downloader

    pages = {"tunnelx.md": _page("TunnelX", ["tunnelx http 80"], [], ["*.tunnelx.example"])}

    def fake_download(url, dest, **kw):
        with zipfile.ZipFile(dest, "w") as w:
            for name, text in pages.items():
                w.writestr(f"repo-main/_lottunnels/Binaries/{name}", text)
        return True

    monkeypatch.setattr(downloader, "_download", fake_download)
    dest = tmp_path / T.ASSET
    assert downloader.fetch_lottunnels(tmp_path, force=True)
    dest.write_text(dest.read_text(encoding="utf-8").replace("(retrieved ", "(retrieved 1999-"),
                    encoding="utf-8")
    stale = dest.read_text(encoding="utf-8")
    assert downloader.fetch_lottunnels(tmp_path, force=True)
    assert dest.read_text(encoding="utf-8") == stale              # same tools: untouched
    pages["chisel.md"] = _page("ChiselX", ["chiselx client"])
    assert downloader.fetch_lottunnels(tmp_path, force=True)
    assert "ChiselX" in dest.read_text(encoding="utf-8")
