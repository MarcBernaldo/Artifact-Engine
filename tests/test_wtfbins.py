"""WTFBins: legitimate programs that look like an intrusion, as notes (v0.7.105).

Pages are synthetic; the bundled asset is checked for its shape only."""

import re

import yaml

from artifact_engine.config import DATA_DIR
from artifact_engine.core import lol_wtfbins as W
from artifact_engine.handlers import _exfil, _wtfbins
from artifact_engine.handlers.win_cmd_hunt import flag


def _page(i, title, body):
    return f'+++\nid = {i}\ntitle = "{title}"\ndate = "2026-01-01"\n+++\n\n{body}\n<!-- more -->\nmore\n'


def test_an_entry_keeps_its_own_programs_not_the_ones_it_runs():
    pages = [_page(1, "AgentX.exe", "AgentX runs `whoami.exe` and `certutil.exe` as SYSTEM."),
             _page(2, "Fake components", "Named `spoolsv.exe` in the wrong folder, by `fleetx.exe`."),
             _page(3, "High ports", "Windows uses random high ports.")]
    got = {e["id"]: e["binaries"] for e in W.entries(pages, {"certutil.exe"} | W._SYSTEM)}
    assert got == {1: ["agentx.exe"], 2: ["fleetx.exe"]}           # 3 names no program


def test_the_bundled_list_marks_no_windows_binary():
    data = yaml.safe_load((DATA_DIR / "assets" / W.ASSET).read_text(encoding="utf-8"))
    names = {b for e in data["entries"] for b in e["binaries"]}
    assert names and not names & (W._SYSTEM | W.lolbas_names(DATA_DIR / "assets"))
    assert all(e["url"].startswith(W.SITE + "/") for e in data["entries"])


def test_a_command_line_note_by_its_program_or_its_process():
    notes = {"agentx.exe": "WTFBins: AgentX.exe https://wtfbins.wtf/1"}
    rules = [("encoded", re.compile(r"-enc\b", re.IGNORECASE))]
    lines = _exfil.collect([("task", "SYSTEM", r'"C:\Program Files\X\AgentX.exe" -enc AAAA'),
                            ("process", "pid 5 AgentX.exe", "powershell.exe -enc BBBB"),
                            ("ps_host", "", "powershell.exe -enc CCCC")])
    rows = {r[1]: r[7] for r in flag(lines, rules, notes)}
    assert rows == {"task": notes["agentx.exe"], "process": notes["agentx.exe"], "ps_host": ""}


def test_program_reads_quoted_and_bare_paths():
    assert _wtfbins.program(r'"C:\Program Files\X\AgentX.exe" -a') == "agentx.exe"
    assert _wtfbins.program("C:/x/ccm.exe run") == "ccm.exe"


def test_the_archive_reader_leaves_out_the_lolbas_binaries(tmp_path):
    import zipfile
    z = tmp_path / "w.zip"
    with zipfile.ZipFile(z, "w") as w:
        w.writestr("wtfbins-main/content/7.md", _page(7, "AgentY.exe", "Runs `regsvr32.exe` daily."))
        w.writestr("wtfbins-main/templates/page.md", _page(8, "Template.exe", ""))
    assert [e["binaries"] for e in W.from_zip(z, {"regsvr32.exe"})] == [["agenty.exe"]]
