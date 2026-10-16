"""v0.7.136: group_policy.csv from Registry.pol (PReg). Synthetic policy files
built here; GUIDs and paths are invented."""
from __future__ import annotations

import csv
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import win_grouppolicy as G

GUID = "{11111111-2222-3333-4444-555555555555}"


def _u(s: str) -> bytes:
    return (s + "\x00").encode("utf-16-le")


def _entry(key: str, value: str, rtype: int, data: bytes) -> bytes:
    semi = ";".encode("utf-16-le")
    return ("[".encode("utf-16-le") + _u(key) + semi + _u(value) + semi
            + struct.pack("<I", rtype) + semi + struct.pack("<I", len(data)) + semi
            + data + "]".encode("utf-16-le"))


def _dword(n: int) -> bytes:
    return struct.pack("<I", n)


def _sz(s: str) -> bytes:
    return _u(s)


def _pol(*entries: bytes) -> bytes:
    return b"PReg" + struct.pack("<I", 1) + b"".join(entries)


DEF = r"Software\Policies\Microsoft\Windows Defender"
POLICY = _pol(
    _entry(DEF, "DisableAntiSpyware", 4, _dword(1)),
    _entry(DEF + r"\Exclusions\Paths", r"C:\ProgramData\x", 1, _sz("0")),
    _entry(r"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
           "EnableScriptBlockLogging", 4, _dword(0)),
    _entry(r"Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
           "EnableModuleLogging", 4, _dword(1)),
    _entry(r"Software\Policies\Microsoft\WindowsFirewall\DomainProfile", "EnableFirewall",
           4, _dword(0)),
    _entry(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "upd", 1,
           _sz(r"C:\Users\Public\upd.exe")),
    _entry(r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "agent", 1,
           _sz(r"C:\Program Files\Vendor\agent.exe")),
    _entry(r"Software\Policies\Example", "**del.OldSetting", 1, _sz(" ")),
    _entry(r"Software\Policies\Example", "**delvals.", 1, _sz(" ")),
    _entry(r"Software\Policies\Example", "Servers", 7, ("a\x00b\x00\x00").encode("utf-16-le")),
    _entry(r"Software\Policies\Example", "Blob", 3, b"\x01\x02"),
)


def _dc(tmp_path: Path, files: dict[str, bytes]) -> Path:
    ev = tmp_path / "ev"
    for rel, data in files.items():
        p = ev / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return ev


def _rows(tmp_path: Path, files: dict[str, bytes]) -> list[dict]:
    ev = _dc(tmp_path, files)
    G.run(SimpleNamespace(evidence=ev, out=tmp_path / "out"))
    with open(tmp_path / "out" / "group_policy.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


SYSVOL_POL = f"Windows/SYSVOL/domain/Policies/{GUID}/Machine/Registry.pol"


def test_entries_are_decoded_by_type(tmp_path):
    rows = {r["value"]: r for r in _rows(tmp_path, {SYSVOL_POL: POLICY})}
    assert rows["DisableAntiSpyware"]["data"] == "1"
    assert rows["DisableAntiSpyware"]["type"] == "REG_DWORD"
    assert rows["Servers"]["data"] == "a|b"
    assert rows["Blob"]["data"] == "0102"
    assert rows["upd"]["data"] == r"C:\Users\Public\upd.exe"
    assert {r["gpo"] for r in rows.values()} == {GUID}
    assert {r["scope"] for r in rows.values()} == {"Machine"}


def test_deletions_are_rows_with_their_action(tmp_path):
    rows = _rows(tmp_path, {SYSVOL_POL: POLICY})
    assert ("OldSetting", "delete value") in {(r["value"], r["action"]) for r in rows}
    assert any(r["action"] == "delete every value" for r in rows)


def test_settings_that_disarm_the_host_are_flagged(tmp_path):
    rows = {r["value"]: r for r in _rows(tmp_path, {SYSVOL_POL: POLICY})}
    for v in ("DisableAntiSpyware", r"C:\ProgramData\x", "EnableScriptBlockLogging",
              "EnableFirewall", "upd"):
        assert rows[v]["suspicious"] == "yes", v
    for v in ("EnableModuleLogging", "agent", "Servers", "Blob"):
        assert rows[v]["suspicious"] == "", v
    assert "exclusion" in rows[r"C:\ProgramData\x"]["note"]


def test_a_doubled_sysvol_layout_is_read_once(tmp_path):
    rows = _rows(tmp_path, {
        SYSVOL_POL: POLICY,
        f"Windows/SYSVOL/sysvol/example.local/Policies/{GUID}/Machine/Registry.pol": POLICY})
    assert len(rows) == 11


def test_the_local_policy_is_read(tmp_path):
    rows = _rows(tmp_path, {"Windows/System32/GroupPolicy/User/Registry.pol": POLICY})
    assert {(r["source"], r["scope"], r["gpo"]) for r in rows} == {("local", "User", "")}


def test_a_truncated_file_keeps_what_parsed(tmp_path):
    assert len(G.parse(POLICY[:-5])) == 10
    assert G.parse(b"not a policy") == []


def test_no_policy_file_is_a_skip(tmp_path):
    (tmp_path / "ev" / "Windows").mkdir(parents=True)
    with pytest.raises(HandlerSkip):
        G.run(SimpleNamespace(evidence=tmp_path / "ev", out=tmp_path / "out"))


def test_an_entry_cut_inside_its_data_is_dropped(tmp_path):
    pol = _pol(_entry(DEF, "DisableAntiSpyware", 4, _dword(1)),
               _entry(r"Software\Policies\Example", "Long", 1, _sz("x" * 40)))
    assert [v for _k, v, *_ in G.parse(pol[:-10])] == ["DisableAntiSpyware"]


def test_deleting_a_setting_is_not_flagged_as_setting_it(tmp_path):
    rows = _rows(tmp_path, {SYSVOL_POL: _pol(_entry(DEF, "**del.DisableAntiSpyware", 4,
                                                    _dword(1)))})
    assert rows[0]["action"] == "delete value" and rows[0]["suspicious"] == ""
