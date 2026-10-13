"""v0.7.125: one corrupt log does not take hayabusa's base64 view with it."""
from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import win_eventlogs_hayabusa as haya

_HELP = ("Hayabusa v4.1.0\nCommands:\n"
         "  dfir-timeline            Create a DFIR timeline\n"
         "  extract-base64           Extract and decode base64 strings from events\n"
         "  logon-summary            Output a summary of successful and failed logons\n")
_HEADER = "Timestamp,Computer,Base64String\n"


def _install(tmp_path, monkeypatch, logs: list[str], panics_on: set[str],
             fails_on: set[str] = frozenset()):
    """Evidence holding `logs`; a scripted hayabusa whose extract-base64 panics
    (exit 101) over the directory and over each log in `panics_on`, exits 2 for
    each in `fails_on`, and writes one row per other log."""
    folder = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
    folder.mkdir(parents=True)
    for name in logs:
        (folder / name).write_bytes(b"ElfFile\x00")
    name = "hayabusa-4.1.0-win-x64.exe" if os.name == "nt" else "hayabusa-4.1.0-lin-x64-gnu"
    exe = tmp_path / "hayabusa" / name
    exe.parent.mkdir()
    exe.write_bytes(b"\x7fELF")
    if os.name != "nt":
        exe.chmod(0o755)

    def fake_run(argv, **kwargs):
        if argv[1] == "help":
            return 0, _HELP, ""
        if argv[1] != "extract-base64":
            return 0, "", ""
        out = Path(argv[argv.index("-o") + 1])
        if "-d" in argv:
            out.write_text(_HEADER + "partial,row,before-the-crash\n", encoding="utf-8")
            return 101, "", "thread 'main' panicked at value_variant.rs: range end index\n"
        log = Path(argv[argv.index("-f") + 1]).name
        if log in panics_on:
            return 101, "", "thread 'main' panicked\n"
        if log in fails_on:
            return 2, "", "[ERROR] cannot read\n"
        out.write_text(_HEADER + f"2026-01-01 00:00:00,HOST-01,{log}\n", encoding="utf-8")
        return 0, "", ""

    monkeypatch.setattr(haya.procs, "run", fake_run)
    return ParserContext(evidence=tmp_path, out=tmp_path / "CSVs", tools=tmp_path,
                         assets=tmp_path, machine_name="HOST-01", volume="C",
                         log=logging.getLogger("aeng.test"))


def test_a_log_that_crashes_the_view_is_named_and_the_others_are_kept(tmp_path, monkeypatch,
                                                                      caplog):
    """MEASURED: `extract-base64 -d` panicked on one snapshot's corrupt log, so
    the parser was an error on every run and the view held nothing."""
    ctx = _install(tmp_path, monkeypatch, ["Application.evtx", "Broken.evtx", "System.evtx"],
                   panics_on={"Broken.evtx"})
    with caplog.at_level(logging.WARNING, logger="aeng.test"):
        haya.run(ctx)

    table = (ctx.out / "hayabusa_base64.csv").read_text(encoding="utf-8")
    assert table == (_HEADER + "2026-01-01 00:00:00,HOST-01,Application.evtx\n"
                     + "2026-01-01 00:00:00,HOST-01,System.evtx\n"), table
    assert "partial,row" not in table, "the crashed run's leftovers are not kept"
    assert "Broken.evtx" in caplog.text and "NOT in hayabusa_base64.csv" in caplog.text
    assert not (ctx.out / ".hayabusa_base64_parts").exists()


def test_any_other_failure_of_a_log_is_still_an_error(tmp_path, monkeypatch):
    ctx = _install(tmp_path, monkeypatch, ["Application.evtx", "Broken.evtx"],
                   panics_on=set(), fails_on={"Broken.evtx"})
    with pytest.raises(RuntimeError, match="extract-base64 exit 2"):
        haya.run(ctx)
