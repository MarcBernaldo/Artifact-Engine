"""A parser removed from the engine with no successor: what it left in a case
parsed before is removed on the next run, so it is no longer consolidated."""
from __future__ import annotations

import logging

from artifact_engine.config import DATA_DIR, Config
from artifact_engine.core import asset_state, outputs, retired, runner, scheduler
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.registry import load_parsers

SPEC = {
    "old_win": {"os": "windows", "category": "filesystem", "outputs": ["old.csv"]},
    "old_glob": {"os": "windows", "category": "eventlogs", "outputs": ["tool_*.csv"]},
}


def _machine(tmp_path, name, os_):
    vol = Volume(name="live", path=tmp_path / name, is_live=True)
    m = Machine(name=name, os=os_, collector="kape", profile_id="windows_kape",
                path=tmp_path / name, source="src", volumes=[vol])
    m.display = name
    return m


def _leave(m, category, pid, names):
    out = scheduler._out_dir(m, category)
    out.mkdir(parents=True, exist_ok=True)
    for n in names:
        (out / n).write_text("a,b\n1,2\n", encoding="utf-8")
    runner.marker_path(out, pid).write_text("fp", encoding="utf-8")
    outputs._write(out, pid, {n: outputs._stamp(out / n) for n in names})
    asset_state.record(out, pid, "abc")
    return out


def test_a_removed_parsers_tables_and_records_go(tmp_path):
    win = _machine(tmp_path, "HOST-01", "windows")
    lin = _machine(tmp_path, "web-01", "linux")
    out = _leave(win, "filesystem", "old_win", ["old.csv"])
    (out / "MFT.csv").write_text("x\n", encoding="utf-8")         # another parser's
    lout = _leave(lin, "filesystem", "old_win", ["old.csv"])        # not its OS
    ev = _leave(win, "eventlogs", "old_glob", ["tool_a.csv", "tool_b.csv"])
    # parsed before v0.7.106: no record of what it wrote, only the declared glob
    outputs.record_path(ev, "old_glob").unlink()

    assert retired.sweep([win, lin], scheduler._out_dir, SPEC) == []
    assert not (out / "old.csv").exists()
    assert not runner.marker_path(out, "old_win").exists()
    assert not outputs.record_path(out, "old_win").exists()
    assert not asset_state.record_path(out, "old_win").exists()
    assert (out / "MFT.csv").exists()
    assert not list(ev.glob("tool_*.csv"))                          # globbed names
    assert (lout / "old.csv").exists()                              # other OS untouched
    # nothing left: a second run has nothing to do and says nothing
    assert retired.sweep([win, lin], scheduler._out_dir, SPEC) == []


def test_a_file_it_cannot_remove_is_named_and_kept_for_the_next_run(tmp_path, monkeypatch, caplog):
    win = _machine(tmp_path, "HOST-01", "windows")
    out = _leave(win, "filesystem", "old_win", ["old.csv"])
    monkeypatch.setattr(outputs, "retire", lambda o, pid, names, fresh=(): ["old.csv"])
    with caplog.at_level(logging.WARNING):
        left = retired.sweep([win], scheduler._out_dir, SPEC)
    assert left == [(0, "old_win", "old.csv")]
    assert any("could not be deleted" in r.message for r in caplog.records)
    assert asset_state.record_path(out, "old_win").exists()        # retried next run


def test_run_all_sweeps_before_parsing(tmp_path, monkeypatch):
    win = _machine(tmp_path, "HOST-01", "windows")
    out = _leave(win, "filesystem", "timestomp_mft", ["timestomp.csv"])
    scheduler.run_all([win], [], Config(parse_processes=False), force=False)
    assert not (out / "timestomp.csv").exists()


def test_the_bundled_list_names_only_parsers_that_no_longer_exist():
    listed = retired.load()
    assert {"timestomp_mft", "timestomp_bodyfile", "suid_sgid", "suid", "chainsaw_sigma"} <= set(listed)
    p = DATA_DIR / "parsers"
    ids = {x.id for x in load_parsers([p / "windows", p / "linux"])}
    assert not set(listed) & ids
    for pid, spec in listed.items():
        assert spec["os"] in ("windows", "linux"), pid
        assert spec["category"] in scheduler._CATEGORY_DIR, pid
        assert spec["outputs"], pid


def test_a_live_parser_keeps_what_it_writes(tmp_path):
    """A copy kept in a user parser dir -- same id, or another id with the same
    `short` -- still writes those tables: they are not the removed parser's."""
    from artifact_engine.models import ParserManifest
    win = _machine(tmp_path, "HOST-01", "windows")
    ev = _leave(win, "eventlogs", "old_glob", ["tool_a.csv"])
    same_id = ParserManifest(id="old_glob", os="windows", category="eventlogs", handler="x:run")
    assert retired.sweep([win], scheduler._out_dir, SPEC, parsers=[same_id]) == []
    assert (ev / "tool_a.csv").exists() and runner.marker_path(ev, "old_glob").exists()

    other = ParserManifest(id="mine", os="windows", category="eventlogs", short="tool",
                           handler="x:run")
    retired.sweep([win], scheduler._out_dir, SPEC, parsers=[other])
    assert (ev / "tool_a.csv").exists()                     # its `short` names it
    assert not runner.marker_path(ev, "old_glob").exists()  # the removed one's marker goes


def test_a_file_left_behind_is_an_error_in_the_run(tmp_path, monkeypatch):
    win = _machine(tmp_path, "HOST-01", "windows")
    _leave(win, "filesystem", "timestomp_mft", ["timestomp.csv"])
    monkeypatch.setattr(outputs, "retire", lambda o, pid, names, fresh=(): ["timestomp.csv"])
    (_, runs), = scheduler.run_all([win], [], Config(parse_processes=False), force=False)
    assert [(r.parser_id, r.status) for r in runs] == [("timestomp_mft", "error")]
    assert "timestomp.csv" in runs[0].detail


def test_the_v0_7_161_tables_go_and_their_neighbours_stay(tmp_path):
    """credential_access, hayabusa's logon summaries and web_auth_fail: two of them
    were never parsers, only tables a live parser stopped writing beside the ones it
    still writes."""
    win = _machine(tmp_path, "HOST-01", "windows")
    lin = _machine(tmp_path, "web-01", "linux")
    det = _leave(win, "detections", "x", ["credential_access.csv"])
    ev = _leave(win, "eventlogs", "x", ["hayabusa_logon-successful.csv",
                                        "hayabusa_logon-failed.csv", "hayabusa.csv",
                                        "hayabusa_base64.csv"])
    web = _leave(lin, "web", "x", ["web_auth_fail.csv", "web_ip_stats.csv"])
    p = DATA_DIR / "parsers"
    live = load_parsers([p / "windows", p / "linux"])
    assert retired.sweep([win, lin], scheduler._out_dir, parsers=live) == []
    assert not (det / "credential_access.csv").exists()
    assert sorted(f.name for f in ev.glob("*.csv")) == ["hayabusa.csv", "hayabusa_base64.csv"]
    assert sorted(f.name for f in web.glob("*.csv")) == ["web_ip_stats.csv"]


def test_the_v0_7_162_process_and_socket_lists_go_and_process_network_stays(tmp_path):
    lin = _machine(tmp_path, "web-01", "linux")
    procs = _leave(lin, "processes", "x", ["processes.csv", "hidden_pids.csv",
                                           "process_identity.csv"])
    net = _leave(lin, "network", "x", ["network_connections.csv", "process_network.csv"])
    p = DATA_DIR / "parsers"
    live = load_parsers([p / "windows", p / "linux"])
    assert retired.sweep([lin], scheduler._out_dir, parsers=live) == []
    assert sorted(f.name for f in procs.glob("*.csv")) == ["process_identity.csv"]
    assert sorted(f.name for f in net.glob("*.csv")) == ["process_network.csv"]


def test_the_v0_7_162_login_tables_go_and_logins_stays(tmp_path):
    lin = _machine(tmp_path, "web-01", "linux")
    ev = _leave(lin, "eventlogs", "x", ["wtmp.csv", "btmp.csv", "lastlog.csv", "logins.csv",
                                        "auth_log.csv"])
    p = DATA_DIR / "parsers"
    live = load_parsers([p / "windows", p / "linux"])
    assert retired.sweep([lin], scheduler._out_dir, parsers=live) == []
    assert sorted(f.name for f in ev.glob("*.csv")) == ["auth_log.csv", "logins.csv"]
