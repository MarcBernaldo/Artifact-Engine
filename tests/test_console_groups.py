"""v0.7.122: one console line per host while parsing and consolidating."""
from __future__ import annotations

from pathlib import Path

from artifact_engine.config import Config
from artifact_engine.core import console_groups, runner, scheduler
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.models import ParserManifest


def _m(name, collector="kape", os="windows", path=Path("."), **kw) -> Machine:
    m = Machine(name=name, os=os, collector=collector, profile_id=collector,
                path=path, source="src", **kw)
    m.display = name
    return m


def test_a_host_and_everything_of_it_share_one_line():
    machines = [
        _m("HOST-01", has_lr=True),
        _m("HOST-01_VSS1", is_vss=True), _m("HOST-01_VSS2", is_vss=True),
        _m("DC01"),
        _m("web-01_uac", "uac", "linux"), _m("web-01_uac", "uac", "linux"),
        _m("WEB-01", "memory", "linux"),
        _m("localhost_uac", "uac", "linux"), _m("localhost_uac", "uac", "linux"),
        _m("weblogs-edge", "weblogs", "linux"),
        _m("HOST-01", "memory", "windows"),
    ]
    got = console_groups.group(machines)
    labels = [g[0] for g in got]
    assert labels[:3] == ["HOST-01 [LR, 2 VSS, mem]", "DC01", "web-01 [UAC x2, mem]"]
    assert labels[5] == "weblogs-edge"      # a log drop is a line of its own
    # a name that is no host joins nothing: each `localhost` keeps its own line
    assert [g[1] for g in got] == [[0, 1, 2, 10], [3], [4, 5, 6], [7], [8], [9]]


def test_two_lines_that_would_read_alike_keep_their_own_labels():
    """One host name on two OSes is two lines; they must not read the same."""
    a, b = _m("SRV", "kape", "windows"), _m("srv_uac", "uac", "linux")
    a.display, b.display = "SRV", "srv_uac"
    b.name = "SRV_uac"
    got = console_groups.group([a, b, _m("SRV_VSS1", is_vss=True)])
    labels = [g[0] for g in got]
    assert len(set(labels)) == len(labels), labels


def test_the_suffix_and_snapshot_are_display_only():
    m = _m("web-01_uac", "uac", "linux")
    console_groups.group([m])
    assert m.name == "web-01_uac"           # the machine itself is untouched


_MADE: list = []


class _Bars:
    def __init__(self, labels, totals, **kw):
        self.labels, self.totals, self.updates = labels, totals, []
        _MADE.append(self)

    def start(self):
        pass

    def stop(self):
        pass

    def set_note(self, text):
        pass

    def update(self, idx, done=None, status=None):
        self.updates.append((idx, done, status))


def test_the_parsing_bar_of_a_host_sums_its_machines(tmp_path, monkeypatch):
    """A host's bar counts every task of its live volume and snapshots, and
    turns `done` only when the last of them is done."""
    machines = []
    for name, vss in (("HOST-01", False), ("HOST-01_VSS1", True), ("DC01", False)):
        d = tmp_path / name
        d.mkdir()
        m = _m(name, path=d, is_vss=vss)
        m.volumes = [Volume(name="C", path=d, is_live=not vss)]
        machines.append(m)
    parsers = [ParserManifest(id=f"p{i}", os="windows", category="systeminfo",
                              handler="x:run") for i in range(2)]
    monkeypatch.setattr(runner, "run_parser", lambda parser, ctx, force=False:
                        runner.ParserRun(parser.id, ctx.volume, "ok", 0.0, ""))
    monkeypatch.setattr(scheduler, "Progress", _Bars)
    _MADE.clear()
    scheduler.run_all(machines, parsers, Config(parse_processes=False))

    bars = _MADE[0]
    assert bars.labels == ["HOST-01 [1 VSS]", "DC01"]
    assert bars.totals == [4, 2]
    host = [(d, s) for i, d, s in bars.updates if i == 0]
    assert host[-1] == (4, "done")
    assert all(s != "done" for d, s in host if d < 4), host


def test_consolidation_bars_read_like_the_parsing_ones():
    """A merged host unit gets the host wording; two units that would read the
    same (two acquisitions of one host are two .db files) keep their own."""
    from artifact_engine import cli
    from artifact_engine.core.consolidate import Unit

    live, vss = _m("HOST-01", has_lr=True), _m("HOST-01_VSS1", is_vss=True)
    a, b = _m("web-01_uac", "uac", "linux"), _m("web-01_uac", "uac", "linux")
    a.display, b.display = "web-01_uac [2026-01-01]", "web-01_uac [2026-02-01]"
    units = [(Unit("HOST-01", Path("."), [live, vss], ["C", "VSS1"]), []),
             (Unit("web-01_uac", Path("."), [a], ["live"]), []),
             (Unit("web-01_uac", Path("."), [b], ["live"]), []),
             (Unit("db-01_uac", Path("."), [_m("db-01_uac", "uac", "linux")], ["live"]), [])]
    assert cli._unit_labels(units) == ["HOST-01 [LR, 1 VSS]", "web-01_uac [2026-01-01]",
                                       "web-01_uac [2026-02-01]", "db-01 [UAC]"]
