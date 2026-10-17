"""v0.7.160: a parser re-runs when an analyst-editable list it reads changes, not
only when its code does -- and a parser parsed before this adopts the lists as
they are instead of re-running."""
from __future__ import annotations

from artifact_engine.config import Config
from artifact_engine.core import asset_state, runner, scheduler
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.models import ParserManifest

_HANDLER = '''
from pathlib import Path

def run(ctx):
    Path(ctx.assets, "lists.txt").read_text()
    for f in Path(ctx.assets, "rules").rglob("*"):
        pass
    Path(ctx.assets, "geo.mmdb")
'''


def _setup(tmp_path, monkeypatch, name):
    mods = tmp_path / "mods"
    mods.mkdir()
    (mods / f"{name}.py").write_text(_HANDLER, encoding="utf-8")
    monkeypatch.syspath_prepend(str(mods))
    assets = tmp_path / "assets"
    (assets / "rules").mkdir(parents=True)
    for rel in ("lists.txt", "rules/a.yar", "other.txt", "geo.mmdb"):
        (assets / rel).write_text("v1\n", encoding="utf-8")
    vol = Volume(name="live", path=tmp_path, is_live=True)
    m = Machine(name="h", os="linux", collector="uac", profile_id="uac",
                path=tmp_path, source="src", volumes=[vol])
    m.display = "h"
    reader = ParserManifest(id="reader", os="linux", category="systeminfo", handler=f"{name}:run")
    after = ParserManifest(id="after", os="linux", category="systeminfo", handler="x:run",
                           depends_on=["reader"])
    called: list[str] = []
    during: list = []                  # what happens to the lists while it runs

    def fake_run_parser(parser, ctx, force=False):
        if runner.is_cached(parser, ctx.out, force):
            return runner.cached_run(parser, ctx.volume)
        called.append(parser.id)
        for act in during:
            act()
        ctx.out.mkdir(parents=True, exist_ok=True)
        runner.marker_path(ctx.out, parser.id).write_text(
            runner.parser_fingerprint(parser), encoding="utf-8")
        return runner.ParserRun(parser.id, ctx.volume, "ok", 0.1, "")

    monkeypatch.setattr(runner, "run_parser", fake_run_parser)
    cfg = Config(parse_processes=False, assets_dir=assets)
    out = scheduler._out_dir(m, "systeminfo")

    def run(fail=False, while_running=None, status=None):
        called.clear()
        during[:] = [while_running] if while_running else []
        if fail or status:
            monkeypatch.setattr(runner, "run_parser", lambda p, ctx, force=False: (
                called.append(p.id),
                runner.ParserRun(p.id, ctx.volume, status or "error", 0.1, "x"))[1])
        scheduler.run_all([m], [after, reader], cfg, force=False)
        monkeypatch.setattr(runner, "run_parser", fake_run_parser)
        return sorted(called)

    return assets, out, reader, run


def test_what_a_parser_reads_comes_from_its_code(tmp_path, monkeypatch):
    assets, _, reader, _ = _setup(tmp_path, monkeypatch, "aeng_probe_used")
    # named in its code: the list and the rules dir; never named: other.txt; and
    # the IP databases are not followed, whoever names them
    assert asset_state.used(reader, assets) == ["lists.txt", "rules"]
    nothing = ParserManifest(id="n", os="linux", category="systeminfo", handler="x:run")
    assert asset_state.used(nothing, assets) == []
    assert asset_state.digest(nothing, assets) == asset_state.NONE
    tool = ParserManifest(id="t", os="windows", category="registry", tool={"binary": "x.exe"},
                          command=["{binary}", "--bn", "{assets}/rules/a.yar"])
    assert asset_state.used(tool, assets) == ["rules"]


def test_an_edited_list_reruns_the_parser_and_what_reads_it(tmp_path, monkeypatch):
    assets, out, _, run = _setup(tmp_path, monkeypatch, "aeng_probe_edit")
    assert run() == ["after", "reader"]                  # first run: both, and recorded
    assert asset_state.record_path(out, "reader").is_file()
    # one that reads no list says so: a list that appears later is a change
    assert asset_state.record_path(out, "after").read_text(encoding="utf-8") == asset_state.NONE
    assert run() == []                                   # nothing changed: cached

    (assets / "lists.txt").write_text("v2\n", encoding="utf-8")
    assert run() == ["after", "reader"]                  # its dependent follows it
    assert run() == []                                   # and the new state is recorded

    (assets / "rules" / "b.yar").write_text("new rule\n", encoding="utf-8")
    assert run() == ["after", "reader"]                  # a file added to a read dir
    (assets / "other.txt").write_text("v2\n", encoding="utf-8")
    (assets / "geo.mmdb").write_text("v2\n", encoding="utf-8")
    assert run() == []                                   # not read, or not followed


def test_a_parser_parsed_before_this_adopts_the_lists_as_they_are(tmp_path, monkeypatch):
    assets, out, reader, run = _setup(tmp_path, monkeypatch, "aeng_probe_adopt")
    assert run() == ["after", "reader"]
    rec = asset_state.record_path(out, "reader")
    rec.unlink()                                         # a marker from before v0.7.160
    mk = runner.marker_path(out, "reader")
    stamp = mk.stat().st_mtime_ns
    assert run() == []                                   # not re-run on upgrade
    assert rec.read_text(encoding="utf-8") == asset_state.digest(reader, assets)
    assert mk.stat().st_mtime_ns == stamp                # the marker orders dependents
    (assets / "lists.txt").write_text("v2\n", encoding="utf-8")
    assert run() == ["after", "reader"]                  # from then on it follows them


def test_a_failed_run_keeps_the_old_record_so_the_next_run_retries(tmp_path, monkeypatch):
    assets, out, _, run = _setup(tmp_path, monkeypatch, "aeng_probe_fail")
    assert run() == ["after", "reader"]
    before = asset_state.record_path(out, "reader").read_text(encoding="utf-8")
    (assets / "lists.txt").write_text("v2\n", encoding="utf-8")
    assert "reader" in run(fail=True)
    assert asset_state.record_path(out, "reader").read_text(encoding="utf-8") == before
    assert run() == ["after", "reader"]


def test_a_list_that_appears_later_or_is_deleted_is_a_change(tmp_path, monkeypatch):
    """A list `aeng update` writes after a case was parsed (the awesome lists,
    LOTTunnels), and the last list a parser read being deleted."""
    assets, _, _, run = _setup(tmp_path, monkeypatch, "aeng_probe_appear")
    (assets / "lists.txt").unlink()
    for f in (assets / "rules").iterdir():
        f.unlink()
    (assets / "rules").rmdir()
    assert run() == ["after", "reader"]
    assert run() == []
    (assets / "lists.txt").write_text("v1\n", encoding="utf-8")
    assert run() == ["after", "reader"]                  # appeared
    (assets / "lists.txt").unlink()
    assert run() == ["after", "reader"]                  # gone again
    assert run() == []


def test_a_list_edited_while_the_parser_runs_is_a_change_next_time(tmp_path, monkeypatch):
    """What is recorded is the state at dispatch: the handler may have read the
    list before the edit, so the edit must still count."""
    assets, _, _, run = _setup(tmp_path, monkeypatch, "aeng_probe_race")
    assert run() == ["after", "reader"]
    (assets / "lists.txt").write_text("v2\n", encoding="utf-8")
    edit = lambda: (assets / "lists.txt").write_text("v3\n", encoding="utf-8")
    assert run(while_running=edit) == ["after", "reader"]
    assert run() == ["after", "reader"]                  # v3 not applied yet: runs again
    assert run() == []


def test_a_run_whose_result_never_came_back_runs_again(tmp_path, monkeypatch):
    """The worker writes the marker before the parent hears the result; a parent
    that dies in between (the native crash, Ctrl+C) leaves a marker and a record
    still saying the run is under way -- which matches no state, so the next run
    runs it instead of adopting the lists as they are by then."""
    assets, out, _, run = _setup(tmp_path, monkeypatch, "aeng_probe_crash")
    assert run() == ["after", "reader"]
    rec = asset_state.record_path(out, "reader")
    seen = []
    assert run(while_running=lambda: seen.append(rec.read_text(encoding="utf-8")),
               ) == []                                   # cached: nothing dispatched
    (assets / "lists.txt").write_text("v2\n", encoding="utf-8")
    assert run(while_running=lambda: seen.append(rec.read_text(encoding="utf-8"))) == [
        "after", "reader"]
    assert seen[0] == asset_state.RUNNING                # under way while it ran
    rec.write_text(asset_state.RUNNING, encoding="utf-8")  # as a crash leaves it
    assert run() == ["after", "reader"]
    assert run() == []


def test_a_forced_run_that_skips_has_not_applied_the_lists(tmp_path, monkeypatch):
    """A skip leaves the old tables, whatever caused it (yara-python missing, the
    lists deleted), so the edit still counts on the next run."""
    assets, _, _, run = _setup(tmp_path, monkeypatch, "aeng_probe_skip")
    assert run() == ["after", "reader"]
    (assets / "lists.txt").write_text("v2\n", encoding="utf-8")
    assert "reader" in run(status="skipped")
    assert run() == ["after", "reader"]
    assert run() == []
