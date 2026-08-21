from artifact_engine.config import Config
from artifact_engine.core import runner, scheduler
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.models import ParserManifest


def _machine(tmp_path):
    vol = Volume(name="live", path=tmp_path, is_live=True)
    m = Machine(name="h", os="linux", collector="uac", profile_id="uac",
                path=tmp_path, source="src", volumes=[vol])
    m.display = "h"
    return m, vol


def test_scheduler_preskips_cached_tasks(tmp_path, monkeypatch):
    m, _ = _machine(tmp_path)
    p_cached = ParserManifest(id="p_cached", os="linux", category="systeminfo", handler="x:run")
    p_run = ParserManifest(id="p_run", os="linux", category="systeminfo", handler="x:run")

    out = scheduler._out_dir(m, "systeminfo")
    out.mkdir(parents=True, exist_ok=True)
    runner.marker_path(out, "p_cached").write_text(   # pretend already parsed (valid fingerprint)
        runner.parser_fingerprint(p_cached), encoding="utf-8")

    called: list[str] = []

    def fake_run_parser(parser, ctx, force=False):
        called.append(parser.id)
        return runner.ParserRun(parser.id, ctx.volume, "ok", 0.1, "")

    monkeypatch.setattr(runner, "run_parser", fake_run_parser)
    cfg = Config(parse_processes=False)   # threads -> in-process so the patch applies
    results = scheduler.run_all([m], [p_cached, p_run], cfg, force=False)

    runs = {r.parser_id: r for r in results[0][1]}
    assert called == ["p_run"]                              # cached task never dispatched
    assert runs["p_cached"].status == "skipped" and runs["p_cached"].detail == "already parsed"
    assert runs["p_cached"].duration_s == 0.0
    assert runs["p_run"].status == "ok"


def test_shellbags_land_in_filesystemaccess_with_named_prefix(tmp_path):
    """Shellbags (SBECmd) get their own `FilesystemAccess/` folder instead of being
    buried in `Registry/`, and the per-user/hive CSVs are prefixed `shellbags_` so
    the filename names the artifact (shellbags_<user>_<hive>.csv)."""
    m, _ = _machine(tmp_path)
    out = scheduler._out_dir(m, "shellbags")
    assert out.name == "FilesystemAccess"                 # dedicated folder, not Registry
    for stem in ("Administrador_NTUSER", "jdoe_UsrClass"):
        assert runner._short_stem(stem, "shellbags") == f"shellbags_{stem}"


def test_plan_pools():
    from artifact_engine.core.scheduler import _plan_pools
    W = 16
    # All-Linux run (handlers only): process pool only, no thread pool -> no 2x.
    assert _plan_pools(py=176, cmd=0, max_workers=W, parse_processes=True) == (True, 16, 0)
    # Small / cached re-run: python <= workers -> threads, no process spawn (#3).
    assert _plan_pools(py=12, cmd=0, max_workers=W, parse_processes=True) == (False, 0, 12)
    # Mixed batch: each pool sized to its OWN load, not the total (#2).
    assert _plan_pools(py=176, cmd=40, max_workers=W, parse_processes=True) == (True, 16, 16)
    assert _plan_pools(py=176, cmd=4, max_workers=W, parse_processes=True) == (True, 16, 4)
    # Windows-only (all command parsers): threads only.
    assert _plan_pools(py=0, cmd=200, max_workers=W, parse_processes=True) == (False, 0, 16)
    # Boundary: python == workers -> not worth spawning (#3 needs > workers).
    assert _plan_pools(py=16, cmd=0, max_workers=W, parse_processes=True) == (False, 0, 16)
    assert _plan_pools(py=17, cmd=0, max_workers=W, parse_processes=True)[0] is True
    # parse_processes disabled -> never spawn, python on threads.
    assert _plan_pools(py=176, cmd=0, max_workers=W, parse_processes=False) == (False, 0, 16)


def test_scheduler_force_reruns_cached(tmp_path, monkeypatch):
    m, _ = _machine(tmp_path)
    p = ParserManifest(id="p", os="linux", category="systeminfo", handler="x:run")
    out = scheduler._out_dir(m, "systeminfo")
    out.mkdir(parents=True, exist_ok=True)
    runner.marker_path(out, "p").write_text(runner.parser_fingerprint(p), encoding="utf-8")

    called: list[str] = []

    def fake_run_parser(parser, ctx, force=False):
        called.append(parser.id)
        return runner.ParserRun(parser.id, ctx.volume, "ok", 0.1, "")

    monkeypatch.setattr(runner, "run_parser", fake_run_parser)
    cfg = Config(parse_processes=False)
    scheduler.run_all([m], [p], cfg, force=True)
    assert called == ["p"]                                  # --force dispatches despite a valid marker


def test_fingerprint_invalidates_stale_marker(tmp_path):
    p = ParserManifest(id="bash", os="linux", category="systeminfo",
                       handler="artifact_engine.handlers.lin_bash:run")
    out = tmp_path
    marker = runner.marker_path(out, "bash")

    marker.write_text("ok", encoding="utf-8")                 # legacy marker content
    assert not runner.is_cached(p, out)                       # mismatch -> re-run
    marker.write_text(runner.parser_fingerprint(p), encoding="utf-8")
    assert runner.is_cached(p, out)                           # fingerprint matches -> cached
    # a manifest change (extra `requires`) changes the fingerprint -> stale again
    p2 = ParserManifest(id="bash", os="linux", category="systeminfo",
                        handler="artifact_engine.handlers.lin_bash:run", requires=["x"])
    assert not runner.is_cached(p2, out)
