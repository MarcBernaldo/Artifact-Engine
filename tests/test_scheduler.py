import sys

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


def test_a_handlers_log_call_survives_the_process_pool(tmp_path, monkeypatch):
    """A worker's `aeng` logger has no handlers -- `setup_logging` runs in the
    parent and a spawned child starts from an empty logging config -- so
    `ctx.log.warning("hayabusa exit 0xC0000142")` reached nothing at all. Measured
    before the fix: three of three messages lost, including every warning.

    v0.7.9 carried the TRACEBACK back as data for this reason and left every
    deliberate diagnostic behind it. This is the same trick, generalised."""
    import logging

    from artifact_engine.core import runner

    aeng = logging.getLogger("aeng")
    kept = aeng.handlers[:]
    aeng.handlers = []                      # stand in for a fresh worker
    try:
        cap = runner._CaptureLog()
        aeng.addHandler(cap)
        aeng.setLevel(logging.DEBUG)
        aeng.warning("[!] hayabusa exit 0xC0000142")
        aeng.debug("web_metrics: 91 IP(s)")
        aeng.removeHandler(cap)
    finally:
        aeng.handlers = kept

    assert [m for _, m in cap.records] == ["[!] hayabusa exit 0xC0000142",
                                           "web_metrics: 91 IP(s)"]
    assert [lv for lv, _ in cap.records] == [logging.WARNING, logging.DEBUG], \
        "the level must survive: the parent re-filters on replay"

    # and the parent emits them for real, at the level the handler chose
    seen: list[tuple[int, str]] = []
    monkeypatch.setattr(runner.log, "log", lambda lv, msg: seen.append((lv, msg)))
    runner.replay_logs(runner.ParserRun("hayabusa", "C", "ok", 1.0, logs=cap.records))
    assert seen == cap.records


def test_nothing_is_captured_where_logging_already_works(tmp_path, monkeypatch):
    """Every `command:` parser runs on a thread in the PARENT, where logging
    already reaches the file. Capturing there too would replay each line a second
    time, so the absence of a handler -- the worker signature -- is what decides.
    Run one for real with the parent configured and nothing should come back."""
    import logging

    from artifact_engine.core.runner import ParserContext

    said = []

    def handler(ctx):
        logging.getLogger("aeng").warning("from a parent thread")
        said.append(True)

    mod = type(sys)("fake_handler_mod")
    mod.run = handler
    monkeypatch.setitem(sys.modules, "fake_handler_mod", mod)
    p = ParserManifest(id="p", os="linux", category="systeminfo",
                       handler="fake_handler_mod:run")

    aeng = logging.getLogger("aeng")
    kept = aeng.handlers[:]
    aeng.handlers = [logging.NullHandler()]          # a configured parent
    try:
        run = runner.run_parser(p, ParserContext(
            evidence=tmp_path, out=tmp_path / "out", tools=tmp_path,
            assets=tmp_path, machine_name="h", volume="live", log=aeng))
    finally:
        aeng.handlers = kept

    assert said, "the handler never ran"
    assert run.logs == [], "captured in the parent, so the line would be logged twice"


def test_a_flood_of_log_lines_cannot_grow_the_result_without_bound():
    """The records cross a pickle boundary back to the parent. A handler logging
    per row would otherwise return a result proportional to the evidence."""
    from artifact_engine.core import runner

    cap = runner._CaptureLog(cap=5)
    for i in range(50):
        cap.emit(_rec(f"line {i}"))
    assert len(cap.records) == 5
    assert cap.dropped == 45, "what was dropped has to be countable, not silent"


def test_pool_workers_are_given_their_own_cancel_hook():
    """`procs._active` is module state and a spawned worker has its own copy, so
    the parent's cancel_all() only reaches Popens the parent opened. Four parsers
    (deepblue, hayabusa, sum, usn) are Python handlers with no `command:`: they run
    in the pool and open their tool there, outside that guarantee. Ctrl+C reaches
    those tools through the console group anyway -- what the parent cannot do for
    them is escalate to kill() when one ignores it."""
    import inspect
    import signal

    from artifact_engine.core import scheduler

    src = inspect.getsource(scheduler.run_all)
    assert "initializer=_worker_init" in src, \
        "the process pool was created without the worker's cancel hook"

    previous = signal.getsignal(signal.SIGINT)
    try:
        scheduler._worker_init()
        assert signal.getsignal(signal.SIGINT) is not previous, \
            "_worker_init installed nothing"
    finally:
        signal.signal(signal.SIGINT, previous)


def _rec(msg):
    import logging
    return logging.LogRecord('aeng', logging.INFO, __file__, 1, msg, None, None)


def test_a_run_that_reports_parser_errors_does_not_exit_clean(tmp_path, monkeypatch):
    """`aeng run` printed "[!] 3 parser error(s)" and returned 0, so anything that
    chained off it -- a scheduled collection, a wrapper script, CI -- learned that
    the exit code carries no information. 2 rather than 1: the run finished and its
    output is on disk, which is a different thing from the command refusing to
    start."""
    import argparse

    from artifact_engine import cli
    from artifact_engine.core import report

    def summary(root, results, errors=0):
        return {"machines": 0, "per_machine": [],
                "totals": {"ok": 0, "skipped": 0, "errors": errors}}

    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)

    monkeypatch.setattr(report, "build_run_summary",
                        lambda r, x, incomplete=None: summary(r, x, errors=0))
    assert cli.cmd_run(args) == 0, "a clean run must stay 0"

    monkeypatch.setattr(report, "build_run_summary",
                        lambda r, x, incomplete=None: summary(r, x, errors=3))
    assert cli.cmd_run(args) == cli.EXIT_INCOMPLETE == 2


def test_the_configured_internal_ranges_reach_the_handler(tmp_path, monkeypatch):
    """`ParserContext.internal_networks` is the only channel configuration has into
    a handler, and it crosses a process boundary as one element of a task payload.
    Every link between `Config` and `ctx` is exercised here, because a break in any
    of them is silent: the handler simply sees nothing declared and reports every
    internal address as an internet source."""
    m, _ = _machine(tmp_path)
    p = ParserManifest(id="p_net", os="linux", category="systeminfo", handler="x:run")
    seen: list[tuple] = []

    def fake_run_parser(parser, ctx, force=False):
        seen.append(ctx.internal_networks)
        return runner.ParserRun(parser.id, ctx.volume, "ok", 0.1, "")

    monkeypatch.setattr(runner, "run_parser", fake_run_parser)
    cfg = Config(parse_processes=False, internal_networks=["1.2.3.0/24"])
    scheduler.run_all([m], [p], cfg, force=False)
    assert seen == [("1.2.3.0/24",)]


def test_declaring_nothing_reaches_the_handler_as_nothing(tmp_path, monkeypatch):
    m, _ = _machine(tmp_path)
    p = ParserManifest(id="p_none", os="linux", category="systeminfo", handler="x:run")
    seen: list[tuple] = []

    def fake_run_parser(parser, ctx, force=False):
        seen.append(ctx.internal_networks)
        return runner.ParserRun(parser.id, ctx.volume, "ok", 0.1, "")

    monkeypatch.setattr(runner, "run_parser", fake_run_parser)
    scheduler.run_all([m], [p], Config(parse_processes=False), force=False)
    assert seen == [()]
