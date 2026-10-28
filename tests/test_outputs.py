"""A re-run that finds less removes what the last one wrote (v0.7.106)."""

import logging
from pathlib import Path

from artifact_engine.core import outputs
from artifact_engine.core.runner import HandlerSkip, ParserContext, run_parser
from artifact_engine.models import ParserManifest


def _planned(ctx) -> None:
    """Writes the tables `plan.txt` names; `skip` / `fail` instead skip or fail."""
    plan = (Path(ctx.evidence) / "plan.txt").read_text(encoding="utf-8").split()
    if "fail" in plan:
        raise RuntimeError("planned failure")
    if "skip" in plan:
        raise HandlerSkip("nothing here")
    ctx.out.mkdir(parents=True, exist_ok=True)
    for name in plan:
        if name.endswith("/"):
            (ctx.out / name.rstrip("/")).mkdir()
            (ctx.out / name.rstrip("/") / "inner.csv").write_text("a\n1\n", encoding="utf-8")
        else:
            (ctx.out / name).write_text("a\n1\n", encoding="utf-8")


def _run(tmp_path: Path, plan: str, pid="hunt"):
    (tmp_path / "plan.txt").write_text(plan, encoding="utf-8")
    out = tmp_path / "CSVs" / "Detections"
    ctx = ParserContext(evidence=tmp_path, out=out, tools=tmp_path, assets=tmp_path,
                        machine_name="HOST-01", volume="C", log=logging.getLogger("aeng.test"))
    p = ParserManifest(id=pid, handler=f"{__name__}:_planned")
    return run_parser(p, ctx, force=True), out


def test_a_table_the_rerun_no_longer_writes_is_removed(tmp_path):
    r, out = _run(tmp_path, "a.csv b.csv dir/")
    assert r.status == "ok" and {"a.csv", "b.csv", "dir"} <= {p.name for p in out.iterdir()}
    (out / "other.csv").write_text("x\n", encoding="utf-8")           # another parser's table
    r, out = _run(tmp_path, "a.csv")
    names = {p.name for p in out.iterdir()}
    assert "a.csv" in names and "b.csv" not in names and "dir" not in names
    assert "other.csv" in names                                         # never ours to remove


def test_a_skip_or_an_error_keeps_the_last_result(tmp_path):
    _run(tmp_path, "a.csv")
    r, out = _run(tmp_path, "fail")
    assert r.status == "error" and (out / "a.csv").exists()            # best result there is
    r, out = _run(tmp_path, "skip")                     # may be a quarantined tool, not evidence
    assert r.status == "skipped" and (out / "a.csv").exists()


def test_a_name_that_only_changed_case_is_the_fresh_table(tmp_path):
    _run(tmp_path, "Evtx_RDP.csv")
    r, out = _run(tmp_path, "evtx_rdp.csv")
    assert r.status == "ok" and [p.name.lower() for p in out.glob("*.csv")] == ["evtx_rdp.csv"]


def test_a_name_another_parser_took_since_is_kept(tmp_path):
    import os
    _run(tmp_path, "alert_rmm.csv", pid="old")
    out = tmp_path / "CSVs" / "Detections"
    (out / "alert_rmm.csv").write_text("new owner\n", encoding="utf-8")       # another parser
    st = (out / "alert_rmm.csv").stat()
    os.utime(out / "alert_rmm.csv", ns=(st.st_atime_ns, st.st_mtime_ns + 1000))
    _run(tmp_path, "other.csv", pid="old")
    assert (out / "alert_rmm.csv").read_text(encoding="utf-8") == "new owner\n"


def _partial_then_fail(ctx) -> None:
    ctx.out.mkdir(parents=True, exist_ok=True)
    (ctx.out / "views.csv").write_text("a\n2\n", encoding="utf-8")
    raise RuntimeError("the last view failed")


def test_what_a_failed_run_merged_is_still_cleaned_later(tmp_path):
    import os
    _run(tmp_path, "views.csv")
    out = tmp_path / "CSVs" / "Detections"
    st = (out / "views.csv").stat()
    ctx = ParserContext(evidence=tmp_path, out=out, tools=tmp_path, assets=tmp_path,
                        machine_name="HOST-01", volume="C", log=logging.getLogger("aeng.test"))
    r = run_parser(ParserManifest(id="hunt", handler=f"{__name__}:_partial_then_fail"), ctx, force=True)
    assert r.status == "error" and (out / "views.csv").read_text(encoding="utf-8") == "a\n2\n"
    os.utime(out / "views.csv", ns=(st.st_atime_ns, st.st_mtime_ns + 7))     # surely rewritten
    r = run_parser(ParserManifest(id="hunt", handler=f"{__name__}:_partial_then_fail"), ctx, force=True)
    _run(tmp_path, "a.csv")                                   # ok, no views this time
    assert not (out / "views.csv").exists()


def test_another_parsers_record_is_its_own(tmp_path):
    _run(tmp_path, "a.csv", pid="one")
    _r, out = _run(tmp_path, "b.csv", pid="two")
    _run(tmp_path, "c.csv", pid="two")
    assert (out / "a.csv").exists() and not (out / "b.csv").exists()


def test_a_locked_stale_table_is_retried(tmp_path, monkeypatch):
    _run(tmp_path, "a.csv b.csv")
    real = Path.unlink

    def locked(self, *a, **k):
        if self.name == "b.csv":
            raise PermissionError("open in Excel")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", locked)
    _r, out = _run(tmp_path, "a.csv")
    assert (out / "b.csv").exists()
    assert "b.csv" in outputs.record_path(out, "hunt").read_text(encoding="utf-8").split()
    monkeypatch.setattr(Path, "unlink", real)
    _run(tmp_path, "a.csv")
    assert not (out / "b.csv").exists()


def test_a_record_naming_a_path_is_never_followed(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (tmp_path / "victim.csv").write_text("x\n", encoding="utf-8")
    (out / ".p.done").write_text("fp", encoding="utf-8")
    v, d = (tmp_path / "victim.csv").stat().st_mtime_ns, (out / ".p.done").stat().st_mtime_ns
    outputs.record_path(out, "p").write_text(f"../victim.csv\t{v}\n.p.done\t{d}\n",
                                             encoding="utf-8")
    assert outputs.settle(out, "p", []) == []
    assert (tmp_path / "victim.csv").exists() and (out / ".p.done").exists()


def test_settle_compares_names_without_case_for_an_unchanged_file(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "evtx_rdp.csv").write_text("a\n", encoding="utf-8")
    stamp = (out / "evtx_rdp.csv").stat().st_mtime_ns            # unchanged since recorded
    outputs.record_path(out, "p").write_text(f"Evtx_RDP.csv\t{stamp}\n", encoding="utf-8")
    assert outputs.settle(out, "p", ["evtx_rdp.csv"]) == []
    assert (out / "evtx_rdp.csv").exists()


def test_without_a_record_the_declared_outputs_stand_in(tmp_path):
    import os
    import time
    out = tmp_path / "CSVs" / "Detections"
    out.mkdir(parents=True)
    old = time.time() - 60
    for name in ("declared.csv", "undeclared.csv"):             # left by a run before v0.7.106
        (out / name).write_text("a\n", encoding="utf-8")
        os.utime(out / name, (old, old))
    (out / "taken.csv").write_text("a\n", encoding="utf-8")       # a sibling, during this run
    later = time.time() + 60
    os.utime(out / "taken.csv", (later, later))
    (tmp_path / "plan.txt").write_text("a.csv", encoding="utf-8")
    ctx = ParserContext(evidence=tmp_path, out=out, tools=tmp_path, assets=tmp_path,
                        machine_name="HOST-01", volume="C", log=logging.getLogger("aeng.test"))
    p = ParserManifest(id="hunt", handler=f"{__name__}:_planned",
                       outputs=[{"path": "{out}/declared.csv"}, {"path": "{out}/sub/x.csv"},
                                {"path": "{out}/taken.csv"}])
    assert run_parser(p, ctx, force=True).status == "ok"
    assert not (out / "declared.csv").exists() and (out / "undeclared.csv").exists()
    assert (out / "taken.csv").exists()


def test_a_first_failed_run_keeps_the_declared_outputs_in_view(tmp_path):
    import os
    import time
    out = tmp_path / "CSVs" / "Detections"
    out.mkdir(parents=True)
    old = time.time() - 60
    (out / "declared.csv").write_text("a\n", encoding="utf-8")   # from before v0.7.106
    os.utime(out / "declared.csv", (old, old))
    ctx = ParserContext(evidence=tmp_path, out=out, tools=tmp_path, assets=tmp_path,
                        machine_name="HOST-01", volume="C", log=logging.getLogger("aeng.test"))
    decl = [{"path": "{out}/declared.csv"}]
    r = run_parser(ParserManifest(id="hunt", handler=f"{__name__}:_partial_then_fail",
                                  outputs=decl), ctx, force=True)
    assert r.status == "error" and (out / "declared.csv").exists()
    (tmp_path / "plan.txt").write_text("a.csv", encoding="utf-8")
    r = run_parser(ParserManifest(id="hunt", handler=f"{__name__}:_planned", outputs=decl),
                   ctx, force=True)
    assert r.status == "ok"
    assert not (out / "declared.csv").exists() and not (out / "views.csv").exists()


def test_without_a_record_nothing_is_removed(tmp_path):
    out = tmp_path / "CSVs" / "Detections"
    out.mkdir(parents=True)
    (out / "left_over.csv").write_text("a\n", encoding="utf-8")   # from before v0.7.106
    _run(tmp_path, "a.csv")
    assert (out / "left_over.csv").exists()
