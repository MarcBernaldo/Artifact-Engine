"""v0.7.156: a parser that no longer exists -- renamed, or folded into another --
is retired by its successor's `replaces:`, so its last table is not consolidated
beside the one that replaced it."""

import logging
import os
from pathlib import Path

from artifact_engine.core import outputs
from artifact_engine.core.runner import ParserContext, marker_path, run_parser
from artifact_engine.models import ParserManifest


def _write_new(ctx) -> None:
    ctx.out.mkdir(parents=True, exist_ok=True)
    (ctx.out / "new.csv").write_text("a\n1\n", encoding="utf-8")


def _old_planned(ctx) -> None:
    ctx.out.mkdir(parents=True, exist_ok=True)
    (ctx.out / "old.csv").write_text("a\n1\n", encoding="utf-8")


def _ctx(tmp_path: Path) -> ParserContext:
    return ParserContext(evidence=tmp_path, out=tmp_path / "CSVs" / "Web", tools=tmp_path,
                         assets=tmp_path, machine_name="HOST-01", volume="live",
                         log=logging.getLogger("aeng.test"))


def _old_run(tmp_path: Path) -> Path:
    """What the retired parser left: its table, its record, its marker."""
    ctx = _ctx(tmp_path)
    assert run_parser(ParserManifest(id="old", handler=f"{__name__}:_old_planned"), ctx,
                      force=True).status == "ok"
    return ctx.out


def _successor(tmp_path: Path, replaces=None):
    p = ParserManifest(id="new", handler=f"{__name__}:_write_new",
                       replaces=replaces if replaces is not None else {"old": ["old.csv"]})
    return run_parser(p, _ctx(tmp_path), force=True)


def test_the_successor_removes_the_retired_table_record_and_marker(tmp_path):
    out = _old_run(tmp_path)
    assert (out / "old.csv").exists() and marker_path(out, "old").exists()
    assert _successor(tmp_path).status == "ok"
    names = {p.name for p in out.iterdir()}
    assert "old.csv" not in names and ".old.outputs" not in names and ".old.done" not in names
    assert "new.csv" in names


def test_without_replaces_the_retired_table_stays(tmp_path):
    out = _old_run(tmp_path)
    _successor(tmp_path, replaces={})
    assert (out / "old.csv").exists()


def test_a_declared_table_goes_even_when_restamped_since(tmp_path):
    # saved from Excel, or re-stamped by a zip or FAT copy: still the retired table
    out = _old_run(tmp_path)
    st =(out / "old.csv").stat()
    os.utime(out / "old.csv", ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
    assert _successor(tmp_path).status == "ok"
    assert not (out / "old.csv").exists() and not (out / ".old.outputs").exists()


def test_a_name_only_the_record_holds_goes_only_if_unchanged(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    for n in ("a.csv", "b.csv"):
        (out / n).write_text("x\n", encoding="utf-8")
    st = (out / "b.csv").stat()
    (out / ".old.outputs").write_text(
        f"a.csv\t{(out / 'a.csv').stat().st_mtime_ns}\nb.csv\t{st.st_mtime_ns}\n", encoding="utf-8")
    os.utime(out / "b.csv", ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
    assert outputs.retire(out, "old") == []
    assert not (out / "a.csv").exists() and (out / "b.csv").exists()
    assert not (out / ".old.outputs").exists()


def test_with_no_record_the_declared_names_go_but_never_what_the_successor_wrote(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "old.csv").write_text("a\n", encoding="utf-8")
    (out / ".old.done").write_text("x", encoding="utf-8")
    assert outputs.retire(out, "old", ["old.csv"]) == []
    assert not (out / "old.csv").exists()
    assert not (out / ".old.done").exists() and not (out / ".old.outputs").exists()
    (out / "old.csv").write_text("the successor's\n", encoding="utf-8")
    assert outputs.retire(out, "old", ["old.csv"], ["OLD.csv"]) == []
    assert (out / "old.csv").exists()


def _write_old_name(ctx) -> None:
    ctx.out.mkdir(parents=True, exist_ok=True)
    (ctx.out / "old.csv").write_text("new rows\n", encoding="utf-8")


def test_a_successor_that_kept_the_old_table_name_keeps_its_table(tmp_path):
    out = _old_run(tmp_path)
    p = ParserManifest(id="new", handler=f"{__name__}:_write_old_name",
                       replaces={"old": ["old.csv"]})
    assert run_parser(p, _ctx(tmp_path), force=True).status == "ok"
    assert (out / "old.csv").read_text(encoding="utf-8") == "new rows\n"
    assert not (out / ".old.outputs").exists() and not (out / ".old.done").exists()


def test_a_retired_parser_never_here_leaves_no_record(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    assert outputs.retire(out, "old", ["old.csv"]) == []
    assert list(out.iterdir()) == []


def test_a_locked_retired_table_fails_the_run_so_the_next_one_retries(tmp_path, monkeypatch):
    out = _old_run(tmp_path)
    real = Path.unlink

    def locked(self, *a, **k):
        if self.name == "old.csv":
            raise PermissionError("open in Excel")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", locked)
    run = _successor(tmp_path)
    assert run.status == "error" and "old.csv" in run.detail
    assert (out / "old.csv").exists() and (out / ".old.outputs").exists()
    # no marker: the scheduler would take a marked parser as cached and never
    # come back to the retired table
    assert not marker_path(out, "new").exists()
    monkeypatch.setattr(Path, "unlink", real)
    p = ParserManifest(id="new", handler=f"{__name__}:_write_new",
                       replaces={"old": ["old.csv"]})
    assert run_parser(p, _ctx(tmp_path)).status == "ok"          # not forced
    assert not (out / "old.csv").exists() and not (out / ".old.outputs").exists()
    assert marker_path(out, "new").exists()
