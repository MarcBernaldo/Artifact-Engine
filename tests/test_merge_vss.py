"""Merging a host's live volume with its shadow copies into one .db/.xlsx."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from artifact_engine import cli
from artifact_engine.config import load_config
from artifact_engine.core import consolidate, report
from artifact_engine.core.detector import Machine, Volume


def _machine(path: Path, name: str, label: str, is_vss: bool = False) -> Machine:
    return Machine(name, "windows", "kape", "windows_kape", path, "acq",
                   [Volume(label, path, not is_vss)], is_vss=is_vss)


def _host(tmp_path: Path, volumes: dict[str, dict[str, str]]) -> list[Machine]:
    """A collection folder with one machine per volume.

    `volumes` maps volume label -> {relative CSV path: contents}, e.g.
    {"C": {"EventLogs/evtx_Security.csv": "a,b\\n1,2\\n"}}.
    """
    coll = tmp_path / "acq"
    machines = []
    for label, files in volumes.items():
        base = coll / label
        for rel, text in files.items():
            f = base / "CSVs" / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, encoding="utf-8")
        base.mkdir(parents=True, exist_ok=True)
        live = label.upper() == "C"
        machines.append(_machine(base, "HOST" if live else f"HOST_{label}", label, not live))
    return machines


def _unit(machines: list[Machine]) -> consolidate.Unit:
    units = consolidate.plan_units([(m, []) for m in machines], merge_vss=True)
    assert len(units) == 1, "the live volume and its snapshots must form ONE unit"
    return units[0][0]


def _query(db: Path, sql: str) -> list[tuple]:
    conn = sqlite3.connect(db)          # `with` commits, it does NOT close: on
    try:                                # Windows a leaked handle locks the file
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def _rows(db: Path, table: str) -> list[tuple]:
    return _query(db, f'SELECT * FROM "{table}"')


def _cols(db: Path, table: str) -> list[str]:
    return [r[1] for r in _query(db, f'PRAGMA table_info("{table}")')]


# --------------------------------------------------------------------------- #
# Grouping
# --------------------------------------------------------------------------- #
def test_a_host_and_its_snapshots_become_one_unit(tmp_path):
    ms = _host(tmp_path, {"C": {"a.csv": "x\n1\n"}, "VSS1": {"a.csv": "x\n1\n"},
                          "VSS2": {"a.csv": "x\n1\n"}})
    unit = _unit(ms)

    assert unit.merged
    assert unit.name == "HOST"
    assert unit.path == tmp_path / "acq"          # the folder the volumes share
    assert unit.labels == ["C", "VSS1", "VSS2"]   # live first, then snapshot order
    assert unit.primary is ms[0]


def test_snapshots_are_ordered_past_nine(tmp_path):
    """VSS10 comes after VSS9: the order is numeric, not the string sort that puts
    `VSS10` between `VSS1` and `VSS2`."""
    vols = {"C": {"a.csv": "x\n1\n"}}
    vols.update({f"VSS{i}": {"a.csv": "x\n1\n"} for i in (1, 2, 9, 10, 11)})
    unit = _unit(_host(tmp_path, vols))

    assert unit.labels == ["C", "VSS1", "VSS2", "VSS9", "VSS10", "VSS11"]


def test_the_flag_off_keeps_one_output_per_volume(tmp_path):
    ms = _host(tmp_path, {"C": {"a.csv": "x\n1\n"}, "VSS1": {"a.csv": "x\n1\n"}})
    units = consolidate.plan_units([(m, []) for m in ms], merge_vss=False)

    assert len(units) == 2
    assert all(not u.merged for u, _ in units)
    assert [u.path for u, _ in units] == [m.path for m in ms]   # each inside its volume


def test_a_machine_with_no_snapshots_is_untouched(tmp_path):
    m = _machine(tmp_path / "acq" / "C", "HOST", "C")
    (units,) = consolidate.plan_units([(m, [])], merge_vss=True)

    assert not units[0].merged
    assert units[0].path == m.path


def test_two_acquisitions_of_one_host_are_not_folded_together(tmp_path):
    """Regression: merging is a fold of VOLUMES, never of acquisitions.

    A LiveResponse-only collection is rooted at the collection folder itself and a
    loose EVTX drop renamed after the host it logged sits beside it, so both have
    the case root as their parent AND the same name. They were being merged, which
    conflated two acquisitions and wrote the result at the top of the case."""
    lr = _machine(tmp_path / "HOST_kape_2026", "HOST", "C")
    drop = _machine(tmp_path / "evtx-host", "HOST", "C")
    for m in (lr, drop):
        (m.path / "CSVs").mkdir(parents=True)
        (m.path / "CSVs" / "a.csv").write_text("id\n1\n", encoding="utf-8")

    units = consolidate.plan_units([(lr, []), (drop, [])], merge_vss=True)

    assert len(units) == 2
    assert all(not u.merged for u, _ in units)
    assert [u.path for u, _ in units] == [lr.path, drop.path]   # never the case root


def test_a_stray_machine_beside_a_merged_host_keeps_its_own_outputs(tmp_path):
    """The snapshots fold into the live volume; the unrelated acquisition that
    happens to share the folder and the name does not get dragged in."""
    ms = _host(tmp_path, {"C": {"a.csv": "id\n1\n"}, "VSS1": {"a.csv": "id\n1\n"}})
    stray = _machine(tmp_path / "acq" / "other", "HOST", "C")
    (stray.path / "CSVs").mkdir(parents=True)

    units = consolidate.plan_units([(m, []) for m in ms] + [(stray, [])], merge_vss=True)

    merged = [u for u, _ in units if u.merged]
    assert len(merged) == 1
    assert merged[0].labels == ["C", "VSS1"] and stray not in merged[0].members
    assert any(u.path == stray.path for u, _ in units if not u.merged)


def test_two_hosts_in_one_case_do_not_merge_into_each_other(tmp_path):
    a = _host(tmp_path / "one", {"C": {"a.csv": "x\n1\n"}, "VSS1": {"a.csv": "x\n1\n"}})
    b = _host(tmp_path / "two", {"C": {"a.csv": "x\n1\n"}, "VSS1": {"a.csv": "x\n1\n"}})
    units = consolidate.plan_units([(m, []) for m in a + b], merge_vss=True)

    assert len(units) == 2
    assert all(u.merged and len(u.members) == 2 for u, _ in units)


# --------------------------------------------------------------------------- #
# Deduplication
# --------------------------------------------------------------------------- #
def test_rows_shared_by_volumes_collapse_and_name_their_volumes(tmp_path):
    """The whole point: eleven copies of one event become one row that says where
    it was seen, and an event only a snapshot still holds survives on its own."""
    unit = _unit(_host(tmp_path, {
        # id 3 is on every volume, id 2 only on the two snapshots (the live disk
        # rolled it out), id 1 only on the oldest.
        "C":    {"EventLogs/evtx_Security.csv": "id,msg\n3,c\n"},
        "VSS1": {"EventLogs/evtx_Security.csv": "id,msg\n3,c\n2,b\n"},
        "VSS2": {"EventLogs/evtx_Security.csv": "id,msg\n3,c\n2,b\n1,a\n"},
    }))
    stats = consolidate.build_unit(unit, emit_xlsx=False)
    db = tmp_path / "acq" / "HOST.db"

    assert db.is_file()
    assert not (tmp_path / "acq" / "C" / "HOST.db").exists()   # substituted, not added
    got = {r[0]: (r[1], r[2]) for r in _rows(db, "evtx_Security")}
    assert got == {1: ("a", "VSS2"), 2: ("b", "VSS1,VSS2"), 3: ("c", "C,VSS1,VSS2")}
    assert _cols(db, "evtx_Security")[-1] == "volumes"
    assert stats["total_rows"] == 6 and stats["merged_rows"] == 3
    assert stats["unique"] == {"VSS1": 0, "VSS2": 1} or stats["unique"] == {"VSS2": 1}


def test_the_volume_column_is_always_in_volume_order(tmp_path):
    """group_concat emits in scan order, so the stored list is normalised -- the
    analyst never sees `VSS2,C` in one table and `C,VSS2` in the next."""
    unit = _unit(_host(tmp_path, {
        "C":    {"a.csv": "id\n1\n"},
        "VSS1": {"a.csv": "id\n2\n"},
        "VSS2": {"a.csv": "id\n1\n2\n"},
    }))
    consolidate.build_unit(unit, emit_xlsx=False)

    got = dict(_rows(tmp_path / "acq" / "HOST.db", "a"))
    assert got == {1: "C,VSS2", 2: "VSS1,VSS2"}


def test_a_provenance_column_does_not_defeat_the_merge(tmp_path):
    """EZ-tools write the parsed file's full path into every row, which differs per
    volume by construction -- left in the key, nothing would ever deduplicate."""
    coll = tmp_path / "acq"
    vols = {}
    for label in ("C", "VSS1"):
        src = coll / label / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
        vols[label] = {"EventLogs/evtx_Security.csv": f"SourceFile,id,msg\n{src},7,hit\n"}
    unit = _unit(_host(tmp_path, vols))
    stats = consolidate.build_unit(unit, emit_xlsx=False)

    rows = _rows(coll / "HOST.db", "evtx_Security")
    assert len(rows) == 1, "the same event recorded once per volume is one event"
    assert rows[0][1:] == (7, "hit", "C,VSS1")
    assert stats["total_rows"] == 2 and stats["merged_rows"] == 1


def test_nothing_is_deduplicated_across_different_artifacts(tmp_path):
    """Two artifacts that share a basename in different categories are two tables:
    the merge key is the path under CSVs/, not the file name."""
    unit = _unit(_host(tmp_path, {
        "C": {"EventLogs/summary.csv": "a\n1\n", "Registry/summary.csv": "a\n1\n"},
        "VSS1": {"EventLogs/summary.csv": "a\n1\n", "Registry/summary.csv": "a\n1\n"},
    }))
    consolidate.build_unit(unit, emit_xlsx=False)

    tables = {r[0] for r in _query(
        tmp_path / "acq" / "HOST.db", "SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables == {"summary", "summary_1"}


def test_schema_drift_between_volumes_is_absorbed(tmp_path):
    """A parser that emitted fewer columns on an older snapshot must not split the
    artifact in two: the table is the union, the missing cells are NULL."""
    unit = _unit(_host(tmp_path, {
        "C":    {"a.csv": "id,msg,extra\n1,x,new\n"},
        "VSS1": {"a.csv": "id,msg\n1,x\n"},
    }))
    consolidate.build_unit(unit, emit_xlsx=False)

    assert _cols(tmp_path / "acq" / "HOST.db", "a") == ["id", "msg", "extra", "volumes"]
    rows = sorted(_rows(tmp_path / "acq" / "HOST.db", "a"), key=lambda r: str(r[2]))
    assert rows == [(1, "x", None, "VSS1"), (1, "x", "new", "C")]


def test_an_artifact_only_one_volume_has_still_lands_in_the_db(tmp_path):
    unit = _unit(_host(tmp_path, {
        "C":    {"a.csv": "id\n1\n"},
        "VSS1": {"a.csv": "id\n1\n", "b.csv": "id\n9\n"},
    }))
    consolidate.build_unit(unit, emit_xlsx=False)

    assert _rows(tmp_path / "acq" / "HOST.db", "b") == [(9, "VSS1")]


def test_liveresponse_json_is_read_as_json_not_as_a_csv(tmp_path):
    """LiveResponse ships JSON and only ever on the live volume, so it takes the
    written-through path -- parsing it with the CSV reader would produce garbage."""
    ms = _host(tmp_path, {"C": {"a.csv": "id\n1\n"}, "VSS1": {"a.csv": "id\n1\n"}})
    js = ms[0].path / "JSONs"
    js.mkdir()
    (js / "netstat.json").write_text('[{"pid": 4, "port": 445}]', encoding="utf-8")

    consolidate.build_unit(_unit(ms), emit_xlsx=False)

    assert _cols(tmp_path / "acq" / "HOST.db", "lr_netstat") == ["pid", "port", "volumes"]
    assert _rows(tmp_path / "acq" / "HOST.db", "lr_netstat") == [(4, 445, "C")]


def test_repeated_rows_inside_one_volume_are_kept(tmp_path):
    """Merging removes what the volumes duplicate OF EACH OTHER. An artifact only
    one volume produced is written through: its own repeats are its own data."""
    ms = _host(tmp_path, {"C": {"a.csv": "id\n1\n"}, "VSS1": {"a.csv": "id\n1\n",
                                                              "b.csv": "x\n7\n7\n7\n"}})
    consolidate.build_unit(_unit(ms), emit_xlsx=False)

    assert _rows(tmp_path / "acq" / "HOST.db", "b") == [(7, "VSS1")] * 3


def test_an_artifact_column_called_volumes_is_not_overwritten(tmp_path):
    unit = _unit(_host(tmp_path, {
        "C":    {"a.csv": "id,volumes\n1,mounted\n"},
        "VSS1": {"a.csv": "id,volumes\n1,mounted\n"},
    }))
    consolidate.build_unit(unit, emit_xlsx=False)

    cols = _cols(tmp_path / "acq" / "HOST.db", "a")
    assert cols == ["id", "volumes", "aeng_volumes_1"]
    assert _rows(tmp_path / "acq" / "HOST.db", "a") == [(1, "mounted", "C,VSS1")]


def test_the_merged_xlsx_holds_the_deduplicated_rows(tmp_path):
    import pandas as pd

    unit = _unit(_host(tmp_path, {
        "C":    {"a.csv": "id\n1\n"},
        "VSS1": {"a.csv": "id\n1\n2\n"},
    }))
    consolidate.build_unit(unit)

    xlsx = tmp_path / "acq" / "HOST.xlsx"
    assert xlsx.is_file()
    df = pd.read_excel(xlsx, sheet_name="a")
    assert list(df["id"]) == [1, 2]
    assert list(df["volumes"]) == ["C,VSS1", "VSS1"]


def test_the_xlsx_can_be_merged_without_a_db(tmp_path):
    """Deduplication IS a SQL GROUP BY, so an xlsx-only run needs a scratch database
    -- which must not survive the run."""
    unit = _unit(_host(tmp_path, {"C": {"a.csv": "id\n1\n"}, "VSS1": {"a.csv": "id\n1\n"}}))
    consolidate.build_unit(unit, emit_db=False)

    coll = tmp_path / "acq"
    assert (coll / "HOST.xlsx").is_file()
    assert not (coll / "HOST.db").exists()
    assert not list(coll.glob("*.aeng-merge.db")) and not list(coll.glob(".*.db"))


# --------------------------------------------------------------------------- #
# What the analyst is told
# --------------------------------------------------------------------------- #
def test_the_report_names_the_snapshot_worth_opening(tmp_path):
    ms = _host(tmp_path, {
        "C":    {"a.csv": "id\n3\n"},
        "VSS1": {"a.csv": "id\n3\n"},                  # adds nothing of its own
        "VSS2": {"a.csv": "id\n3\n1\n2\n"},            # holds two rows nothing else does
    })
    unit = _unit(ms)
    stats = consolidate.build_unit(unit, emit_xlsx=False)
    report.build(unit.primary, [], out_dir=unit.path, volume_labels=unit.labels, stats=stats)

    txt = (tmp_path / "acq" / "report.txt").read_text(encoding="utf-8")
    assert "Volumes  : C, VSS1, VSS2" in txt
    assert "Volume contribution (merged)" in txt
    line = next(x for x in txt.splitlines() if x.strip().startswith("VSS2"))
    assert line.split()[-1] == "2"                     # unique-to-this-volume count
    assert next(x for x in txt.splitlines() if x.strip().startswith("VSS1")).split()[-1] == "0"
    assert "5 row(s) read | 3 after merging" in txt


def test_an_unmerged_machine_reports_exactly_as_before(tmp_path):
    (tmp_path / "CSVs").mkdir()
    m = _machine(tmp_path, "HOST", "C")
    report.build(m, [])

    txt = (tmp_path / "report.txt").read_text(encoding="utf-8")
    assert "Volumes  : C" in txt
    assert "Volume contribution" not in txt


def test_outputs_from_an_earlier_unmerged_run_are_reported_not_deleted(tmp_path):
    ms = _host(tmp_path, {"C": {"a.csv": "id\n1\n"}, "VSS1": {"a.csv": "id\n1\n"}})
    stale = ms[1].path / "HOST_VSS1.db"
    stale.write_bytes(b"old")

    unit = _unit(ms)
    found = consolidate.stale_outputs(unit)
    consolidate.build_unit(unit, emit_xlsx=False)

    assert stale in found
    assert stale.read_bytes() == b"old", "the engine never deletes inside a case"


def test_the_stale_list_names_every_file_so_none_is_derived_by_hand(tmp_path):
    ms = _host(tmp_path, {"C": {"a.csv": "id\n1\n"},
                          "VSS1": {"a.csv": "id\n1\n"},
                          "VSS2": {"a.csv": "id\n2\n"}})
    left = []
    for m in ms:
        for name in (f"{m.name}.db", f"{m.name}.xlsx", "report.txt"):
            p = m.path / name
            p.write_bytes(b"old")
            left.append(p)
    # A machine with no snapshots still produces its own outputs: not stale.
    solo = _machine(tmp_path / "other", "OTHER", "C")
    solo.path.mkdir(parents=True, exist_ok=True)
    keep = solo.path / "report.txt"
    keep.write_bytes(b"current")

    units = consolidate.plan_units([(m, []) for m in [*ms, solo]], merge_vss=True)
    stale = [p for u, _ in units for p in consolidate.stale_outputs(u)]
    dest = consolidate.write_stale_list(stale, tmp_path)

    listed = dest.read_text(encoding="utf-8").splitlines()
    assert listed == [str(p) for p in left], "every stale file, in unit order, nothing else"
    assert str(keep) not in listed, "a machine without snapshots keeps its outputs"


def test_a_stale_list_never_outlives_the_files_it_names(tmp_path):
    dest = tmp_path / consolidate.STALE_LIST
    dest.write_text("C:\\gone\\HOST.db\n", encoding="utf-8")

    assert consolidate.write_stale_list([], tmp_path) is None
    assert dest.read_text(encoding="utf-8") == "", "the analyst may already have acted on it"


def test_a_case_with_nothing_stale_gets_no_list(tmp_path):
    assert consolidate.write_stale_list([], tmp_path) is None
    assert not (tmp_path / consolidate.STALE_LIST).exists()


def test_the_run_points_at_the_list_instead_of_one_example(tmp_path, caplog):
    ms = _host(tmp_path, {"C": {"a.csv": "id\n1\n"}, "VSS1": {"a.csv": "id\n1\n"}})
    (ms[1].path / "HOST_VSS1.db").write_bytes(b"x" * 2048)
    units = consolidate.plan_units([(m, []) for m in ms], merge_vss=True)

    with caplog.at_level("INFO", logger="aeng"):
        cli._report_stale(units, tmp_path)

    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert "1 per-volume output" in msgs
    assert "2.0 KB" in msgs, "the size is what makes it worth acting on"
    assert consolidate.STALE_LIST in msgs


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def test_a_flag_written_as_yes_or_one_is_not_silently_false(tmp_path):
    """`str(value).lower() == "true"` read `merge_vss: 1` as FALSE -- the opposite
    of what was asked for, with nothing said about it."""
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("avoid_vss: 0\nmerge_vss: yes\nemit_xlsx: off\n", encoding="utf-8")
    cfg = load_config(cfg_file)

    assert cfg.avoid_vss is False
    assert cfg.merge_vss is True
    assert cfg.emit_xlsx is False
    assert cfg.emit_db is True                        # untouched keys keep the default


def test_merge_vss_defaults_on(tmp_path):
    assert load_config(tmp_path / "absent.yaml").merge_vss is True


def _one_unit(tmp_path):
    """A minimal single-machine unit with one CSV input."""
    from artifact_engine.core.consolidate import Unit
    from artifact_engine.core.detector import Machine, Volume

    (tmp_path / "CSVs" / "Execution").mkdir(parents=True)
    (tmp_path / "CSVs" / "Execution" / "runs.csv").write_text(
        "when_utc,host,exe\n2026-01-01,HOST-01,cmd.exe\n", encoding="utf-8")
    m = Machine("HOST-01", "windows", "kape", "windows_kape", tmp_path, "src",
                [Volume("C", tmp_path, True)])
    return Unit(name="HOST-01", path=tmp_path, members=[m], labels=["live"])


def test_an_unchanged_unit_is_not_rebuilt(tmp_path):
    """Consolidation was ~29% of a measured run and 99.9% of that sat in one unit,
    which does not change between runs unless its parsers did."""
    from artifact_engine.core import consolidate

    u = _one_unit(tmp_path)
    first = consolidate.build_unit(u, emit_db=True, emit_xlsx=False)
    assert not first.get("cached"), "the FIRST build must not claim to be cached"
    assert (tmp_path / "HOST-01.db").is_file()

    second = consolidate.build_unit(u, emit_db=True, emit_xlsx=False)
    assert second.get("cached") is True, "an unchanged unit was rebuilt"
    assert second.get("inputs") == 1


def test_changed_content_rebuilds_even_at_the_same_size(tmp_path):
    """The reason the fingerprint hashes CONTENT and not size+mtime: a rewrite to
    the same length inside the same mtime tick would leave the analyst reading a
    .db that silently does not contain it."""
    from artifact_engine.core import consolidate

    u = _one_unit(tmp_path)
    consolidate.build_unit(u, emit_db=True, emit_xlsx=False)
    src = tmp_path / "CSVs" / "Execution" / "runs.csv"
    before = src.stat()
    # same LENGTH on purpose: cmd.exe -> bad.exe, only the bytes differ
    src.write_text("when_utc,host,exe\n2026-01-01,HOST-01,bad.exe\n", encoding="utf-8")
    import os
    os.utime(src, (before.st_atime, before.st_mtime))     # same size, same mtime
    assert src.stat().st_size == before.st_size

    again = consolidate.build_unit(u, emit_db=True, emit_xlsx=False)
    assert not again.get("cached"), "a same-size same-mtime rewrite was treated as unchanged"


def test_a_deleted_output_rebuilds_despite_a_matching_marker(tmp_path):
    """A marker that outlives the file it describes must not paper over it."""
    from artifact_engine.core import consolidate

    u = _one_unit(tmp_path)
    consolidate.build_unit(u, emit_db=True, emit_xlsx=False)
    (tmp_path / "HOST-01.db").unlink()

    again = consolidate.build_unit(u, emit_db=True, emit_xlsx=False)
    assert not again.get("cached"), "a missing .db was reported as cached"
    assert (tmp_path / "HOST-01.db").is_file(), "the .db was not rebuilt"


def test_asking_for_a_new_output_rebuilds(tmp_path):
    """Flipping emit_xlsx must rebuild, not report 'unchanged' and leave no xlsx."""
    from artifact_engine.core import consolidate

    u = _one_unit(tmp_path)
    consolidate.build_unit(u, emit_db=True, emit_xlsx=False)
    again = consolidate.build_unit(u, emit_db=True, emit_xlsx=True)
    assert not again.get("cached"), "the xlsx was never asked for before"


def test_force_ignores_the_marker(tmp_path):
    from artifact_engine.core import consolidate

    u = _one_unit(tmp_path)
    consolidate.build_unit(u, emit_db=True, emit_xlsx=False)
    assert not consolidate.build_unit(u, emit_db=True, emit_xlsx=False,
                                      force=True).get("cached")
