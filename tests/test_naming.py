"""Every table says its type (v0.7.171): `art_` for what a source holds, `alert_`
for tables whose every row is a judgement. A parser's id is its main table."""
from __future__ import annotations

import re

import yaml

from artifact_engine.config import DATA_DIR
from artifact_engine.core.consolidate import lr_table
from artifact_engine.core.runner import _short_stem, snake

# The parsers that write several tables of different kinds keep a name of their own.
_MULTI = {"cmd_hunt", "exec_hunt", "liveresponse"}


def _manifests():
    for f in sorted((DATA_DIR / "parsers").rglob("*.yaml")):
        yield f, yaml.safe_load(f.read_text(encoding="utf-8"))


def test_every_parser_id_says_its_type_and_fits_a_sheet():
    bad = [m["id"] for _, m in _manifests()
           if m["id"] not in _MULTI and not re.fullmatch(r"(art|alert)_[a-z0-9_]+", m["id"])]
    assert bad == []
    assert [m["id"] for _, m in _manifests() if len(m["id"]) > 31] == []


def test_the_file_is_named_after_the_id():
    assert [f.name for f, m in _manifests() if f.stem != m["id"]] == []


def test_every_renamed_parser_retires_its_old_name():
    """Without its `replaces:` entry a case parsed before keeps the old table beside
    the new one, and the consolidation loads both."""
    missing = [m["id"] for _, m in _manifests()
               if m["id"] not in _MULTI
               and not any(not k.startswith(("art_", "alert_")) for k in (m.get("replaces") or {}))]
    assert missing == []


def test_a_multi_output_tool_gets_short_snake_case_names():
    assert snake("AppResourceUseInfo") == "app_resource_use_info"
    assert snake("DETAIL_ClientsDetailed") == "detail_clients_detailed"
    assert _short_stem("20260620211506_SrumECmd_EnergyUsage_Output", "art_srum",
                       {"EnergyUsage": "energy"}) == "art_srum_energy"
    assert _short_stem("art_amcache_DriveBinaries", "art_amcache",
                       {"DriveBinaries": "drive_binaries"}) == "art_amcache_drive_binaries"
    # a subtype nobody mapped still comes out lowercase
    assert _short_stem("Report_X", "art_search") == "art_search_report_x"


def test_every_mapped_subtype_fits_a_sheet():
    long = [f"{m['short']}_{v}" for _, m in _manifests()
            for v in (m.get("subtypes") or {}).values() if len(f"{m['short']}_{v}") > 31]
    assert long == []


def test_live_response_files_are_artifacts_and_its_verdicts_alerts():
    assert lr_table("services") == "art_lr_services"
    assert lr_table("suspicious") == "alert_lr"
    assert lr_table("correlation") == "alert_lr_correlation"


def test_a_rename_that_only_lowercases_happens(tmp_path):
    """AmcacheParser writes `..._ShortCuts`; on a case-insensitive disk the
    lowercase target "exists" (it is the same file) and the rename was skipped."""
    from artifact_engine.core.runner import _clean_output_names
    (tmp_path / "art_amcache_ShortCuts.csv").write_text("a", encoding="utf-8")
    _clean_output_names(tmp_path, before=set(), short="art_amcache",
                        subtypes={"ShortCuts": "shortcuts"})
    assert [f.name for f in tmp_path.glob("*.csv")] == ["art_amcache_shortcuts.csv"]


def test_a_replaces_entry_never_names_a_live_table():
    """`retire` removes a declared name whatever its age; one that a live parser
    writes is protected only while that parser just wrote it."""
    live = [(m["id"], n) for _, m in _manifests()
            for names in (m.get("replaces") or {}).values() for n in names
            if n.startswith(("art_", "alert_"))]
    assert live == []


def test_the_old_tables_of_parsers_that_kept_their_ids_are_retired():
    """exec_hunt and cmd_hunt kept their ids, so no successor names them under
    `replaces:`; and mem_exfil_commands wrote `_exfil`'s table, not `<id>.csv`."""
    from artifact_engine.core import retired
    gone = {n for e in retired.load().values() if e.get("os") == "windows"
            and e.get("category") == "detections" for n in e["outputs"]}
    assert {"rmm.csv", "lolbas.csv", "byovd.csv", "suspicious_tools.csv",
            "exfil_commands.csv", "suspicious_commands.csv"} <= gone
    by_id = {m["id"]: m for _, m in _manifests()}
    assert by_id["alert_mem_exfil_commands"]["replaces"] == {
        "mem_exfil_commands": ["exfil_commands.csv"]}


def test_pecmd_timeline_is_lowercased_and_its_old_name_retired():
    m = {m["id"]: m for _, m in _manifests()}["art_prefetch"]
    assert _short_stem("art_prefetch_Timeline", m["short"]) == "art_prefetch_timeline"
    assert _short_stem("art_prefetch", m["short"]) == "art_prefetch"
    assert "prefetch_Timeline.csv" in m["replaces"]["prefetch"]
