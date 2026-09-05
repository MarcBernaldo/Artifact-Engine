r"""Sigma detections by source, and the line between quietening and hiding.

The noise this exists for is one rule firing four hundred times about four hundred
ordinary internal sessions. The danger is the fix: a detector that downgrades by
matching `external` or `public ip` in a rule title also quietens rules about a
DESTINATION being public, and rules that have nothing to do with addresses at all.

So these tests pin both directions -- what is downgraded, and the rules that must
keep their level however internal the source is -- plus the two facts a table like
this cannot leave unsaid: which detections it does not cover, and that hayabusa's
own output was not touched.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import win_sigma_sources as G

_COLS = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID",
         "RecordID", "Details", "ExtraFieldInfo", "RuleID"]

_WHEN = "2026-05-19 11:22:33.000 +00:00"


class _Ctx:
    def __init__(self, evidence: Path, out: Path, internal=()):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "C"
        self.log = None
        self.internal_networks = internal


def _det(rule: str, *, level="high", src="", tgt="", when=_WHEN,
         eid="4624", channel="Sec", extra="") -> dict:
    parts = ["TgtUser: EXAMPLE\\jdoe"]
    if src:
        parts.append(f"SrcIP: {src}")
    if tgt:
        parts.append(f"TgtIP: {tgt}")
    return {"Timestamp": when, "RuleTitle": rule, "Level": level,
            "Computer": "HOST-01", "Channel": channel, "EventID": eid,
            "RecordID": "1", "Details": " ¦ ".join(parts),
            "ExtraFieldInfo": extra, "RuleID": "rule-0001"}


def _run(tmp_path: Path, dets: list[dict], internal=()) -> list[dict]:
    d = tmp_path / "CSVs" / "EventLogs"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "hayabusa.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_COLS)
        w.writeheader()
        for row in dets:
            w.writerow({c: row.get(c, "") for c in _COLS})
    G.run(_Ctx(tmp_path, tmp_path / "out", internal))
    p = tmp_path / "out" / "sigma_sources.csv"
    if not p.is_file():
        return []
    with p.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


_RDP_PUBLIC = "External Remote RDP Logon from Public IP"


# --------------------------------------------------------------------------- #
# The noise, and what removes it
# --------------------------------------------------------------------------- #
def test_four_hundred_events_from_one_source_are_one_row(tmp_path):
    """The actionable unit is "rule X fired N times from source Y"."""
    rows = _run(tmp_path, [
        _det(_RDP_PUBLIC, src="1.2.3.4",
             when=f"2026-05-19 11:{i % 60:02d}:00.000 +00:00") for i in range(400)
    ])
    assert len(rows) == 1
    assert rows[0]["hits"] == "400" and rows[0]["source_ip"] == "1.2.3.4"


def test_a_declared_internal_source_downgrades_the_rule_that_fires_on_publicness(tmp_path):
    rows = _run(tmp_path, [_det(_RDP_PUBLIC, src="1.2.3.4")],
                internal=("1.2.3.0/24",))
    assert rows[0]["scope"] == "internal"
    assert rows[0]["triage"].startswith("DOWNGRADED")
    assert "internal_networks" in rows[0]["triage"]
    assert rows[0]["suspicious"] == ""


def test_the_downgrade_never_touches_the_level_the_rule_gave_it(tmp_path):
    """The rule's verdict is evidence; the engine's reading of it is not the same
    thing, and an analyst sorting by level must still see what the rule said."""
    rows = _run(tmp_path, [_det(_RDP_PUBLIC, level="high", src="1.2.3.4")],
                internal=("1.2.3.0/24",))
    assert rows[0]["level"] == "high"


def test_a_genuinely_external_source_is_untouched_and_flagged(tmp_path):
    rows = _run(tmp_path, [_det(_RDP_PUBLIC, src="4.5.6.7")],
                internal=("1.2.3.0/24",))
    assert rows[0]["scope"] == "public"
    assert rows[0]["triage"] == "" and rows[0]["suspicious"] == "yes"


def test_a_low_level_detection_from_outside_is_reported_not_flagged(tmp_path):
    rows = _run(tmp_path, [_det(_RDP_PUBLIC, level="low", src="4.5.6.7")])
    assert rows[0]["scope"] == "public" and rows[0]["suspicious"] == ""


# --------------------------------------------------------------------------- #
# The rules that must KEEP their level, however internal the source is
# --------------------------------------------------------------------------- #
def test_a_rule_about_a_public_destination_is_not_downgraded(tmp_path):
    """`Outbound Network Connection To Public IP Via Winlogon` is a real rule and
    is about where the host went, not where the session came from. A substring
    match on `public ip` would quieten it on every internal host."""
    rule = "Outbound Network Connection To Public IP Via Winlogon"
    rows = _run(tmp_path, [_det(rule, src="10.0.0.5")], internal=("10.0.0.0/8",))
    assert rows[0]["triage"] == ""
    assert not G.downgradeable(rule)


def test_a_rule_that_merely_says_external_is_not_downgraded(tmp_path):
    for rule in ("External Disk Drive Or USB Storage Device Was Recognized "
                 "By The System",
                 "Raspberry Robin Initial Execution From External Drive",
                 "Internet Explorer Autorun Keys Modification",
                 "Exchange Set OabVirtualDirectory ExternalUrl Property"):
        assert not G.downgradeable(rule), rule


def test_lateral_movement_from_inside_is_the_case_not_the_noise(tmp_path):
    """The last rule to quieten is one firing from an internal address."""
    rows = _run(tmp_path, [_det("Suspicious PsExec Execution", src="10.0.0.5")],
                internal=("10.0.0.0/8",))
    assert rows[0]["triage"] == "" and rows[0]["level"] == "high"


def test_the_marker_matches_the_rules_it_was_read_from(tmp_path):
    for rule in ("External Remote RDP Logon from Public IP",
                 "External Remote SMB Logon from Public IP",
                 "Failed Logon From Public IP",
                 "MSSQL Server Failed Logon From External Network"):
        assert G.downgradeable(rule), rule


def test_a_private_source_downgrades_too_and_says_which_it_was(tmp_path):
    """An estate that declared nothing still gets the RFC1918 half for free, and
    the reason has to distinguish the two: one is a fact about addressing, the
    other is a claim the organisation made."""
    rows = _run(tmp_path, [_det(_RDP_PUBLIC, src="10.0.0.5")])
    assert rows[0]["scope"] == "private"
    assert "private address" in rows[0]["triage"]


# --------------------------------------------------------------------------- #
# Reading the source, and saying what is not covered
# --------------------------------------------------------------------------- #
def test_the_source_is_read_by_its_key_not_by_looking_like_an_address(tmp_path):
    """Scanning the row for anything address-shaped returns the TARGET as readily
    as the source, and a target read as a source inverts the finding."""
    assert G.source_ip("TgtUser: jdoe ¦ SrcIP: 1.2.3.4 ¦ TgtIP: 10.0.0.9") == "1.2.3.4"
    assert G.source_ip("TgtUser: jdoe ¦ TgtIP: 10.0.0.9") == ""
    assert G.source_ip("Proc: C:\\x.exe ¦ PID: 4242") == ""


def test_a_placeholder_source_is_not_a_source(tmp_path):
    for blob in ("SrcIP: -", "SrcIP: 127.0.0.1", "SrcIP: ::1", "SrcIP:   "):
        assert G.source_ip(blob) == ""


def test_the_source_is_also_read_from_the_extra_field(tmp_path):
    rows = _run(tmp_path, [_det("Failed Logon From Public IP", src="",
                                extra="IpAddress: 4.5.6.7")])
    assert rows[0]["source_ip"] == "4.5.6.7"


def test_the_detections_naming_no_source_are_counted_not_dropped(tmp_path):
    """A table that silently covers a third of the timeline reads as a quiet
    case."""
    rows = _run(tmp_path, [_det(_RDP_PUBLIC, src="4.5.6.7")]
                + [_det("Suspicious Process", src="") for _ in range(7)])
    last = rows[-1]
    assert last["rule"] == "(not listed)"
    assert "7 detection(s) name no source address" in last["triage"]


def test_hayabusa_own_csv_is_not_rewritten(tmp_path):
    before = None
    d = tmp_path / "CSVs" / "EventLogs"
    _run(tmp_path, [_det(_RDP_PUBLIC, src="1.2.3.4")], internal=("1.2.3.0/24",))
    before = (d / "hayabusa.csv").read_text(encoding="utf-8")
    assert "sigma_sources" not in before
    assert "DOWNGRADED" not in before
    assert before.splitlines()[0] == ",".join(_COLS)


def test_a_timeline_with_nothing_in_it_writes_no_table(tmp_path):
    assert _run(tmp_path, []) == []


def test_no_hayabusa_csv_skips(tmp_path):
    with pytest.raises(HandlerSkip):
        G.run(_Ctx(tmp_path, tmp_path / "out"))
