r"""The organisation's own address space, and what declaring it may change.

`is_global` answers "routable on the internet", and for an estate holding its own
public allocation that is the opposite of "came from outside": every ordinary
file-share access between two of their own hosts draws as an internet source, and
the graph's node cap then drops real peers to make room for them.

These tests pin the two halves of that. The classifier itself -- including the
cases where getting it wrong would be silent, a typo'd range and a value that is
not an address at all. And the promise attached to it: a declared range
RECLASSIFIES a source and never removes it, because "we own that range" is a
claim about ownership, not about innocence.
"""
from __future__ import annotations

import csv as _csv

from artifact_engine.config import Config, load_config
from artifact_engine.core import lateral, netclass, pipeline
from tests.test_lateral import _win_machine, _write_security


# --------------------------------------------------------------------------- #
# The classifier
# --------------------------------------------------------------------------- #
def test_a_declared_public_range_stops_being_public():
    """This is the whole point: 1.2.3.0/24 is globally routable AND theirs.

    (The RFC 5737 documentation ranges are no use for this: Python already reports
    them as non-global, so a test written with them would pass while proving
    nothing.)"""
    nc = netclass.parse(["1.2.3.0/24"])
    assert nc.scope("1.2.3.4") == netclass.INTERNAL
    assert not nc.is_public("1.2.3.4")
    assert nc.scope("4.5.6.7") == netclass.PUBLIC
    assert nc.is_public("4.5.6.7")


def test_with_nothing_declared_the_answer_is_the_old_one():
    """An estate that declares nothing must behave exactly as before."""
    assert netclass.EMPTY.scope("1.2.3.4") == netclass.PUBLIC
    assert netclass.EMPTY.scope("10.0.0.5") == netclass.PRIVATE
    assert netclass.EMPTY.scope("169.254.1.1") == netclass.PRIVATE
    assert netclass.EMPTY.scope("127.0.0.1") == netclass.PRIVATE


def test_a_host_name_is_not_a_private_address():
    """"Not an address" and "an internal address" are different answers, and a
    handler that conflates them calls every resolved hostname internal."""
    assert netclass.EMPTY.scope("SRV-EXAMPLE") == ""
    assert netclass.EMPTY.scope("") == ""
    assert netclass.parse(["10.0.0.0/8"]).scope("SRV-EXAMPLE") == ""


def test_a_declared_private_range_reads_as_declared_not_private():
    """Stating 10.0.0.0/8 is true and harmless, and answering `private` for it
    would read as if the declaration had been ignored."""
    assert netclass.parse(["10.0.0.0/8"]).scope("10.0.0.5") == netclass.INTERNAL


def test_a_bare_address_is_a_range_of_one():
    nc = netclass.parse(["1.2.3.4"])
    assert nc.scope("1.2.3.4") == netclass.INTERNAL
    assert nc.scope("1.2.3.5") == netclass.PUBLIC


def test_ipv6_is_classified_alongside_v4_ranges():
    """Both families in one list, which is how a real declaration is written.

    This pins a behaviour of `ipaddress` the classifier leans on: an address is
    simply not `in` a network of the other family -- it answers False rather than
    raising -- so no version guard is needed and none is written."""
    nc = netclass.parse(["2001:db8::/32", "1.2.3.0/24"])
    assert nc.scope("2001:db8::1") == netclass.INTERNAL
    assert nc.scope("2606:4700::1111") == netclass.PUBLIC
    assert nc.scope("fe80::1") == netclass.PRIVATE


def test_an_unreadable_range_is_reported_and_not_silently_dropped():
    """A typo that matches nothing looks identical to a rule that is working."""
    nc = netclass.parse(["1.2.3.0/24", "not-a-range", "10.0.0.0/64"])
    assert len(nc.networks) == 1
    assert nc.rejected == ("not-a-range", "10.0.0.0/64")
    assert "IGNORED" in netclass.describe(nc)


def test_host_bits_are_masked_rather_than_refused():
    """`203.0.113.9/24` is what somebody writes when they mean the network."""
    nc = netclass.parse(["1.2.3.9/24"])
    assert str(nc.networks[0]) == "1.2.3.0/24"
    assert nc.scope("1.2.3.200") == netclass.INTERNAL


def test_the_list_is_read_however_it_was_written():
    """A YAML list, or one string, is how the value actually gets typed."""
    assert len(netclass.parse(["10.0.0.0/8", "192.0.2.0/24"]).networks) == 2
    assert len(netclass.parse("10.0.0.0/8, 192.0.2.0/24").networks) == 2
    assert len(netclass.parse("10.0.0.0/8 192.0.2.0/24").networks) == 2
    assert netclass.parse(None).networks == ()
    assert netclass.parse([]).networks == ()


def test_nothing_declared_says_nothing():
    assert netclass.describe(netclass.EMPTY) == ""


# --------------------------------------------------------------------------- #
# The config
# --------------------------------------------------------------------------- #
def test_the_config_defaults_to_declaring_nothing():
    assert Config().internal_networks == []


def test_the_config_validates_the_ranges_once_at_load(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "internal_networks:\n  - 203.0.113.0/24\n  - nonsense\n  - 10.0.0.0/8\n",
        encoding="utf-8")
    cfg = load_config(cfg_file)
    assert cfg.internal_networks == ["203.0.113.0/24", "10.0.0.0/8"]


def test_a_config_without_the_key_leaves_it_empty(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("max_workers: 4\n", encoding="utf-8")
    assert load_config(cfg_file).internal_networks == []


# --------------------------------------------------------------------------- #
# What it changes in the graph, and what it must not
# --------------------------------------------------------------------------- #
def _case(tmp_path, internal):
    a = _win_machine(tmp_path / "A", "PCA", ["1.2.3.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["1.2.3.20"])
    _write_security(b, [
        # an RDP session from an address inside the organisation's own range
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624", "Computer": "PCB.corp",
         "UserName": "CORP\\jdoe", "RemoteHost": "- (1.2.3.77)",
         "PayloadData1": "Target: CORP\\jdoe", "PayloadData2": "LogonType 10"},
        # and one from an address that is genuinely outside it
        {"TimeCreated": "2026-06-18 10:05:00", "EventId": "4624", "Computer": "PCB.corp",
         "UserName": "CORP\\jdoe", "RemoteHost": "- (4.5.6.7)",
         "PayloadData1": "Target: CORP\\jdoe", "PayloadData2": "LogonType 10"},
    ])
    summary = lateral.build([a, b], tmp_path, netclass.parse(internal))
    with (tmp_path / "lateral_movement.csv").open(encoding="utf-8") as fh:
        rows = {r["src"]: r for r in _csv.DictReader(fh)}
    return summary, rows, (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")


def test_an_internal_rdp_source_stops_being_an_internet_finding(tmp_path):
    """`rdp_public` on every internal RDP session is the noise this exists for."""
    _, rows, _ = _case(tmp_path, ["1.2.3.0/24"])
    assert "rdp_public" not in rows["1.2.3.77"]["reasons"]
    assert rows["1.2.3.77"]["src_scope"] == "internal"


def test_the_genuinely_external_source_is_untouched(tmp_path):
    """Declaring one range must not quieten a different one."""
    _, rows, _ = _case(tmp_path, ["1.2.3.0/24"])
    assert "rdp_public" in rows["4.5.6.7"]["reasons"]
    assert rows["4.5.6.7"]["src_scope"] == "public"
    assert rows["4.5.6.7"]["suspicious"] == "yes"


def test_a_reclassified_source_is_still_in_the_csv(tmp_path):
    """Reclassified, never removed. "We own that range" is a claim about
    ownership, not about innocence, and an attacker who reached a host inside it
    is exactly the case a suppressed row would have hidden.

    The CSV is where that promise lives. The HTML graph is CURATED -- an inbound
    RDP that no longer carries a reason is ordinary administration and was always
    CSV-only, exactly like a routine inbound SSH -- so the reclassified edge
    dropping out of the drawing is the curation working, not a row being lost."""
    summary, rows, _ = _case(tmp_path, ["1.2.3.0/24"])
    assert "1.2.3.77" in rows
    assert summary["edges"] == 2


def test_the_same_case_without_the_declaration_flags_both(tmp_path):
    """The control: the behaviour is unchanged for an estate that declares
    nothing."""
    _, rows, _ = _case(tmp_path, [])
    assert "rdp_public" in rows["1.2.3.77"]["reasons"]
    assert "rdp_public" in rows["4.5.6.7"]["reasons"]
    assert rows["1.2.3.77"]["src_scope"] == "public"


def test_the_run_reports_how_many_hosts_the_declaration_matched(tmp_path):
    """A declared range that matched nothing is the case worth noticing, so the
    summary reports the MATCH count and not the range count."""
    summary, _, _ = _case(tmp_path, ["1.2.3.0/24"])
    assert summary["internal_declared"] == 1
    assert summary["internal_hosts"] == 1        # only the bare source IP
    line = pipeline.describe_graph(summary)
    assert "internal_networks: 1 of" in line and "reclassified as internal" in line


def test_nothing_declared_says_nothing_in_the_summary(tmp_path):
    summary, _, _ = _case(tmp_path, [])
    assert "internal_networks" not in pipeline.describe_graph(summary)


def test_a_private_source_reads_as_private_not_as_declared(tmp_path):
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    _write_security(a, [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624", "Computer": "PCA.corp",
         "UserName": "CORP\\jdoe", "RemoteHost": "- (10.0.0.99)",
         "PayloadData1": "Target: CORP\\jdoe", "PayloadData2": "LogonType 10"},
    ])
    lateral.build([a], tmp_path, netclass.parse(["1.2.3.0/24"]))
    with (tmp_path / "lateral_movement.csv").open(encoding="utf-8") as fh:
        rows = list(_csv.DictReader(fh))
    assert rows[0]["src_scope"] == "private"


def test_a_source_that_is_a_host_name_has_no_scope(tmp_path):
    """The `src_in_case` column already answers "is this one of ours"; an empty
    scope says "this was never an address", which is a different fact."""
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    _write_security(a, [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624", "Computer": "PCA.corp",
         "UserName": "CORP\\jdoe", "RemoteHost": "WKSTN-9 (-)",
         "PayloadData1": "Target: CORP\\jdoe", "PayloadData2": "LogonType 10"},
    ])
    lateral.build([a], tmp_path, netclass.parse(["1.2.3.0/24"]))
    with (tmp_path / "lateral_movement.csv").open(encoding="utf-8") as fh:
        rows = list(_csv.DictReader(fh))
    assert rows[0]["src"] == "wkstn-9" and rows[0]["src_scope"] == ""


def test_the_classifier_does_not_leak_between_runs(tmp_path):
    """`build()` sets the module-level classifier on every call. A second run that
    inherited the first one's ranges would be wrong in the quiet direction."""
    _case(tmp_path / "one", ["1.2.3.0/24"])
    _, rows, _ = _case(tmp_path / "two", [])
    assert rows["1.2.3.77"]["src_scope"] == "public"
    assert "rdp_public" in rows["1.2.3.77"]["reasons"]
