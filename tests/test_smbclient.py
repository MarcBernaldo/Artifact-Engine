r"""Outbound SMB, and the two fields that read as noise until they are decoded.

The case this exists for was found by a generic Sigma rule that named a CVE for
software the host did not have installed. The rule name was wrong; the behaviour
-- a server reaching OUT over SMB to a public address -- was the finding, and no
parser here read the channel that recorded it.

These tests pin the decoders (a sockaddr whose two halves have opposite byte
orders, an NTSTATUS that must answer even when it is not in the table), the one
indicator strong enough to stand alone, and the ones that are ordinary until they
keep company.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _evtx
from artifact_engine.handlers import win_smbclient as S


class _Ctx:
    def __init__(self, evidence: Path, out: Path, internal=()):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "C"
        self.log = None
        self.internal_networks = internal


_COLS = ["RecordNumber", "TimeCreated", "EventId", "Channel", "Provider",
         "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "Payload"]

_WHEN = "2026-05-19 11:22:33.0000000"


def _event(eid="30803", *, server="", share="", address="", status="",
           reason="", when=_WHEN, mapped=False) -> dict:
    data = {k: v for k, v in (("ServerName", server), ("ShareName", share),
                              ("RemoteAddress", address), ("Status", status),
                              ("Reason", reason)) if v}
    row = {c: "" for c in _COLS}
    row.update({"RecordNumber": "1", "TimeCreated": when, "EventId": eid,
                "Provider": "Microsoft-Windows-SMBClient",
                "Payload": json.dumps({"EventData": data})})
    if mapped:
        # The two events that DO have a bundled map put their fields here.
        row.update({"PayloadData1": f"ServerName: {server}",
                    "PayloadData2": f"Status: {status}"})
        row["Payload"] = ""
    return row


def _write(tmp_path: Path, events: list[dict], name="evtx_smbclient_conn.csv") -> None:
    d = tmp_path / "CSVs" / "EventLogs"
    d.mkdir(parents=True, exist_ok=True)
    with (d / name).open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_COLS)
        w.writeheader()
        for e in events:
            w.writerow({c: e.get(c, "") for c in _COLS})


def _run(tmp_path: Path, events: list[dict], internal=(), name=None) -> list[dict]:
    _write(tmp_path, events, name or "evtx_smbclient_conn.csv")
    S.run(_Ctx(tmp_path, tmp_path / "out", internal))
    p = tmp_path / "out" / "smb_client_connections.csv"
    if not p.is_file():
        return []
    with p.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# A globally-routable peer, and a private one. (The RFC 5737 documentation ranges
# are no use here: Python already reports them as non-global.)
_PUBLIC = "020001BD01020304" + "0" * 16          # 1.2.3.4:445
_PRIVATE = "020001BD0A000005" + "0" * 16         # 10.0.0.5:445
_ODD_PORT = "0200115C01020304" + "0" * 16        # 1.2.3.4:4444


# --------------------------------------------------------------------------- #
# The decoders
# --------------------------------------------------------------------------- #
def test_the_two_halves_of_a_sockaddr_have_opposite_byte_orders():
    """The family is little-endian and the port is network order. Reading both the
    same way round yields a plausible-looking wrong port, which is worse than
    none."""
    assert _evtx.sockaddr_from_hex(_PUBLIC) == ("1.2.3.4", 445)
    assert _evtx.sockaddr_from_hex(_ODD_PORT) == ("1.2.3.4", 4444)


def test_an_ipv6_peer_is_written_the_way_an_address_is_written():
    # family(2) port(2) flowinfo(4) address(16) scope(4)
    blob = "170001BD" + "00000000" + "20010db8" + "0" * 20 + "0001" + "00000000"
    assert _evtx.sockaddr_from_hex(blob) == ("2001:db8::1", 445)


def test_a_field_that_is_not_a_sockaddr_answers_nothing(tmp_path):
    assert _evtx.sockaddr_from_hex("") == ("", 0)
    assert _evtx.sockaddr_from_hex("zz") == ("", 0)
    assert _evtx.sockaddr_from_hex("0200") == ("", 0)          # too short
    assert _evtx.sockaddr_from_hex("990001BD" + "0" * 24) == ("", 0)   # family?


def test_an_ntstatus_answers_even_when_it_is_not_in_the_table():
    """`3221226036` tells an analyst nothing. "unknown error (0xC00000B4)" tells
    them the connection failed, which is most of what they needed."""
    assert _evtx.ntstatus_name("3221225506") == "STATUS_ACCESS_DENIED (0xC0000022)"
    assert _evtx.ntstatus_name("0") == "STATUS_SUCCESS (0x00000000)"
    assert _evtx.ntstatus_name("0xC0000236") == "STATUS_CONNECTION_REFUSED (0xC0000236)"
    assert _evtx.ntstatus_name("3267915996").startswith("unknown error")
    assert _evtx.ntstatus_name("") == "" and _evtx.ntstatus_name("nope") == ""


# --------------------------------------------------------------------------- #
# The finding
# --------------------------------------------------------------------------- #
def test_smb_out_to_a_public_address_is_the_finding_on_its_own(tmp_path):
    """This host is the CLIENT here. A client reaching the internet over SMB is
    not a client doing its job."""
    rows = _run(tmp_path, [_event(server="\\\\1.2.3.4\\share", address=_PUBLIC,
                                  status="3221225506")])
    assert len(rows) == 1
    assert rows[0]["address"] == "1.2.3.4" and rows[0]["port"] == "445"
    assert rows[0]["scope"] == "public"
    assert "outbound_to_public" in rows[0]["indicators"]
    assert rows[0]["suspicious"] == "yes"
    assert rows[0]["status"] == "STATUS_ACCESS_DENIED (0xC0000022)"


def test_an_ordinary_internal_mount_is_reported_and_not_flagged(tmp_path):
    """Every workstation on the estate does this all day."""
    rows = _run(tmp_path, [_event(server="\\\\FILESRV\\home", address=_PRIVATE,
                                  status="0")])
    assert rows[0]["scope"] == "private" and rows[0]["suspicious"] == ""
    assert rows[0]["indicators"] == ""


def test_a_declared_internal_range_stops_being_outbound_to_public(tmp_path):
    """An estate holding its own routable allocation would otherwise have every
    ordinary internal mount reported here, which is how a detector gets switched
    off."""
    loud = _run(tmp_path, [_event(server="\\\\FILESRV\\home", address=_PUBLIC)])
    assert loud[0]["suspicious"] == "yes"

    quiet = _run(tmp_path, [_event(server="\\\\FILESRV\\home", address=_PUBLIC)],
                 internal=("1.2.3.0/24",))
    assert quiet[0]["scope"] == "internal"
    assert "outbound_to_public" not in quiet[0]["indicators"]
    assert quiet[0]["suspicious"] == ""


def test_an_admin_share_by_ip_is_the_remote_execution_shape(tmp_path):
    """Neither half is a finding alone: scripts address hosts by IP, and backup
    agents touch C$. Together they are how a tool moves."""
    rows = _run(tmp_path, [_event(server="\\\\10.0.0.5", share="C$",
                                  address=_PRIVATE)])
    assert "admin_share" in rows[0]["indicators"]
    assert "target_by_ip" in rows[0]["indicators"]
    assert rows[0]["suspicious"] == "yes"


def test_an_admin_share_by_name_alone_is_not_a_finding(tmp_path):
    rows = _run(tmp_path, [_event(server="\\\\FILESRV", share="ADMIN$",
                                  address=_PRIVATE)])
    assert rows[0]["indicators"] == "admin_share" and rows[0]["suspicious"] == ""


def test_ipc_dollar_is_not_an_admin_share(tmp_path):
    """Every share browse opens one. A detector that reports IPC$ reports the
    estate."""
    rows = _run(tmp_path, [_event(server="\\\\10.0.0.5", share="IPC$",
                                  address=_PRIVATE)])
    assert "admin_share" not in rows[0]["indicators"]
    assert rows[0]["suspicious"] == ""


def test_a_non_smb_port_is_named_in_the_indicator(tmp_path):
    rows = _run(tmp_path, [_event(server="\\\\FILESRV", address=_ODD_PORT,
                                  status="3221226038")],
                internal=("1.2.3.0/24",))
    assert "port_4444" in rows[0]["indicators"]


def test_a_peer_that_refused_this_host_is_an_indicator(tmp_path):
    rows = _run(tmp_path, [_event(server="\\\\10.0.0.5", share="C$",
                                  address=_PRIVATE, status="3221225581")])
    assert "refused_by_peer" in rows[0]["indicators"]
    assert "LOGON_FAILURE" in rows[0]["status"]


# --------------------------------------------------------------------------- #
# Reading the channel as it arrives
# --------------------------------------------------------------------------- #
def test_retries_are_one_destination_not_three_hundred_rows(tmp_path):
    """A client that loses a share retries. One row per retry hides the six
    destinations that matter behind the one that flapped."""
    rows = _run(tmp_path, [
        _event(server="\\\\FILESRV\\home", address=_PRIVATE, status="0",
               when=f"2026-05-19 11:{i:02d}:00.0000000") for i in range(30)
    ])
    assert len(rows) == 1
    assert rows[0]["events"] == "30"
    assert rows[0]["first_seen_utc"].endswith("11:00:00.0000000")
    assert rows[0]["last_seen_utc"].endswith("11:29:00.0000000")


def test_the_address_is_recovered_from_the_share_name_when_there_is_no_sockaddr(tmp_path):
    r"""`AddressLength 0` is common, and `\\1.2.3.4\C$` carries the same fact --
    on those events it is the only place it survives."""
    rows = _run(tmp_path, [_event(server="\\\\1.2.3.4\\C$")])
    assert rows[0]["address"] == "1.2.3.4" and rows[0]["scope"] == "public"
    assert rows[0]["suspicious"] == "yes"


def test_an_event_carrying_a_map_is_read_the_same(tmp_path):
    """Two of these events have a bundled map and the rest do not, so the mapped
    columns are the exception -- but they must still be read."""
    rows = _run(tmp_path, [_event("30807", server="\\\\1.2.3.4\\abc$",
                                  status="3221225506", mapped=True)])
    assert rows[0]["address"] == "1.2.3.4"
    assert rows[0]["status"] == "STATUS_ACCESS_DENIED (0xC0000022)"


def test_a_reason_stands_in_when_there_is_no_status(tmp_path):
    rows = _run(tmp_path, [_event("31010", server="\\\\FILESRV", share="data",
                                  reason="Access Denied.")],
                name="evtx_smbclient_sec.csv")
    assert rows[0]["channel"] == "Security"
    assert rows[0]["status"] == "Access Denied."


def test_an_event_with_nothing_to_say_is_not_a_row(tmp_path):
    assert _run(tmp_path, [_event("30800")]) == []


def test_the_three_channels_are_read_and_named(tmp_path):
    _write(tmp_path, [_event(server="\\\\A", address=_PRIVATE)],
           "evtx_smbclient_conn.csv")
    _write(tmp_path, [_event("31010", server="\\\\B", reason="Access Denied.")],
           "evtx_smbclient_sec.csv")
    _write(tmp_path, [_event("30622", server="\\\\C", share="data")],
           "evtx_smbclient_op.csv")
    S.run(_Ctx(tmp_path, tmp_path / "out"))
    with (tmp_path / "out" / "smb_client_connections.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["channel"] for r in rows} == {"Connectivity", "Security", "Operational"}


def test_no_smbclient_dump_skips(tmp_path):
    with pytest.raises(HandlerSkip):
        S.run(_Ctx(tmp_path, tmp_path / "out"))


# --------------------------------------------------------------------------- #
# The channel the configuration reaches the handler through
# --------------------------------------------------------------------------- #
def test_the_declared_ranges_reach_a_worker_context(monkeypatch):
    """`ParserContext` is the ONLY channel configuration has into a handler, and
    adding it re-fingerprinted every python parser, so it is worth a test of its
    own: the payload crosses a process boundary and both ends must agree on its
    shape. A silent mismatch here means a handler that quietly sees no ranges."""
    from artifact_engine.core import runner, scheduler

    seen = {}

    def _capture(parser, ctx, force=False):
        seen["internal"] = ctx.internal_networks
        return runner.ParserRun("x", "C", "ok", 0.0)

    monkeypatch.setattr(runner, "run_parser", _capture)
    payload = (0, object(), Path("."), Path("."), Path("."), Path("."),
               "HOST-01", "C", False, ("1.2.3.0/24", "10.0.0.0/8"))
    scheduler._run_task(payload)
    assert seen["internal"] == ("1.2.3.0/24", "10.0.0.0/8")


def test_a_handler_run_without_the_field_still_works(tmp_path):
    """An older caller, or a test, may build a context without it. Declaring
    nothing must behave exactly as it did before the field existed."""
    class _Bare:
        def __init__(self):
            self.evidence, self.out = tmp_path, tmp_path / "out"
            self.tools = self.assets = tmp_path
            self.machine_name, self.volume, self.log = "HOST-01", "C", None

    _write(tmp_path, [_event(server="\\FILESRV", address=_PUBLIC)])
    S.run(_Bare())
    with (tmp_path / "out" / "smb_client_connections.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["scope"] == "public" and rows[0]["suspicious"] == "yes"
