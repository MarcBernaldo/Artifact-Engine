r"""Handler: what this host reached out to over SMB. Output: smb_client_connections.csv

A server attempted outbound SMB to an external address. The only record of it was
in `Microsoft-Windows-SMBClient/Connectivity`, which no parser in this engine
read; it surfaced through a generic Sigma sweep, under a rule name that cited a
CVE for software the host did not have installed. The rule name was wrong and the
BEHAVIOUR was the finding, which is the argument for reading the channel directly
rather than hoping a signature happens to cover it.

WHY THE CHANNEL IS THE POINT. Everything logged here is this host acting as the
CLIENT -- SMB going OUT. On a file server, whose whole role is to receive SMB,
that inverts the expected direction, and a connection out to an address on the
public internet is hash capture, relay or C2 rather than anything a file server
does. `internal_networks` decides what "outside" means (see `core/netclass.py`):
without it, an estate holding its own routable allocation would have every
ordinary internal mount reported here, which is how a detector gets turned off.

TWO FIELDS THAT READ AS NOISE UNTIL DECODED, and are the whole content of the
event once they are:

- `RemoteAddress` is a raw socket address written as hex. Thirty-two hex
  characters is what an eye skips; decoded it is the peer and its port, and the
  port is what says whether this was SMB at all.
- `Status` is a decimal NTSTATUS. `3221225506` and `3221226036` are a refused
  connection and an access denial -- different findings, identical-looking
  integers. Both decoders live in `_evtx` because neither is specific to SMB.

The events are AGGREGATED per destination. A client that loses a share and
retries writes the same event a few hundred times, and a table with one row per
retry hides the six destinations that matter behind the one that flapped.

Unlike the other EvtxECmd readers here, this one asks the raw payload FIRST. Two
of these events have a bundled map and the rest do not, so the mapped columns are
the exception rather than the rule, and preferring them would make the handler
work on the two events nobody needed help with.
"""

from __future__ import annotations

import csv
from pathlib import Path

from artifact_engine.core import netclass
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _evtx
from artifact_engine.handlers._lincommon import write_csv

_EVENTLOGS = Path("CSVs") / "EventLogs"
_SOURCES = {
    "Connectivity": "evtx_smbclient_conn.csv",
    "Security": "evtx_smbclient_sec.csv",
    "Operational": "evtx_smbclient_op.csv",
}

# Where SMB actually lives. Anything else on this channel is a client that was
# pointed somewhere unusual.
_SMB_PORTS = {445, 139}

# `IPC$` is deliberately absent: every share browse opens one, and a detector
# that reports it reports the estate. `C$` and `ADMIN$` are the ones that carry
# remote execution.
_ADMIN_SHARES = {"c$", "admin$"}

# NTSTATUS names that mean the far side refused this host, rather than that the
# network was in the way. A burst of these outbound is a client trying
# credentials somewhere it is not welcome.
_REFUSALS = ("LOGON_FAILURE", "ACCESS_DENIED", "WRONG_PASSWORD", "ACCOUNT_",
             "NO_SUCH_USER", "TRUSTED_RELATIONSHIP", "LOGON_TYPE_NOT_GRANTED")

_CAP = 5000

_COLUMNS = ["first_seen_utc", "last_seen_utc", "events", "channel", "event_ids",
            "server", "share", "address", "port", "status", "scope",
            "indicators", "suspicious"]


def _field(row: dict, payload: str, *names: str) -> str:
    """One EventData field, from the raw payload first and the map after."""
    for name in names:
        value = _evtx.payload_field(payload, name)
        if value:
            return value.strip()
    for col in ("PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
                "PayloadData5", "PayloadData6", "ExecutableInfo"):
        cell = (row.get(col) or "").strip()
        for name in names:
            if cell.lower().startswith(name.lower() + ":"):
                return _evtx.after(cell, name)
    return ""


def server_address(server: str) -> str:
    r"""The address in a server name, when the name IS one.

    A share is written `\\10.0.0.5\C$` as readily as `\\FILESRV\C$`, and the
    first is the same fact the sockaddr carries -- on events that have no
    sockaddr at all, it is the only fact.
    """
    text = (server or "").strip().strip("\\").split("\\")[0]
    return text if netclass.EMPTY.scope(text) else ""


class _Dest:
    """Every event about one destination."""

    __slots__ = ("count", "eids", "first", "last")

    def __init__(self) -> None:
        self.count = 0
        self.eids: set[str] = set()
        self.first = self.last = ""

    def add(self, when: str, eid: str) -> None:
        self.count += 1
        if eid:
            self.eids.add(eid)
        if when:
            self.first = when if not self.first else min(self.first, when)
            self.last = max(self.last, when)


def indicators_for(address: str, port: int, share: str, status: str,
                   server: str, internal: netclass.NetClass) -> list[str]:
    """Every structural reason this outbound connection is worth a second look."""
    found: list[str] = []
    if address and internal.is_public(address):
        found.append("outbound_to_public")
    if port and port not in _SMB_PORTS:
        found.append(f"port_{port}")
    if share.strip("\\").lower() in _ADMIN_SHARES:
        found.append("admin_share")
    if any(tok in status for tok in _REFUSALS):
        found.append("refused_by_peer")
    if server and server_address(server):
        found.append("target_by_ip")
    return found


def _rows_from(path: Path):
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        yield from csv.DictReader(line.replace("\x00", "") for line in fh)


def _collect(base: Path, internal: netclass.NetClass) -> dict[tuple, _Dest]:
    seen: dict[tuple, _Dest] = {}
    for channel, name in _SOURCES.items():
        path = base / _EVENTLOGS / name
        if not path.is_file():
            continue
        for row in _rows_from(path):
            payload = row.get("Payload") or ""
            server = _field(row, payload, "ServerName", "Server")
            share = _field(row, payload, "ShareName", "Share")
            address, port = _evtx.sockaddr_from_hex(
                _field(row, payload, "RemoteAddress", "Address", "ServerAddress"))
            if not address:
                address = server_address(server)
            status = (_evtx.ntstatus_name(_field(row, payload, "Status"))
                      or _field(row, payload, "Reason"))
            if not (server or share or address):
                continue        # an event of this channel with nothing to say
            key = (channel, server.lower(), share.lower(), address, port, status)
            seen.setdefault(key, _Dest()).add(
                (row.get("TimeCreated") or "").strip(),
                (row.get("EventId") or "").strip())
    return seen


def run(ctx) -> None:
    base = Path(ctx.evidence)
    if not any((base / _EVENTLOGS / n).is_file() for n in _SOURCES.values()):
        raise HandlerSkip("no SMBClient channel dumps to read")

    internal = netclass.parse(getattr(ctx, "internal_networks", ()))
    try:
        seen = _collect(base, internal)
    except (OSError, csv.Error) as e:
        raise HandlerSkip(f"SMBClient dumps unreadable: {e}") from e
    if not seen:
        return                                # the channels exist and are quiet

    rows: list[list] = []
    for (channel, server, share, address, port, status), dest in seen.items():
        found = indicators_for(address, port, share, status, server, internal)
        # The public destination is the finding on its own: this host is the
        # CLIENT here, and a client reaching the internet over SMB is not a
        # client doing its job. Everything else needs company.
        flagged = "outbound_to_public" in found or len(found) >= 2
        rows.append([
            dest.first, dest.last, dest.count, channel,
            " ".join(sorted(dest.eids)), server, share, address,
            port or "", status, internal.scope(address),
            " ".join(found), "yes" if flagged else "",
        ])

    rows.sort(key=lambda r: (r[-1] != "yes", -int(r[2]), r[0]))
    hidden = max(0, len(rows) - _CAP)
    rows = rows[:_CAP]
    if hidden:
        rows.append(["", "", "", "(not listed)", "", "", "", "", "", "", "",
                     (f"{hidden:,} further destination(s) beyond the "
                      f"{_CAP}-row cap"), ""])
    write_csv(ctx.out, "smb_client_connections.csv", _COLUMNS, rows)
