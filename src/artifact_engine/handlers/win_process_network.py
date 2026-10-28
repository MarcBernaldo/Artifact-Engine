"""Handler: the processes of a Windows host, each with the live sockets it holds.
Output: art_process_network.csv (see `_procnet`).

Read from the Velociraptor LiveResponse results the `liveresponse` parser
reads (Windows.System.Pslist and Windows.Network.Netstat, or ListeningPorts
when there is no Netstat), joined by PID: path, command line, account,
elevation, hashes, signature and start time of the owner, and its parent. A
process with no socket is one row of its own, so this is the host's process
table too and `liveresponse` writes neither list again (v0.7.162). The same
table and columns as from UAC or a memory image.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core import netclass
from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _procnet
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers._webcommon import Geo
from artifact_engine.handlers.win_liveresponse_velociraptor import (
    _artifact_key,
    _find_results,
    _read_jsonl,
)


def _hash(rec: dict, algo: str) -> str:
    """A digest from Pslist's `Hash` -- nested as Velociraptor writes it, or
    flattened (`Hash.SHA256`) as some exports do."""
    h = rec.get("Hash")
    if isinstance(h, dict):
        return str(h.get(algo) or "")
    return str(rec.get(f"Hash.{algo}") or "")


def _authenticode(rec: dict, key: str) -> str:
    """`Trusted` or `SubjectName` from Pslist's Authenticode, nested or flattened."""
    a = rec.get("Authenticode")
    v = a.get(key) if isinstance(a, dict) else rec.get(f"Authenticode.{key}")
    return str(v or "")


def _signer(subject: str) -> str:
    """The common name of a certificate subject (`C=US, ..., CN=Example Corp`),
    or the whole subject when it has none."""
    for part in subject.split(","):
        k, _, v = part.strip().partition("=")
        if k.upper() == "CN" and v:
            return v.strip()
    return subject.strip()


def _elevated(rec: dict) -> str:
    v = rec.get("TokenIsElevated")
    return "" if v is None else str(bool(v)).lower()


def _proto(rec: dict) -> str:
    """`tcp`, `udp6`: Velociraptor gives the type and the family apart."""
    kind = str(rec.get("Type") or rec.get("Protocol") or "").strip().lower()
    six = "6" if "6" in str(rec.get("Family") or "") else ""
    return f"{kind}{six}" if kind else ""


def run(ctx) -> None:
    if str(ctx.volume).upper().startswith("VSS"):
        raise HandlerSkip("LiveResponse is host-global, parsed on the live volume only")
    results = _find_results(ctx)
    if results is None:
        raise HandlerSkip("no Velociraptor LiveResponse results")
    files = {_artifact_key(f): f for f in results.glob("*.json")}
    procs_raw = _read_jsonl(files["Windows.System.Pslist"]) \
        if "Windows.System.Pslist" in files else []
    if "Windows.Network.Netstat" in files:
        sockets, kind = _read_jsonl(files["Windows.Network.Netstat"]), "netstat"
    elif "Windows.Network.ListeningPorts" in files:
        sockets, kind = _read_jsonl(files["Windows.Network.ListeningPorts"]), "listening_ports"
    else:
        sockets, kind = [], "pslist"
    if not procs_raw and not sockets:
        raise HandlerSkip("no Pslist, Netstat or ListeningPorts in the LiveResponse results")

    procs = {}
    for p in procs_raw:
        procs[p.get("Pid")] = {
            "process": p.get("Name") or "", "path": p.get("Exe") or "",
            "cmdline": p.get("CommandLine") or "", "user": p.get("Username") or "",
            "elevated": _elevated(p),
            "md5": _hash(p, "MD5"), "sha1": _hash(p, "SHA1"), "sha256": _hash(p, "SHA256"),
            "signature": _authenticode(p, "Trusted"),
            "signer": _signer(_authenticode(p, "SubjectName")),
            "ppid": p.get("Ppid"),
            # Velociraptor writes RFC 3339 in UTC (`...Z`)
            "started_utc": p.get("CreateTime") or ""}
    conns = []
    for r in sockets:
        if kind == "netstat":
            conns.append({"pid": r.get("Pid"), "owner": r.get("Name") or "",
                          "proto": _proto(r), "state": r.get("Status") or "",
                          "local_addr": r.get("Laddr.IP") or "",
                          "local_port": r.get("Laddr.Port"),
                          "remote_addr": r.get("Raddr.IP") or "",
                          "remote_port": r.get("Raddr.Port"),
                          # when the socket was opened, RFC 3339 in UTC
                          "socket_created_utc": r.get("Timestamp") or ""})
        else:
            conns.append({"pid": r.get("Pid"), "owner": r.get("Name") or "",
                          "proto": _proto(r), "state": "LISTEN",
                          "local_addr": r.get("Address") or "", "local_port": r.get("Port")})
    nc = netclass.parse(getattr(ctx, "internal_networks", ()) or ())
    write_csv(ctx.out, _procnet.TABLE, _procnet.HEADER,
              _procnet.rows(procs, conns, f"velociraptor/{kind}", nc, Geo(Path(ctx.assets))))
