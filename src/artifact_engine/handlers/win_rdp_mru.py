"""Handler: outbound RDP history per user (Terminal Server Client). Output: rdp_outbound.csv

Where each user RDP'd TO, from their NTUSER.DAT: `Terminal Server Client\\Default`
(MRU list of targets, MRU0 = most recent) merged with `Terminal Server Client\\
Servers\\<host>` (UsernameHint = account used against that host; the subkey's
last-write time approximates the last completed connection where the client
stored settings, and a CertHash means the user accepted an untrusted/self-signed
certificate - i.e. the connection really happened).

This is the client-side complement of the evtx_rdp_out event log (which rolls
over); the MRU survives for years, so it reconstructs the operator's lateral-
movement map - including connections made with OTHER accounts (a local
administrator hint on a remote host is exactly the pattern to chase).
Informational, no flag column: whether a target is legitimate is case context.
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_systeminfo import _open

_KEY = r"Software\Microsoft\Terminal Server Client"
_MRU = re.compile(r"^MRU(\d+)$", re.IGNORECASE)


def _scan_hive(reg) -> dict[str, dict]:
    """{target_lower: {target, mru, hint, cert, last_write}} for one NTUSER hive."""
    out: dict[str, dict] = {}

    def entry(target: str) -> dict:
        return out.setdefault(target.lower(),
                              {"target": target, "mru": None, "hint": "",
                               "cert": "", "last_write": ""})

    try:
        for v in reg.open(_KEY + r"\Default").values():
            m = _MRU.match(v.name() or "")
            target = str(v.value() or "").strip()
            if m and target:
                e = entry(target)
                pos = int(m.group(1))
                e["mru"] = pos if e["mru"] is None else min(e["mru"], pos)
    except Exception:  # noqa: BLE001 - key absent
        pass

    try:
        for sub in reg.open(_KEY + r"\Servers").subkeys():
            target = sub.name().strip()
            if not target:
                continue
            e = entry(target)
            try:
                e["last_write"] = sub.timestamp().strftime("%Y-%m-%d %H:%M:%S")
            except Exception:  # noqa: BLE001 - fake/corrupt key
                pass
            for v in sub.values():
                if (v.name() or "").lower() == "usernamehint":
                    e["hint"] = str(v.value() or "").strip()
                elif (v.name() or "").lower() == "certhash":
                    e["cert"] = "yes"      # user accepted an untrusted certificate
    except Exception:  # noqa: BLE001 - key absent
        pass
    return out


def run(ctx) -> None:
    users_dir = Path(ctx.evidence) / "Users"
    ntusers = sorted(users_dir.glob("*/NTUSER.DAT")) if users_dir.is_dir() else []
    if not ntusers:
        raise HandlerSkip("no NTUSER hives")

    rows: list[list] = []
    for ntuser in ntusers:
        reg = _open(ntuser)
        if reg is None:
            continue
        for e in _scan_hive(reg).values():
            rows.append([ntuser.parent.name, e["target"],
                         "" if e["mru"] is None else e["mru"],
                         e["hint"], e["cert"], e["last_write"]])

    # Most recent target first per user (MRU order; Servers-only entries after).
    rows.sort(key=lambda r: (r[0].lower(), r[2] == "", r[2] if r[2] != "" else 0,
                             r[1].lower()))
    write_csv(ctx.out, "rdp_outbound.csv",
              ["user", "target", "mru", "username_hint", "cert_accepted",
               "key_last_write_utc"], rows)
