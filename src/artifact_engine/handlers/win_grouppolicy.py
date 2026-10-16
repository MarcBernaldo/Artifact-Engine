"""Handler: registry settings pushed by Group Policy (Registry.pol).
Output: group_policy.csv

Policy-level tampering -- Defender switched off, script-block logging turned
off, the firewall disabled, a program run at every logon -- is applied through
`Registry.pol` and lands in the hives only while the policy is linked. Unlink
it and the live registry no longer shows it; the file in SYSVOL still does
(backlog §35). `sysvol` reads Group Policy Preferences and scripts; this reads
the other half, the Administrative Templates registry settings.

Sources: every `Registry.pol` under `Windows/SYSVOL` (each GPO's `Machine` and
`User` folders, on a domain controller) and the local policy under
`Windows/System32/GroupPolicy` and `GroupPolicyUsers`. One row per setting.

Format (MS-GPREG): `PReg` + version 1, then entries
`[key;value;type;size;data]` whose delimiters and strings are UTF-16LE and whose
type and size are little-endian 32-bit. A value named `**del.X` deletes X,
`**delvals.` deletes every value of the key; those are kept as rows with the
action spelled out -- removing a setting is as much a policy as adding one.

Flagged: a setting that disarms the host -- Defender disabled or given an
exclusion, PowerShell script-block / module logging or transcription turned
off, command lines dropped from process auditing, a firewall profile disabled,
UAC disabled, WDigest told to keep cleartext credentials -- and a program a
policy runs at logon from a staging directory or through a LOLBin.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_liveresponse_velociraptor import _in_staging, _is_lolbin

HEADER = ["source", "gpo", "scope", "key", "value", "type", "data", "action",
          "suspicious", "note", "file"]

_SIG = b"PReg"
_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
          4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 7: "REG_MULTI_SZ", 11: "REG_QWORD"}
_GUID = re.compile(r"\{[0-9A-Fa-f\-]{36}\}")
_OPEN, _SEMI, _CLOSE = "[".encode("utf-16-le"), ";".encode("utf-16-le"), "]".encode("utf-16-le")

# (key suffix, value, data that disarms, note). Keys are compared lower-cased
# and by suffix, so both the policy and the plain hive path match.
_DISARM = [
    (r"software\policies\microsoft\windows defender", "disableantispyware", "1",
     "Defender turned off by policy"),
    (r"software\policies\microsoft\windows defender", "disableantivirus", "1",
     "Defender turned off by policy"),
    (r"windows defender\real-time protection", "disablerealtimemonitoring", "1",
     "Defender real-time protection off"),
    (r"windows defender\real-time protection", "disablebehaviormonitoring", "1",
     "Defender behaviour monitoring off"),
    (r"windows defender\real-time protection", "disableioavprotection", "1",
     "Defender scan of downloads off"),
    (r"windows defender\real-time protection", "disableonaccessprotection", "1",
     "Defender on-access protection off"),
    (r"windows defender\real-time protection", "disablescriptscanning", "1",
     "Defender script scanning off"),
    (r"powershell\scriptblocklogging", "enablescriptblocklogging", "0",
     "PowerShell script-block logging turned off"),
    (r"powershell\modulelogging", "enablemodulelogging", "0",
     "PowerShell module logging turned off"),
    (r"powershell\transcription", "enabletranscripting", "0",
     "PowerShell transcription turned off"),
    (r"policies\system\audit", "processcreationincludecmdline_enabled", "0",
     "command lines dropped from process-creation events"),
    (r"currentversion\policies\system", "enablelua", "0", "UAC disabled"),
    (r"securityproviders\wdigest", "uselogoncredential", "1",
     "WDigest keeps cleartext credentials in memory"),
]
_FIREWALL = re.compile(r"windowsfirewall\\(domain|standard|public|private)profile$")
_EXCLUSION = re.compile(r"windows defender\\exclusions\\(paths|processes|extensions|ipaddresses)$")
_RUN_KEY = re.compile(r"currentversion\\(policies\\explorer\\)?run(once)?$")


def _decode(rtype: int, raw: bytes) -> str:
    if rtype in (1, 2):
        return raw.decode("utf-16-le", "replace").rstrip("\x00")
    if rtype == 7:
        return "|".join(s for s in raw.decode("utf-16-le", "replace").split("\x00") if s)
    if rtype == 4 and len(raw) >= 4:
        return str(struct.unpack_from("<I", raw)[0])
    if rtype == 5 and len(raw) >= 4:
        return str(struct.unpack_from(">I", raw)[0])
    if rtype == 11 and len(raw) >= 8:
        return str(struct.unpack_from("<Q", raw)[0])
    return raw.hex()


def _string(buf: bytes, pos: int) -> tuple[str, int]:
    """A null-terminated UTF-16LE string at `pos`; (text, position after it)."""
    end = pos
    while end + 1 < len(buf) and buf[end:end + 2] != b"\x00\x00":
        end += 2
    return buf[pos:end].decode("utf-16-le", "replace"), end + 2


def parse(data: bytes) -> list[tuple[str, str, str, str]]:
    """(key, value, type name, decoded data) per entry. Stops quietly at the
    first entry that does not parse: what came before it is still the policy."""
    if data[:4] != _SIG:
        return []
    out = []
    pos = 8
    while pos + 2 <= len(data):
        if data[pos:pos + 2] != _OPEN:
            break
        key, pos = _string(data, pos + 2)
        if data[pos:pos + 2] != _SEMI:
            break
        value, pos = _string(data, pos + 2)
        if data[pos:pos + 2] != _SEMI or pos + 16 > len(data):
            break
        rtype = struct.unpack_from("<I", data, pos + 2)[0]
        size = struct.unpack_from("<I", data, pos + 8)[0]
        start = pos + 14
        raw = data[start:start + size]
        pos = start + size
        if data[pos:pos + 2] != _CLOSE:
            break
        pos += 2
        out.append((key, value, _TYPES.get(rtype, str(rtype)), _decode(rtype, raw)))
    return out


def _action(value: str) -> tuple[str, str]:
    low = value.lower()
    if low.startswith("**delvals."):
        return "", "delete every value"
    if low.startswith("**del."):
        return value[6:], "delete value"
    if low.startswith("**deletevalues"):
        return "", "delete values"
    if low.startswith("**deletekeys"):
        return "", "delete keys"
    if low.startswith("**soft."):
        return value[7:], "set if absent"
    if low.startswith("**"):
        return value, "special"
    return value, "set"


def _flag(key: str, value: str, data: str, action: str) -> tuple[str, str]:
    if action not in ("set", "set if absent"):
        return "", ""
    k, v, d = key.lower().rstrip("\\"), value.lower(), data.strip()
    for suffix, name, bad, note in _DISARM:
        if k.endswith(suffix) and v == name and d == bad:
            return "yes", note
    if _FIREWALL.search(k) and v == "enablefirewall" and d == "0":
        return "yes", "a Windows Firewall profile disabled by policy"
    if _EXCLUSION.search(k) and v:
        return "yes", f"Defender exclusion ({_EXCLUSION.search(k).group(1)}) by policy"
    if _RUN_KEY.search(k) and d and (_in_staging(d) or _is_lolbin(d)):
        return "yes", "runs at logon by policy, from a staging dir or a LOLBin"
    return "", ""


def _files(ev: Path) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    sysvol = ev / "Windows" / "SYSVOL"
    if sysvol.is_dir():
        found += [("sysvol", p) for p in sysvol.rglob("*") if p.name.lower() == "registry.pol"]
    for local in ("GroupPolicy", "GroupPolicyUsers"):
        d = ev / "Windows" / "System32" / local
        if d.is_dir():
            found += [("local", p) for p in d.rglob("*") if p.name.lower() == "registry.pol"]
    return found


def run(ctx) -> None:
    ev = Path(ctx.evidence)
    files = _files(ev)
    if not files:
        raise HandlerSkip("no Registry.pol")
    rows: list[list] = []
    seen: set[tuple[str, str, bytes]] = set()
    for source, path in files:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        gpo = (_GUID.search(str(path)) or [""])[0] if source == "sysvol" else ""
        scope = path.parent.name.capitalize()          # Machine / User
        # SYSVOL is often collected twice (domain\ and sysvol\<fqdn>\, a junction)
        if (gpo, scope.lower(), data) in seen:
            continue
        seen.add((gpo, scope.lower(), data))
        rel = path.relative_to(ev).as_posix()
        for key, raw_value, rtype, decoded in parse(data):
            value, action = _action(raw_value)
            suspicious, note = _flag(key, value, decoded, action)
            rows.append([source, gpo, scope, key, value, rtype, decoded, action,
                         suspicious, note, rel])
    write_csv(ctx.out, "group_policy.csv", HEADER, rows)
