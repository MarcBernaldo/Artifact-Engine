"""Handler: SYSVOL (domain controllers) — Group Policy Preferences and scripts.

Only DCs replicate ``Windows\\SYSVOL``, so the presence of that tree is what
scopes this parser to a domain controller. Two things matter forensically and
nothing else in the pipeline touches them:

* ``sysvol_gpp.csv`` — Group Policy Preferences items (Scheduled Tasks, Groups,
      Services, Data Sources, Drives, ...). Two attacker-relevant signals:
        - **cpassword**: GPP stores the "run as" credential AES-256 encrypted
          with a key Microsoft published (MS14-025). Any cpassword is a finding;
          we decrypt it in place. A scheduled task or service pushed domain-wide
          with a stored password is textbook privilege escalation.
        - **Scheduled Tasks pushed by GPO**: command line, run-as and trigger —
          the domain-wide equivalent of the on-disk task store (win_tasks_disk).

* ``sysvol_scripts.csv`` — logon/logoff/startup/shutdown script assignments from
      ``scripts.ini`` / ``psscripts.ini`` (what actually runs, and in which
      order), one row per assignment, flagged when the script path looks off.

SYSVOL is collected either as ``SYSVOL\\domain\\...`` or ``SYSVOL\\sysvol\\<fqdn>\\...``
(a junction to the same content); we walk the whole tree and dedup by GPO GUID +
relative path so a doubled layout is not counted twice.
"""

from __future__ import annotations

import base64
import binascii
import configparser
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_liveresponse_velociraptor import _in_staging, _is_lolbin

# AES-256 key Microsoft published for GPP cpassword (same for every domain).
_GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")

# GPP action codes -> readable verb (attribute is a single letter, sometimes a digit).
_ACTION = {"C": "Create", "R": "Replace", "U": "Update", "D": "Delete",
           "0": "Create", "1": "Replace", "2": "Update", "3": "Delete"}

# GUID of a GPO folder, used to label rows and dedup the doubled SYSVOL layout.
_GUID = re.compile(r"\{[0-9A-Fa-f\-]{36}\}")

# Privileged groups: adding a member to one via GPP restricted-groups is a finding
# (matches the localised "Administradores" too).
_PRIV_GROUP = re.compile(r"admin|domain admins|enterprise admins|"
                         r"backup operators|remote desktop", re.IGNORECASE)


def _decrypt_cpassword(cpassword: str) -> str:
    """Decrypt a GPP cpassword (base64 AES-256-CBC, zero IV, public key)."""
    b64 = (cpassword or "").strip()
    if not b64:
        return ""
    b64 += "=" * ((4 - len(b64) % 4) % 4)          # MS omits the base64 padding
    try:
        blob = base64.b64decode(b64)
    except (binascii.Error, ValueError):
        return ""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(_GPP_KEY), modes.CBC(b"\x00" * 16)).decryptor()
        out = dec.update(blob) + dec.finalize()
    except Exception:  # noqa: BLE001 - lib missing or bad block -> report raw, don't crash
        return "<cpassword set; decrypt unavailable>"
    if out:                                         # strip PKCS#7 padding
        pad = out[-1]
        if 1 <= pad <= 16:
            out = out[:-pad]
    return out.decode("utf-16-le", "replace")


def _gpo_of(path: Path) -> str:
    m = _GUID.search(str(path))
    return m.group(0) if m else ""


def _attr(el, *names) -> str:
    for n in names:
        v = el.get(n)
        if v:
            return v.strip()
    return ""


def _task_command(props) -> str:
    """Command line of a GPP scheduled task: v1 keeps it in appName/args
    attributes, v2 nests a Task Scheduler <Exec> block."""
    app = _attr(props, "appName")
    args = _attr(props, "args")
    if app:
        return (app + " " + args).strip()
    cmds = []
    for ex in props.iter():
        if ex.tag.rsplit("}", 1)[-1] == "Exec":
            c = "".join(x.text or "" for x in ex if x.tag.rsplit("}", 1)[-1] == "Command")
            a = "".join(x.text or "" for x in ex if x.tag.rsplit("}", 1)[-1] == "Arguments")
            if c:
                cmds.append((c + " " + a).strip())
    return " | ".join(cmds)


def _gpp_rows(sysvol: Path) -> list[list]:
    seen: set[tuple] = set()
    rows: list[list] = []
    # GPP items live under <GPO>/{Machine,User}/Preferences/<Type>/<Type>.xml.
    for xml in sysvol.rglob("*.xml"):
        low = str(xml).lower().replace("\\", "/")
        if "/preferences/" not in low:
            continue
        gpo = _gpo_of(xml)
        rel = low.split("/preferences/", 1)[1]
        key = (gpo, rel)
        if key in seen:                            # domain/ and sysvol/ mirror each other
            continue
        seen.add(key)
        ftype = xml.stem                           # ScheduledTasks / Groups / Services / ...
        is_task = ftype.lower().startswith("scheduledtask")
        try:
            root = ET.fromstring(xml.read_bytes())
        except (ET.ParseError, OSError):
            continue
        # An item is any element with a direct <Properties> child (GPP's shape:
        # <User>/<Task>/<NTService>/... wrapping <Properties>). The display name
        # sits on the item element; the rest on <Properties>.
        for item in root.iter():
            props = next((ch for ch in item if ch.tag.rsplit("}", 1)[-1] == "Properties"), None)
            if props is None:
                continue
            name = _attr(item, "name") or _attr(props, "name", "userName", "accountName", "newName")
            action = _ACTION.get(_attr(props, "action"), _attr(props, "action"))
            runas = _attr(props, "runAs", "accountName", "userName")
            cpw = _decrypt_cpassword(_attr(props, "cpassword"))
            command = _task_command(props) if is_task else ""
            # membership changes (Groups.xml restricted groups) as the 'extra' detail
            extra = ""
            if ftype.lower() == "groups":
                adds = [_attr(m, "name") for m in item.iter()
                        if m.tag.rsplit("}", 1)[-1] == "Member" and _attr(m, "action").lower() == "add"]
                if any(adds):
                    extra = "members+: " + ", ".join(a for a in adds if a)
            susp = "yes" if (
                cpw
                or (command and (_in_staging(command) or _is_lolbin(command)))
                or (extra and _PRIV_GROUP.search(name))   # members added to a privileged group
            ) else ""
            rows.append([gpo, ftype, name, action, runas, cpw, command, extra, susp])
    rows.sort(key=lambda r: (r[8] != "yes", r[1].lower(), r[2].lower()))
    return rows


_SCRIPT_INIS = ("scripts.ini", "psscripts.ini")
# A logon/logoff script from a world-writable/temp path or a script engine that
# is unusual for a policy script (HTA/encoded VBScript/JScript, remote URL).
_SCRIPT_SUSP = re.compile(r"\\temp\\|\\programdata\\|\\public\\|\\appdata\\|"
                          r"\.(?:hta|ps1|vbe|jse|scr)\b|https?://", re.IGNORECASE)


def _script_rows(sysvol: Path) -> list[list]:
    seen: set[tuple] = set()
    rows: list[list] = []
    for ini in sysvol.rglob("*.ini"):
        if ini.name.lower() not in _SCRIPT_INIS:
            continue
        gpo = _gpo_of(ini)
        low = str(ini).lower().replace("\\", "/")
        scope = "user" if "/user/" in low else "machine" if "/machine/" in low else ""
        key = (gpo, scope, ini.name.lower())
        if key in seen:
            continue
        seen.add(key)
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        try:
            raw = ini.read_bytes()
            enc = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
            cp.read_string(raw.decode(enc, errors="replace"))
        except (OSError, configparser.Error):
            continue
        # sections are Logon/Logoff/Startup/Shutdown; entries are <i>CmdLine / <i>Parameters
        for trigger in cp.sections():
            entries: dict[str, dict[str, str]] = {}
            for opt in cp.options(trigger):
                m = re.match(r"(\d+)(cmdline|parameters)$", opt.lower())
                if m:
                    entries.setdefault(m.group(1), {})[m.group(2)] = cp.get(trigger, opt)
            for idx in sorted(entries, key=lambda x: int(x)):
                script = entries[idx].get("cmdline", "").strip()
                params = entries[idx].get("parameters", "").strip()
                if not script:
                    continue
                susp = "yes" if _SCRIPT_SUSP.search(script + " " + params) else ""
                rows.append([gpo, scope, trigger, script, params, susp])
    rows.sort(key=lambda r: (r[5] != "yes", r[0], r[2]))
    return rows


def run(ctx) -> None:
    sysvol = Path(ctx.evidence) / "Windows" / "SYSVOL"
    if not sysvol.is_dir():
        raise HandlerSkip("no Windows/SYSVOL (not a domain controller)")

    write_csv(ctx.out, "sysvol_gpp.csv",
              ["gpo", "type", "item", "action", "runas", "cpassword",
               "command", "extra", "suspicious"],
              _gpp_rows(sysvol))
    write_csv(ctx.out, "sysvol_scripts.csv",
              ["gpo", "scope", "trigger", "script", "parameters", "suspicious"],
              _script_rows(sysvol))
