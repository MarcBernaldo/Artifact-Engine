"""Handler: Windows registry persistence / ASEPs. Output: art_reg_persistence.csv

RECmd reads the auto-start extensibility points an attacker plants to survive a
reboot or logon -- the Windows sibling of lin_persistence -- with the engine's own
batch, `assets/recmd/Persistence.reb` (v0.7.211; before it a python-registry scan
of 15 of them). RECmd replays a dirty hive's transaction logs, so the newest values
are there. Every SOFTWARE and SYSTEM value it lists, of the control set in use, and
each user's NTUSER.DAT and UsrClass.dat, one hive at a time.

The batch's Category is the row's `technique`. It covers what Autoruns does in the
registry (RECmd's RegistryASEPs, DFIRBatch and Kroll batches, curated) plus what
those lack: Run/RunOnce/RunOnceEx/RunServices and the Terminal Server install
copies, Winlogon (Userinit, Shell, Taskman, GinaDLL, Notify, mpnotify, ...),
AppInit and AppCert DLLs, IFEO debuggers / GlobalFlag / VerifierDlls,
SilentProcessExit, AeDebug, WER debuggers, LSA and SSP packages, BootExecute and
the other Session Manager boot commands, netsh helpers, print monitors and
processors, network providers, time providers, Winsock namespace providers, AMSI
providers, credential providers, shell service objects and BHOs, Active Setup,
Group Policy scripts, logon scripts, COR_PROFILER, Command Processor AutoRun,
screen savers, Office test / add-ins / Outlook home page, browser force-installed
extensions and launch commands, file-handler and UAC-bypass class hijacks, per-user
COM servers, hidden accounts (SpecialAccounts), netsh portproxy, RDP startup
programs, the SafeBoot shell, the DNS server plugin, NTDS extension points, the
Startup folder location and the StartupApproved state.

Left out, measured on four clean Windows builds and the real hosts (they list each
host's own hundreds of entries and name no program): the HKLM COM catalog, SafeBoot
driver lists, GP extensions, SvcHost groups, KnownDLLs, shell-extension CLSID lists,
IE add-on statistics, SharedDLLs and the per-user Active Setup markers. Services,
scheduled tasks and RunMRU have their own tables.

`suspicious` is "yes" by a rule that needs no list of a Windows version's defaults
(two real hosts run a build none of the clean references has): a Run, Active
Setup, script or command value that runs from a staging folder or carries a
download cradle; a DLL or program outside Windows and Program Files; a location
that differs from its one default (Userinit, Shell, BootExecute, SafeBoot shell,
RDP startup, file handlers, LSA packages Windows ships); and a location empty on
every Windows whose mere presence is the signal (IFEO debugger, SilentProcessExit,
AppCert/AppInit DLLs, COR_PROFILER, Office test, class hijacks, portproxy, ...).
It does not assert maliciousness. Per-user COM servers are listed only when the
server runs from a staging folder: a user's profile legitimately registers
thousands (OneDrive, Teams). category: detections.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_liveresponse_velociraptor import _in_staging, _is_lolbin
from artifact_engine.handlers.win_reg_activity import _exe, _recmd, _unique, _user, utc

BATCH = "Persistence.reb"
HEADER = ["technique", "source", "detail", "suspicious", "user", "key_last_write_utc"]
_AT_ONCE = 4

# ---- known-good defaults (lower-case) --------------------------------------
_SHELL_OK = {"explorer.exe", ""}
# LSA Authentication / Security / Notification packages and SSPs Windows ships
# (without the .dll suffix). "" covers the literal `""` placeholder Windows stores
# in Security Packages when there are no extra SSPs.
_LSA_KNOWN = {
    "", "msv1_0", "kerberos", "schannel", "wdigest", "tspkg", "pku2u", "cloudap",
    "negoexts", "livessp", "rassfm", "scecli", "kdcsvc", "ctxsmartcardpsw",
    "wsauth", "credssp", "pwdssp", "msapsspc", "msnsspc", "digest.ssp",
}
_FIXED = {   # (technique, value name) -> its one default, lower-case
    ("safeboot_shell", "alternateshell"): "cmd.exe",
    ("rdp_startup", "startupprograms"): "rdpclip",
    ("rdp_startup", "initialprogram"): "",
    ("winlogon_hijack", "vmapplet"): "systempropertiesperformance.exe /pagefile",
    ("winlogon_hijack", "uihost"): "logonui.exe",
    ("winlogon_hijack", "system"): "",
    ("bootexecute", "setupexecute"): "",
    ("bootexecute", "execute"): "",
    ("bootexecute", "initialcommand"): "",
    ("setup_cmdline", "cmdline"): "",
}
# A location empty on every Windows: a value there is the signal.
_PRESENCE = {"appcert_dlls", "ifeo_debugger", "ifeo_verifierdlls", "silent_process_exit",
             "cor_profiler", "office_test", "class_hijack", "port_proxy", "dns_plugin",
             "natural_language", "outlook_homepage",
             "winlogon_notify", "policies_system", "cmd_autorun", "logon_script",
             "crypto_offload", "ctf_addin", "com_hijack"}
# A DLL or program Windows loads from here: outside Windows / Program Files is odd.
_PATHS = {"netsh_helper", "drivers32", "print_monitor", "print_processor",
          "network_provider", "time_provider", "winsock_provider", "aedebug",
          "wer_debugger", "screensaver", "browser_command", "scm_extension",
          "ntds_extension"}         # a DC's own: ntdsa.dll, lsadb.dll
# A command a user or an installer sets: staging folders and cradles only.
_COMMANDS = {"run", "active_setup", "gp_script"}
_SYSTEM_DIR = re.compile(
    r"^\"?(?:%(?:systemroot|windir|programfiles|programfiles\(x86\)|programw6432|"
    r"commonprogramfiles|commonprogramfiles\(x86\))%|\\systemroot\\|"
    r"[a-z]:\\(?:windows|program files|program files \(x86\))\\)", re.IGNORECASE)
_AUTOCHK = re.compile(r"autocheck\s+autochk\s+(?:/\S+\s+)*\*", re.IGNORECASE)
_CONTROL_SET = re.compile(r"^ControlSet(\d{3})(?=\\|$)", re.IGNORECASE)
_HANDLER_DEFAULT = '"%1" %*'


def _run_suspicious(data: str) -> str:
    """A command is suspicious when it runs from a staging dir or carries a
    download-cradle / encoded-command hint."""
    return "yes" if (_in_staging(data) or _is_lolbin(data)) else ""


def _flag_userinit(data: str) -> str:
    """Userinit default is <system32>\\userinit.exe; any extra program appended
    (the classic `userinit.exe,C:\\evil.exe` hijack) is suspicious."""
    for part in str(data).split(","):
        p = part.strip().rstrip("\x00").lower()
        if p and not p.endswith("userinit.exe"):
            return "yes"
    return ""


def _flag_shell(data: str) -> str:
    return "" if str(data).strip().lower() in _SHELL_OK else "yes"


def _lsa_unknown(pkg: str) -> bool:
    name = pkg.strip().strip('"').strip().rstrip(",").lower()
    return name.removesuffix(".dll") not in _LSA_KNOWN and name not in _LSA_KNOWN


def _foreign(data: str) -> bool:
    """A path outside Windows and Program Files (a bare name is System32's)."""
    d = str(data).strip()
    if not d or _in_staging(d):
        return bool(d)
    return ("\\" in d or "/" in d) and not _SYSTEM_DIR.match(d)


def _flag(technique: str, value: str, data: str, hive: str) -> str:
    d = str(data or "").strip()
    v = value.lower()
    if technique == "winlogon_userinit":
        return _flag_userinit(d) if hive != "NTUSER" or not d else "yes"
    if technique == "winlogon_shell":
        return _flag_shell(d) if hive != "NTUSER" or not d else "yes"
    if technique == "lsa_package":
        return "yes" if any(_lsa_unknown(p) for p in d.replace(",", " ").split()) else ""
    if technique == "bootexecute":
        if v == "bootexecute":
            return "yes" if _AUTOCHK.sub("", d).strip() else ""
        if v == "bootshell":
            return "yes" if _foreign(d) or "bootim.exe" not in d.lower() else ""
        if v == "pendingfilerenameoperations":
            return ""       # installers' clean-up of Windows\Temp: context, not a flag
    if (technique, v) in _FIXED:
        return "" if d.lower() == _FIXED[(technique, v)] else "yes"
    if technique == "winlogon_hijack":
        return "yes" if d else ""
    if technique == "appinit_dlls":
        if v == "loadappinit_dlls":
            return "yes" if d not in ("", "0") else ""
        return "yes" if d else ""
    if technique == "ifeo_globalflag":     # FLG_MONITOR_SILENT_PROCESS_EXIT
        try:
            return "yes" if int(d, 0) & 0x200 else ""
        except ValueError:
            return ""
    if technique == "file_handler":
        return "" if not d or d == _HANDLER_DEFAULT or "iexplore" in d.lower() else "yes"
    if technique == "startup_folder":
        return "" if d.lower().rstrip("\\").endswith(r"start menu\programs\startup") else "yes"
    if technique == "shim_database":
        return "yes" if v == "databasepath" and d else ""
    if technique == "hidden_account":          # a value of 0 hides the account
        return "yes"
    if technique == "scm_extension" and v == "imagepath":
        return "yes" if d else ""
    if technique in _PRESENCE:
        return "yes" if d and d not in ("0",) else ""
    if technique in _PATHS:
        return "yes" if _foreign(d) else ""
    if technique in _COMMANDS:
        return _run_suspicious(d)
    return ""


def _startup_state(data: str) -> str:
    """StartupApproved: the first byte says whether Task Manager left the entry on."""
    first = re.sub(r"[^0-9A-Fa-f]", "", str(data))[:2]
    return {"02": "enabled", "06": "enabled", "03": "disabled", "07": "disabled"}.get(first, data)


def _rows(rows: list[dict], hive: str, prefix: str, user: str) -> list[list]:
    """The batch rows of one hive as table rows (SYSTEM: the control set in use)."""
    current = ""
    if hive == "SYSTEM":
        for r in rows:
            if r.get("Category") == "control_set" and str(r.get("ValueData", "")).strip():
                current = f"{int(str(r['ValueData']).strip(), 0):03d}"
                break
    out = []
    for r in rows:
        technique = (r.get("Category") or "").strip()
        if not technique or technique == "control_set":
            continue
        # RECmd names the root after the hive's own root key (ROOT, or the name
        # the tool that wrote the hive gave it): drop it, keep the path below.
        key = (r.get("KeyPath") or "").partition("\\")[2]
        if hive == "SYSTEM":
            m = _CONTROL_SET.match(key)
            if m and current and m.group(1) != current:
                continue
            key = _CONTROL_SET.sub("CurrentControlSet", key)
        value = r.get("ValueName") or ""
        data = str(r.get("ValueData") or "").strip()
        if technique == "com_hijack" and not _in_staging(data):
            continue
        if technique == "startup_approved":
            data = _startup_state(data)
        source = "\\".join(p for p in (prefix, key, value) if p)
        out.append([technique, source, data, _flag(technique, value, data, hive), user,
                    utc(r.get("LastWriteTimestamp"))])
    return out


def run(ctx) -> None:
    cfg = Path(ctx.evidence) / "Windows" / "System32" / "config"
    users_dir = Path(ctx.evidence) / "Users"
    hives: list[tuple[Path, str, str, str]] = []      # (file, hive, prefix, user)
    for name in ("SOFTWARE", "SYSTEM"):
        if (cfg / name).is_file():
            hives.append((cfg / name, name, rf"HKLM\{name}", ""))
    if users_dir.is_dir():
        for prof in sorted(p for p in users_dir.iterdir() if p.is_dir()):
            if (prof / "NTUSER.DAT").is_file():
                hives.append((prof / "NTUSER.DAT", "NTUSER", rf"HKU\{prof.name}", prof.name))
            uc = prof / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
            if uc.is_file():
                hives.append((uc, "USRCLASS", rf"HKU\{prof.name}\Classes", prof.name))
    if not hives:
        raise HandlerSkip("no registry hives")
    exe = _exe(ctx)
    batch = Path(ctx.assets) / "recmd" / BATCH
    with ThreadPoolExecutor(max_workers=_AT_ONCE) as pool:
        got = list(pool.map(lambda h: _recmd(exe, h[0], batch, ctx.log), hives))
    if all(g is None for g in got):
        raise RuntimeError("RECmd failed on every hive")
    rows: list[list] = []
    for (path, hive, prefix, user), res in zip(hives, got):
        if res is not None:
            rows += _rows(res[0], hive, prefix, user or _user(path, users_dir))
    # Suspicious first, then group by technique / location.
    rows = _unique(rows)
    rows.sort(key=lambda r: (r[3] != "yes", r[0], r[1]))
    write_csv(ctx.out, "art_reg_persistence.csv", HEADER, rows)
