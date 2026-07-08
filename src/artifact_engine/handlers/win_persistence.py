"""Handler: Windows registry persistence / ASEPs. Output: persistence.csv

Native hive scan (python-registry) of the auto-start extensibility points an
attacker plants to survive a reboot or logon -- the Windows sibling of
lin_persistence and a superset of the old RECmd AutoRuns batch (which pointed
only at .../config, so it never even read a user's NTUSER.DAT). This reads
SYSTEM + SOFTWARE and every user's NTUSER.DAT / UsrClass.dat and covers the
exotic ASEPs Autoruns does: Winlogon (Userinit/Shell), AppInit / AppCert DLLs,
Image File Execution Options debuggers, LSA packages, BootExecute, Command
Processor AutoRun, netsh helpers, time providers, COM hijacks, logon scripts and
Active Setup, in addition to the Run/RunOnce keys.

Run keys legitimately hold many entries, so they are surfaced in full but only
flagged `suspicious` when the command runs from a staging dir or looks like a
download cradle. The fixed-default ASEPs (Userinit/Shell/AppInit/AppCert/LSA/...)
are compared against their known-good values and surfaced only on deviation,
which is near FP-free. It does not assert maliciousness. category: detections;
self-gates (HandlerSkip) when no hive is readable.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_liveresponse_velociraptor import _in_staging, _is_lolbin
from artifact_engine.handlers.win_systeminfo import _CONTROL_SETS, _norm, _open

# ---- known-good defaults (lower-case) --------------------------------------
_SHELL_OK = {"explorer.exe", ""}
# LSA Authentication / Security / Notification package names shipped by Windows
# (without the .dll suffix). Anything else in these lists is a package DLL an
# attacker registered (mimilib, hookpasswordchange, ...). "" covers both the
# MULTI_SZ null terminators and the literal `""` placeholder Windows stores in
# Security Packages when there are no extra SSPs.
_LSA_KNOWN = {
    "", "msv1_0", "kerberos", "schannel", "wdigest", "tspkg", "pku2u", "cloudap",
    "negoexts", "livessp", "rassfm", "scecli", "kdcsvc", "ctxsmartcardpsw",
    "wsauth", "wdigest.dll",
}


def _s(data) -> str:
    """Registry value -> flat string (REG_MULTI_SZ joined with spaces)."""
    if isinstance(data, (list, tuple)):
        return " ".join(str(x) for x in data)
    return "" if data is None else str(data)


def _values(reg, keypath: str) -> dict[str, object]:
    """{value_name: normalized_data} for a key, or {} if the key is absent."""
    try:
        key = reg.open(keypath)
    except Exception:  # noqa: BLE001 - missing key / corrupt hive
        return {}
    return {v.name(): _norm(v.value()) for v in key.values()}


def _subkeys(reg, keypath: str):
    try:
        return list(reg.open(keypath).subkeys())
    except Exception:  # noqa: BLE001
        return []


def _default(key) -> str:
    """The (default) value of an already-opened key, as a string ('' if none)."""
    for v in key.values():
        if v.name() in ("", "(default)"):
            return _s(_norm(v.value()))
    return ""


def _control_set(system) -> str:
    for cs in _CONTROL_SETS:
        try:
            system.open(cs + r"\Control")
            return cs
        except Exception:  # noqa: BLE001
            continue
    return "ControlSet001"


# ---- pure flag predicates (unit-tested directly) ---------------------------
def _run_suspicious(data: str) -> str:
    """A Run-key command is suspicious when it executes from a staging dir or
    carries a download-cradle / encoded-command hint."""
    return "yes" if (_in_staging(data) or _is_lolbin(data)) else ""


def _flag_userinit(data: str) -> str:
    """Userinit default is <system32>\\userinit.exe; any extra program appended
    (the classic `userinit.exe,C:\\evil.exe` hijack) is suspicious."""
    for part in _s(data).split(","):
        p = part.strip().rstrip("\x00").lower()
        if p and not p.endswith("userinit.exe"):
            return "yes"
    return ""


def _flag_shell(data: str) -> str:
    return "" if _s(data).strip().lower() in _SHELL_OK else "yes"


def _lsa_unknown(pkg: str) -> bool:
    # strip the surrounding quotes Windows uses on the empty placeholder (`""`).
    return pkg.strip().strip('"').strip().lower() not in _LSA_KNOWN


# ---- per-hive scans --------------------------------------------------------
_SW_RUN = (
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
)
_NT_RUN = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
)


def _scan_software(sw, rows: list[list]) -> None:
    for kp in _SW_RUN:
        for name, data in _values(sw, kp).items():
            d = _s(data)
            rows.append(["run", rf"HKLM\SOFTWARE\{kp}\{name}", d, _run_suspicious(d)])

    win = _values(sw, r"Microsoft\Windows NT\CurrentVersion\Winlogon")
    for key, flagger in (("Userinit", _flag_userinit), ("Shell", _flag_shell)):
        if key in win:
            rows.append([f"winlogon_{key.lower()}",
                         rf"HKLM\SOFTWARE\...\Winlogon\{key}", _s(win[key]), flagger(_s(win[key]))])
    for key in ("Taskman", "GinaDLL", "AppSetup"):
        if win.get(key):   # absent by default -> presence is the signal
            rows.append(["winlogon_hijack", rf"HKLM\SOFTWARE\...\Winlogon\{key}", _s(win[key]), "yes"])

    # AppInit_DLLs / LoadAppInit_DLLs (empty by default).
    for kp in (r"Microsoft\Windows NT\CurrentVersion\Windows",
               r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"):
        v = _values(sw, kp)
        if _s(v.get("AppInit_DLLs")).strip():
            rows.append(["appinit_dlls", rf"HKLM\SOFTWARE\{kp}\AppInit_DLLs",
                         _s(v["AppInit_DLLs"]), "yes"])

    # Image File Execution Options: a subkey carrying a Debugger value hijacks
    # that executable (also SilentProcessExit monitors).
    ifeo = r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    for sub in _subkeys(sw, ifeo):
        vals = {v.name(): _norm(v.value()) for v in sub.values()}
        if vals.get("Debugger"):
            rows.append(["ifeo_debugger", rf"HKLM\SOFTWARE\...\IFEO\{sub.name()}\Debugger",
                         _s(vals["Debugger"]), "yes"])

    # netsh helper DLLs: benign helpers load a bare name from System32; a path
    # (esp. into staging) is the abuse.
    for name, data in _values(sw, r"Microsoft\Netsh").items():
        d = _s(data)
        if "\\" in d or _in_staging(d):
            rows.append(["netsh_helper", rf"HKLM\SOFTWARE\Microsoft\Netsh\{name}", d,
                         "yes" if _in_staging(d) else ""])

    # Command Processor AutoRun: runs on every cmd.exe launch (empty by default).
    cp = _values(sw, r"Microsoft\Command Processor")
    if _s(cp.get("AutoRun")).strip():
        rows.append(["cmd_autorun", r"HKLM\SOFTWARE\Microsoft\Command Processor\AutoRun",
                     _s(cp["AutoRun"]), "yes"])

    # Active Setup: StubPath runs once per user at logon (many benign -> staging only).
    for sub in _subkeys(sw, r"Microsoft\Active Setup\Installed Components"):
        stub = next((_s(_norm(v.value())) for v in sub.values() if v.name() == "StubPath"), "")
        if stub and _in_staging(stub):
            rows.append(["active_setup", rf"HKLM\SOFTWARE\...\Active Setup\{sub.name()}\StubPath",
                         stub, "yes"])


def _scan_system(sy, rows: list[list]) -> None:
    cs = _control_set(sy)
    lsa = _values(sy, cs + r"\Control\Lsa")
    for key in ("Authentication Packages", "Security Packages", "Notification Packages"):
        for pkg in (lsa.get(key) or []) if isinstance(lsa.get(key), (list, tuple)) else _s(lsa.get(key)).split():
            if _lsa_unknown(pkg):
                rows.append(["lsa_package", rf"HKLM\SYSTEM\...\Lsa\{key}", str(pkg), "yes"])

    # BootExecute is a MULTI_SZ of native-mode apps run at boot; every default
    # entry is an `autocheck autochk ...` line. A foreign element is the abuse.
    be = _values(sy, cs + r"\Control\Session Manager").get("BootExecute")
    for entry in be if isinstance(be, (list, tuple)) else ([be] if be else []):
        e = _s(entry).strip()
        if e and not e.lower().startswith("autocheck autochk"):
            rows.append(["bootexecute", r"HKLM\SYSTEM\...\Session Manager\BootExecute", e, "yes"])
    for name, data in _values(sy, cs + r"\Control\Session Manager\AppCertDlls").items():
        rows.append(["appcert_dlls", rf"HKLM\SYSTEM\...\AppCertDlls\{name}", _s(data), "yes"])

    # Time providers: DllName is w32time.dll (System32) by default.
    for sub in _subkeys(sy, cs + r"\Services\W32Time\TimeProviders"):
        dll = next((_s(_norm(v.value())) for v in sub.values() if v.name() == "DllName"), "")
        if dll and (_in_staging(dll) or ("\\" in dll and "system32" not in dll.lower())):
            rows.append(["time_provider", rf"HKLM\SYSTEM\...\TimeProviders\{sub.name()}\DllName",
                         dll, "yes" if _in_staging(dll) else ""])


def _scan_ntuser(reg, prof: str, rows: list[list]) -> None:
    for kp in _NT_RUN:
        for name, data in _values(reg, kp).items():
            d = _s(data)
            rows.append(["run", rf"HKU\{prof}\{kp}\{name}", d, _run_suspicious(d)])
    win = _values(reg, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon")
    if win.get("Shell"):   # per-user Shell override is unusual
        rows.append(["winlogon_shell", rf"HKU\{prof}\...\Winlogon\Shell", _s(win["Shell"]), "yes"])
    cp = _values(reg, r"Software\Microsoft\Command Processor")
    if _s(cp.get("AutoRun")).strip():
        rows.append(["cmd_autorun", rf"HKU\{prof}\...\Command Processor\AutoRun", _s(cp["AutoRun"]), "yes"])
    env = _values(reg, "Environment")
    if _s(env.get("UserInitMprLogonScript")).strip():
        rows.append(["logon_script", rf"HKU\{prof}\Environment\UserInitMprLogonScript",
                     _s(env["UserInitMprLogonScript"]), "yes"])


def _scan_usrclass(reg, prof: str, rows: list[list]) -> None:
    # COM hijack: a per-user CLSID server pointing into a staging dir shadows the
    # machine-wide (HKLM) registration. Only staging hits are surfaced (low FP).
    for sub in _subkeys(reg, "CLSID"):
        for server in ("InprocServer32", "InprocServer32Wow", "LocalServer32"):
            try:
                data = _default(sub.subkey(server))
            except Exception:  # noqa: BLE001
                continue
            if data and _in_staging(data):
                rows.append(["com_hijack",
                             rf"HKU\{prof}\Classes\CLSID\{sub.name()}\{server}", data, "yes"])


def run(ctx) -> None:
    cfg = Path(ctx.evidence) / "Windows" / "System32" / "config"
    software = _open(cfg / "SOFTWARE")
    system = _open(cfg / "SYSTEM")
    users_dir = Path(ctx.evidence) / "Users"
    ntusers = sorted(users_dir.glob("*/NTUSER.DAT")) if users_dir.is_dir() else []
    if not (software or system or ntusers):
        raise HandlerSkip("no registry hives")

    rows: list[list] = []
    if software:
        _scan_software(software, rows)
    if system:
        _scan_system(system, rows)
    for ntuser in ntusers:
        prof = ntuser.parent.name
        reg = _open(ntuser)
        if reg:
            _scan_ntuser(reg, prof, rows)
        uc = _open(ntuser.parent / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat")
        if uc:
            _scan_usrclass(uc, prof, rows)

    # Suspicious first, then group by technique / location.
    rows.sort(key=lambda r: (r[3] != "yes", r[0], r[1]))
    write_csv(ctx.out, "persistence.csv",
              ["technique", "source", "detail", "suspicious"], rows)
