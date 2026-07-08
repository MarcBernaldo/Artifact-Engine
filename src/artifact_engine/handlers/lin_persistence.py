"""Handler: Linux persistence vectors. Output: persistence.csv

Surfaces the locations an attacker uses to survive a reboot or regain access:
systemd units/timers, SysV init scripts, rc.local, shell profiles/rc files, XDG
autostart, ld.so.preload, sudoers, update-motd.d, PAM stacks, kernel-module
auto-load (modules-load.d/modprobe.d), APT invoke hooks and /etc/environment.
Many entries are legitimate OS/vendor config; the `suspicious` column flags the
ones worth a closer look (fetch-and-run, reverse shells, exec from
world-writable dirs, preloading, NOPASSWD grants, non-standard PAM modules). It
does not assert maliciousness.

Vendor systemd units (/usr/lib, /lib) are only emitted when they look
suspicious -- an admin/attacker normally drops a unit under /etc/systemd/system
or a user's ~/.config/systemd/user, which are always listed in full.
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.handlers._lincommon import read_lines, root, write_csv

# Command content that is rarely benign inside a persistence location. `eval`
# is deliberately absent: bash-completion, dircolors and lesspipe use it
# constantly, so it is noise here, not signal.
_SUSP = re.compile(
    r"/dev/tcp/|/dev/shm|/tmp/|/var/tmp/|bash\s+-i|\bnc\b|\bncat\b|\bsocat\b|"
    r"mkfifo|\bcurl\b|\bwget\b|LD_PRELOAD|base64\s+(-d|--decode)|"
    r"python[0-9.]*\s+-c|perl\s+-e|ruby\s+-e|chmod\s+\+[xs]|\.onion\b",
    re.IGNORECASE,
)

# systemd directives worth recording (start/stop commands + timer schedules).
_TIMER_KEYS = {"OnCalendar", "OnBootSec", "OnUnitActiveSec", "OnActiveSec", "Unit"}
_UNIT_KEYS = {"ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload",
              "ExecStop", *_TIMER_KEYS}

_SHELL_RC = (".bashrc", ".bash_profile", ".bash_login", ".profile",
             ".bash_aliases", ".zshrc", ".zprofile", ".bash_logout", ".kshrc")


def _susp(text: str) -> str:
    return "yes" if _SUSP.search(text) else ""


def _rel(base: Path, f: Path) -> str:
    try:
        # POSIX separators: this is a Linux artifact path, not a host path.
        return f.relative_to(base).as_posix()
    except ValueError:
        return f.name


def _homes(base: Path) -> list[Path]:
    homes = [base / "root"]
    h = base / "home"
    if h.is_dir():
        homes += [d for d in h.iterdir() if d.is_dir()]
    return [d for d in homes if d.is_dir()]


def _systemd_unit(rows: list[list], base: Path, f: Path, admin: bool) -> None:
    rel = _rel(base, f)
    is_timer = f.suffix == ".timer"
    for ln in read_lines(f):
        s = ln.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        key = s.split("=", 1)[0].strip()
        if key not in _UNIT_KEYS:
            continue
        susp = _susp(s)
        # Vendor units are package-owned: only surface them when suspicious.
        if not admin and not susp:
            continue
        kind = "timer" if (is_timer or key in _TIMER_KEYS) else "service"
        rows.append([f"systemd_{kind}", rel, s, susp])


def _systemd(rows: list[list], base: Path) -> None:
    for d, admin in ((base / "etc/systemd/system", True),
                     (base / "usr/lib/systemd/system", False),
                     (base / "lib/systemd/system", False)):
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*")):
            if f.is_file() and f.suffix in (".service", ".timer", ".conf"):
                _systemd_unit(rows, base, f, admin)
    # Per-user systemd units are user-controlled -> always listed.
    for home in _homes(base):
        ud = home / ".config/systemd/user"
        if ud.is_dir():
            for f in sorted(ud.rglob("*")):
                if f.is_file() and f.suffix in (".service", ".timer", ".conf"):
                    _systemd_unit(rows, base, f, True)


def _dump(rows: list[list], vector: str, base: Path, f: Path,
          only_suspicious: bool = False) -> None:
    """One row per non-comment line (the line attacker injection lands on).

    Large config files (profile/shell rc) are emitted suspicious-line-only:
    dumping every benign export/alias would bury the table.
    """
    rel = _rel(base, f)
    for ln in read_lines(f):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        susp = _susp(s)
        if only_suspicious and not susp:
            continue
        rows.append([vector, rel, s, susp])


def _autostart(rows: list[list], base: Path, d: Path) -> None:
    if not d.is_dir():
        return
    for f in sorted(d.glob("*.desktop")):
        rel = _rel(base, f)
        for ln in read_lines(f):
            s = ln.strip()
            if s.startswith("Exec="):
                rows.append(["autostart", rel, s, _susp(s)])


def _sudoers(rows: list[list], base: Path) -> None:
    """sudo grants. Alias/Defaults scaffolding is skipped (it can run to
    thousands of lines on enterprise hosts); only the user/group grant lines an
    attacker would add are kept. `NOPASSWD: ALL` (full passwordless root) and
    `Defaults !authenticate` (sudo with no password at all) are flagged."""
    files = [base / "etc/sudoers"]
    d = base / "etc/sudoers.d"
    if d.is_dir():
        files += sorted(f for f in d.iterdir() if f.is_file())
    for f in files:
        if not f.is_file():
            continue
        rel = _rel(base, f)
        for ln in read_lines(f):
            s = ln.strip()
            if not s:
                continue
            # '#include'/'#includedir' are real directives despite the '#'.
            if s.startswith("#") and not s.lower().startswith("#include"):
                continue
            if re.match(r"(Cmnd|User|Host|Runas)_Alias\b", s):
                continue
            if s.startswith("Defaults"):
                if re.search(r"!\s*authenticate\b", s):
                    rows.append(["sudoers", rel, s, "yes"])
                continue
            susp = "yes" if re.search(r"NOPASSWD:\s*ALL\b", s) else ""
            rows.append(["sudoers", rel, s, susp])


def _motd(rows: list[list], base: Path) -> None:
    """update-motd.d scripts run as root on every interactive/SSH login."""
    d = base / "etc/update-motd.d"
    if not d.is_dir():
        return
    for f in sorted(d.iterdir()):
        if f.is_file():
            rows.append(["motd", _rel(base, f), "", ""])   # presence: runs at login
            _dump(rows, "motd", base, f, only_suspicious=True)


_STD_PAM = re.compile(r"^pam_[\w.-]+\.so$")


def _pam(rows: list[list], base: Path) -> None:
    """PAM stacks. A module given by absolute path, a non pam_*.so name, or
    pam_exec (runs an arbitrary command on auth) is a backdoor sign."""
    d = base / "etc/pam.d"
    if not d.is_dir():
        return
    for f in sorted(d.iterdir()):
        if not f.is_file():
            continue
        rel = _rel(base, f)
        for ln in read_lines(f):
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            mod = next((t for t in s.split() if t.endswith(".so")), None)
            if not mod:
                continue
            name = mod.rsplit("/", 1)[-1]
            if "/" in mod or not _STD_PAM.match(name) or name == "pam_exec.so":
                rows.append(["pam", rel, s, "yes"])


def _kernel_modules(rows: list[list], base: Path) -> None:
    """Modules auto-loaded at boot + modprobe install/alias hooks (which can run
    arbitrary commands when a module is requested)."""
    files = [base / "etc/modules"]
    ld = base / "etc/modules-load.d"
    if ld.is_dir():
        files += sorted(f for f in ld.iterdir() if f.is_file())
    for f in files:
        if not f.is_file():
            continue
        rel = _rel(base, f)
        for ln in read_lines(f):
            s = ln.strip()
            if s and not s.startswith("#"):
                rows.append(["kernel_module", rel, s, ""])
    md = base / "etc/modprobe.d"
    if md.is_dir():
        for f in sorted(md.iterdir()):
            if not f.is_file():
                continue
            rel = _rel(base, f)
            for ln in read_lines(f):
                s = ln.strip()
                if not s or s.startswith("#") or not s.split():
                    continue
                verb = s.split()[0]
                if verb in ("install", "alias"):
                    # Benign idioms: '/bin/true|false' (disable) and
                    # '/sbin/modprobe --ignore-install' (the stock re-invoke used
                    # by nfs, firewalld, ... to set sysctls around a load).
                    benign = re.search(r"/bin/(true|false)\b", s) or "--ignore-install" in s
                    susp = "yes" if (verb == "install" and not benign) else ""
                    rows.append(["modprobe", rel, s, susp])


def _pkg_hooks(rows: list[list], base: Path) -> None:
    """APT Pre/Post-Invoke directives run a command on every apt operation."""
    d = base / "etc/apt/apt.conf.d"
    if not d.is_dir():
        return
    for f in sorted(d.iterdir()):
        if not f.is_file():
            continue
        rel = _rel(base, f)
        for ln in read_lines(f):
            s = ln.strip()
            # List every invoke hook (so the analyst sees them) but only flag the
            # ones whose command looks malicious; stock distro hooks are benign.
            if s and not s.startswith("//") and re.search(r"(Pre|Post)-Invoke", s):
                rows.append(["pkg_hook", rel, s, _susp(s)])


def run(ctx) -> None:
    base = root(ctx.evidence)
    rows: list[list] = []

    _systemd(rows, base)

    # SysV init scripts: presence is the signal (content is large boilerplate).
    ind = base / "etc/init.d"
    if ind.is_dir():
        for f in sorted(ind.iterdir()):
            if f.is_file():
                rows.append(["init_d", _rel(base, f), "", ""])

    for rc in (base / "etc/rc.local", base / "etc/rc.d/rc.local"):
        if rc.is_file():
            _dump(rows, "rc_local", base, rc)

    # System-wide login/interactive shell config.
    profile = [base / "etc/profile", base / "etc/bash.bashrc"]
    pd = base / "etc/profile.d"
    if pd.is_dir():
        profile += sorted(f for f in pd.iterdir() if f.is_file())
    for f in profile:
        if f.is_file():
            _dump(rows, "profile", base, f, only_suspicious=True)

    # Per-user shell rc/profile and autostart.
    for home in _homes(base):
        for name in _SHELL_RC:
            f = home / name
            if f.is_file():
                _dump(rows, "shell_rc", base, f, only_suspicious=True)
        _autostart(rows, base, home / ".config/autostart")

    _autostart(rows, base, base / "etc/xdg/autostart")

    _sudoers(rows, base)
    _motd(rows, base)
    _pam(rows, base)
    _kernel_modules(rows, base)
    _pkg_hooks(rows, base)

    # /etc/environment can pin LD_PRELOAD/LD_LIBRARY_PATH system-wide.
    env = base / "etc/environment"
    if env.is_file():
        _dump(rows, "environment", base, env, only_suspicious=True)

    # ld.so.preload: a non-empty file is a classic library-injection rootkit hook.
    for ln in read_lines(base / "etc/ld.so.preload"):
        s = ln.strip()
        if s and not s.startswith("#"):
            rows.append(["ld_preload", "etc/ld.so.preload", s, "yes"])

    # Surface the suspicious entries first, then group by vector.
    rows.sort(key=lambda r: (r[3] != "yes", r[0], r[1]))
    write_csv(ctx.out, "persistence.csv",
              ["vector", "source", "detail", "suspicious"], rows)
