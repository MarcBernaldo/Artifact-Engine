r"""Handler: what a running process claims to be, against what it is.
Output: art_process_identity.csv

UAC collects `live_response/process/proc/<pid>/` for every process -- cmdline,
comm, status, the exe symlink -- and nothing read it. Those files hold three
independent answers to "what is this process", written by three different
parties, and an implant has to lie in all three to stay hidden:

  cmdline   argv, chosen by the process itself. What `ps` shows.
  comm      the kernel's name for it: the basename of what was exec'd, 15 chars,
            and settable by the process. What `top` shows.
  exe       the symlink to the binary on disk, which the kernel maintains and
            the process cannot rewrite. The only one of the three that is not
            the process's own claim.

`container` names the runtime whose cgroup the process is in (kubepods,
docker, libpod, containerd, crio, lxc), from UAC's `ps -axo pid,user,cgroup`;
empty for a host process or when that listing is missing.

`lin_proc_anomalies` asks where a process runs FROM (memfd, staging dirs, hidden
from ps). This asks whether its names agree, which catches the case that one
misses: a process running from an ordinary-looking path under a borrowed name.

One row per process, whether or not anything is wrong -- the join itself is the
artifact, and it did not exist anywhere before. `flags` names what disagreed.

FLAGS
  argv0_bracketed  argv[0] is `[name]`, the shape `ps` uses for kernel threads.
                   A real kernel thread has an EMPTY cmdline, so a bracketed
                   argv[0] means a userland process is dressed as one.
  comm_mismatch    comm is explained by neither the exe nor the command line.
  exe_deleted      the binary is gone from disk. Ordinary during a package
                   update, which is why it does not flag `suspicious` on its
                   own -- but UAC recovered the bytes, and `recovered_exe` in
                   the same folder is what to look at next.
  uid_no_passwd    the process runs as a UID with no entry in /etc/passwd.
                   Inside a container that is normal -- the image brings its
                   own users -- so there it is recorded but not `suspicious`
                   (v0.7.145: on six real hosts 497 of 574 flags were pods).
                   v0.7.170, the two left on a real host: a process `ps` did
                   not list (it started after `ps` ran) is in the container of
                   the nearest parent `ps` did list -- 29 of 40 flags; and
                   where nsswitch.conf takes accounts from a directory (sss,
                   ldap, nis, winbind) a UID passwd lacks is a domain account,
                   recorded but not suspicious -- the other 11, all in login
                   sessions. systemd's dynamic users (61184-65519) likewise
                   where nsswitch names `systemd`.
  exe_unknown      the exe symlink was not collected for this PID, so
                   `comm_mismatch` could NOT be judged. Recorded rather than
                   left blank: a check that quietly did not run is the one thing
                   that must never look like a check that passed.
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.handlers._lincommon import live_response, read_lines, read_text, root, write_csv
from artifact_engine.handlers.lin_proc_anomalies import proc_link

# Long enough to recognise a command, short enough that one process cannot make
# the CSV unreadable. The full string is in the evidence.
_CMDLINE_CHARS = 300

# `ps` renders a kernel thread as [kworker/0:1]. A kernel thread's cmdline in
# /proc is EMPTY, so nothing legitimate writes this shape into argv[0].
_BRACKETED = re.compile(r"^\[.*\]$")

_DELETED = " (deleted)"

# A container runtime's mark in a cgroup path, most specific first: a pod's
# containers run under kubepods, whichever runtime started them.
_RUNTIMES = ("kubepods", "libpod", "docker", "crio", "containerd", "lxc")

# comm is truncated to TASK_COMM_LEN-1 characters by the kernel, so a name any
# longer than this can only ever be compared by its first 15.
_COMM_LEN = 15


# nsswitch `passwd:` sources that resolve accounts /etc/passwd does not hold.
_DIRECTORY = {"sss", "ldap", "nis", "nisplus", "winbind"}
_DYNAMIC = range(61184, 65520)          # systemd DynamicUser= UIDs


def uid_resolver(base: Path) -> tuple[bool, bool]:
    """(a directory resolves accounts, systemd resolves its dynamic UIDs), from
    the `passwd:` line of nsswitch.conf. `compat` with a `+` line in passwd is
    NIS too. Without that line -- nsswitch.conf not collected, on one real host
    -- a configured SSSD (/etc/sssd/sssd.conf) is taken as the directory."""
    sources: set[str] = set()
    found = False
    for line in read_lines(base / "etc" / "nsswitch.conf"):
        head, sep, rest = line.split("#", 1)[0].partition(":")
        if sep and head.strip() == "passwd":
            found = True
            sources |= {w.lower() for w in rest.split() if w.isalpha()}
    if not found and (base / "etc" / "sssd" / "sssd.conf").is_file():
        sources.add("sss")
    if "compat" in sources and any(ln.startswith(("+", "-"))
                                   for ln in read_lines(base / "etc" / "passwd")):
        sources.add("nis")
    return bool(sources & _DIRECTORY), "systemd" in sources


def _passwd_users(base: Path) -> dict[str, str]:
    """uid -> account name, from /etc/passwd."""
    out: dict[str, str] = {}
    for line in read_lines(base / "etc" / "passwd"):
        parts = line.split(":")
        if len(parts) >= 3 and parts[2].isdigit():
            out[parts[2]] = parts[0]
    return out


def read_argv(path: Path) -> list[str]:
    """argv from a captured /proc/<pid>/cmdline. Public: `lin_recovered_exe`
    reads the same tree to say WHICH process a rescued binary belonged to.

    In /proc the arguments are NUL-separated. Collectors differ on whether they
    keep that or translate it, so both are handled: split on NUL, and if that
    yields a single field, fall back to whitespace.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    text = raw.decode("utf-8", "replace").rstrip("\x00\n")
    if not text.strip():
        return []
    parts = [p for p in text.split("\x00") if p]
    return parts if len(parts) > 1 else text.split()


def read_status(path: Path) -> dict[str, str]:
    """The `Key:\tvalue` fields of /proc/<pid>/status."""
    out: dict[str, str] = {}
    for line in read_lines(path):
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip()] = v.strip()
    return out


# A name that differs from another only by trailing digits, dots or dashes is
# the same program at a different version. Nothing else is allowed to differ:
# `cron` and `crond` are two programs, and that is exactly the pair this check
# has to keep apart.
_VERSION_TAIL = re.compile(r"^[.\-_]?[0-9][0-9.\-_]*$")


def _clean_name(token: str) -> str:
    """A comparable program name from one argv token.

    Strips the decorations honest programs put in argv[0]: a login shell's
    leading `-`, and everything after the `:` of the `sshd: user@pts/0` /
    `nginx: worker process` / `postgres: checkpointer` family.
    """
    head = token.strip().split(":", 1)[0]
    return Path(head).name.lstrip("-")[:_COMM_LEN]


def _same_program(a: str, b: str) -> bool:
    """Two program names that differ only by a version suffix.

    `/proc/<pid>/exe` resolves symlinks and comm does not: a unit whose shebang
    reads `/usr/bin/python3` runs with comm `python3` while its exe is
    `/usr/bin/python3.11`. Same program -- and on a host full of python and perl
    units, that difference alone would be most of the noise this check produces.
    """
    if a == b:
        return True
    lo, hi = sorted((a, b), key=len)
    return bool(lo) and hi.startswith(lo) and bool(_VERSION_TAIL.match(hi[len(lo):]))


def names_agree(comm: str, argv: list[str], exe: str) -> bool:
    """True when `comm` is explained by the exe or by the command line.

    comm and argv diverge constantly for honest reasons, and every one of them
    has to be allowed here or the flag is noise:

      truncation    `systemd-journald` is 16 characters; comm holds 15
      decoration    sshd/nginx/postgres rewrite argv[0] into a status string
      login shells  argv[0] is `-bash` while comm is `bash`
      interpreters  a script with a `#!/usr/bin/python3` line runs with comm
                    `python3` and an argv that never mentions python at all --
                    which is why the EXE is checked first. It is the kernel's
                    answer, not the process's, and it settles the common case
                    that argv alone cannot.
    """
    want = comm[:_COMM_LEN]
    if not want:
        return True                       # nothing claimed, nothing to disagree with
    if exe and _same_program(_clean_name(exe), want):
        return True
    return any(_same_program(_clean_name(a), want) for a in argv)


def exe_by_pid(lr: Path) -> dict[str, str]:
    """pid -> exe symlink target, from `ls -l /proc/*/exe`."""
    out: dict[str, str] = {}
    for ln in read_lines(lr / "process" / "running_processes_full_paths.txt"):
        p = proc_link(ln)
        if p:
            out[p[0]] = p[2].strip()
    return out


def container_by_pid(lr: Path) -> tuple[dict[str, str], set[str]]:
    """(pid -> container runtime, every pid listed), from `ps -axo
    pid,user,cgroup`; host processes are listed but have no runtime."""
    out: dict[str, str] = {}
    listed: set[str] = set()
    for ln in read_lines(lr / "process" / "ps_-axo_pid_user_cgroup.txt")[1:]:
        parts = ln.split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        listed.add(parts[0])
        cgroup = parts[2].lower()
        for runtime in _RUNTIMES:
            if runtime in cgroup:
                out[parts[0]] = runtime
                break
    return out, listed


def inherit(pid: str, ppid: dict[str, str], containers: dict[str, str],
            listed: set[str]) -> str:
    """The container of a process `ps` did not list: that of the nearest parent
    it did. A process started after `ps` ran is in its parent's cgroup unless it
    moved, and the parent is what `ps` saw. One `ps` listed is the answer, even
    a host process; nothing listed up the chain is no answer."""
    seen = 0
    while pid and pid not in listed and seen < 64:
        pid = ppid.get(pid, "")
        seen += 1
    return containers.get(pid, "") if pid in listed else ""


def pid_dirs(proc_root: Path) -> list[Path]:
    if not proc_root.is_dir():
        return []
    return sorted((d for d in proc_root.iterdir() if d.is_dir() and d.name.isdigit()),
                  key=lambda d: int(d.name))


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    if not lr:
        return
    pids = pid_dirs(lr / "process" / "proc")
    if not pids:
        return

    users = _passwd_users(root(ctx.evidence))
    directory, dynamic = uid_resolver(root(ctx.evidence))
    exes = exe_by_pid(lr)
    containers, listed = container_by_pid(lr)
    status = {d.name: read_status(d / "status.txt") for d in pids}
    ppid = {pid: st.get("PPid", "") for pid, st in status.items()}
    rows: list[list] = []

    for d in pids:
        pid = d.name
        argv = read_argv(d / "cmdline.txt")
        comm = read_text(d / "comm.txt").strip()
        st = status[pid]
        if not comm:
            comm = st.get("Name", "")
        # "Uid: real effective saved fs" -- the real UID is what the process runs as.
        uid = (st.get("Uid", "").split() or [""])[0]
        raw_exe = exes.get(pid, "")
        deleted = raw_exe.endswith(_DELETED)
        exe = raw_exe[: -len(_DELETED)].strip() if deleted else raw_exe

        flags: list[str] = []
        if argv and _BRACKETED.match(argv[0].strip()):
            flags.append("argv0_bracketed")
        if not raw_exe:
            # Judged as unknown rather than as agreement: without the kernel's
            # answer, a shebang script is indistinguishable from a borrowed name.
            flags.append("exe_unknown")
        elif not names_agree(comm, argv, exe):
            flags.append("comm_mismatch")
        if deleted:
            flags.append("exe_deleted")
        if uid and uid not in users:
            flags.append("uid_no_passwd")

        # exe_deleted alone stays unflagged: a package update replaces the binary
        # under a running process every time one is applied, and a signal that
        # fires on routine patching is a signal nobody reads. exe_unknown is a
        # gap in the evidence, not a finding about the host.
        # uid_no_passwd in a container is the image's own user, not the host's;
        # with a directory behind nsswitch it is a domain account.
        container = containers.get(pid, "") if pid in listed else inherit(
            pid, ppid, containers, listed)
        elsewhere = container or directory or (
            dynamic and uid.isdigit() and int(uid) in _DYNAMIC)
        loud = {"argv0_bracketed", "comm_mismatch"} | (set() if elsewhere else {"uid_no_passwd"})
        rows.append([
            pid, st.get("PPid", ""), users.get(uid, ""), uid, comm,
            argv[0] if argv else "", " ".join(argv)[:_CMDLINE_CHARS], raw_exe,
            st.get("State", ""), container, "+".join(flags),
            "yes" if loud.intersection(flags) else "",
        ])

    write_csv(ctx.out, "art_process_identity.csv",
              ["pid", "ppid", "user", "uid", "comm", "argv0", "cmdline", "exe",
               "state", "container", "flags", "suspicious"], rows)
