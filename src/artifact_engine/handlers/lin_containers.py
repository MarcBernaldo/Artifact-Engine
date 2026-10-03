"""Handler: Linux containers. Outputs: containers.csv, container_changes.csv,
container_procs.csv

The blind spot this closes. Every other Linux parser here reads the HOST: the
host's `ps`, the host's bodyfile, the host's `/var/log`. A compromised container
is invisible to all of them -- its processes appear in the host `ps` as PIDs with
no context, its filesystem is not in the bodyfile in any readable form, and its
own logs exist only in what the collector asked the runtime for. UAC collects all
of it (`live_response/containers/*`, in the `full` profile) and nothing read it.

Three tables, from three different kinds of input:

- **containers.csv** -- the inventory, read from the per-container `inspect` JSON
  rather than from the `container ls` table. `ls` is a human table whose columns
  hold spaces (an image tag, a command, a port list), and column-splitting it is
  how a parser silently mis-attributes a row; `inspect` is machine-readable and
  carries everything the table does plus the mounts, the capabilities and the
  security options the flags below need. LXC has no JSON equivalent, so its
  inventory comes from `lxc_list.txt` with `lxc_config_show_<name>.txt` for the
  settings.
- **container_changes.csv** -- `docker diff`, which is the closest thing Linux
  has to an $MFT delta: every path Added, Changed or Deleted in the container's
  writable layer since the image it started from. Handed over for free, and the
  only record of what a container wrote.
- **container_procs.csv** -- `docker top`, which is what gives those host PIDs
  their context back.

What is flagged, and why each one is a finding rather than a preference:

- `privileged` -- the container can do what root on the host can do. Escape is
  not an exploit at that point, it is a feature.
- `host_network`, `host_pid` -- the namespace that separates it from the host is
  not there.
- `bind_root`, `bind_sensitive` -- a bind mount of `/`, `/etc`, `/root`, the
  docker socket or `/proc` hands the host's filesystem or control plane to the
  container.
- `cap_sys_admin` and friends, and `apparmor=unconfined` / `seccomp=unconfined`.
- On a CHANGE row: a write into a staging directory (`/tmp`, `/var/tmp`,
  `/dev/shm`), a server-side script written into a web root (the roots and the
  extensions come from `lin_webshells`, so the two agree by construction), and a
  write to the places persistence lives (`/etc/cron*`, `/etc/systemd`,
  `~/.ssh/authorized_keys`, `/etc/passwd`, `/etc/shadow`).

Nothing here asserts compromise. A privileged container is a design decision on
plenty of hosts, and a web application writes to its own web root. What the flag
says is "this is the row to read first", which is the same contract every other
`suspicious` column in this tool carries.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from artifact_engine.handlers._lincommon import live_response, read_lines, read_text, write_csv
from artifact_engine.handlers.lin_webshells import _EXTS as _SCRIPT_EXTS
from artifact_engine.handlers.lin_webshells import _WEBROOTS

# `docker` and `podman` write the same file names under the same directory, and
# `podman inspect` answers with the same keys for everything read here.
_OCI = ("docker", "podman")

_STAGING = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")

# A bind mount of any of these hands over the host, or the control plane that
# owns it. `docker.sock` is root on the host by a shorter route than an exploit.
_SENSITIVE_BINDS = ("/etc", "/root", "/boot", "/proc", "/sys", "/var/run/docker.sock",
                    "/run/docker.sock", "/var/lib/docker", "/home")

# Capabilities that take most of the distance between a container and the host.
_HOT_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "ALL"}

# Where persistence lives, as a change to any of these is a change worth reading.
_PERSISTENCE = ("/etc/cron", "/var/spool/cron", "/etc/systemd", "/etc/init.d",
                "/etc/rc.local", "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                "/root/.ssh/", "/.ssh/authorized_keys", "/etc/ld.so.preload")

_INSPECT = re.compile(r"^(docker|podman)_inspect_(.+)\.txt$", re.IGNORECASE)
_DIFF = re.compile(r"^(docker|podman)_diff_(.+)\.txt$", re.IGNORECASE)
_TOP = re.compile(r"^(docker|podman)_top_(.+)\.txt$", re.IGNORECASE)
_LXC_CONFIG = re.compile(r"^lxc_config_show_(.+)\.txt$", re.IGNORECASE)

# `created` carries no `_utc` suffix on purpose: docker writes RFC 3339 with a
# `Z` and podman writes it with the HOST's offset, so the value states its own
# basis and a suffix claiming one of them would be wrong half the time
# (docs/ARCHITECTURE.md §5).
CONTAINER_HEADER = ["runtime", "container_id", "name", "image", "created", "status",
                    "command", "ports", "network_mode", "mounts", "detail", "suspicious"]
CHANGE_HEADER = ["runtime", "container", "change", "path", "detail", "suspicious"]
# `started` and `elapsed` are two columns because they are two facts: docker's
# `top` reports STIME, a clock time, and podman's reports ELAPSED, a duration.
# One column holding either would be a column nobody can compare across rows.
PROC_HEADER = ["runtime", "container", "uid", "pid", "ppid", "started", "elapsed",
               "command"]


# --------------------------------------------------------------------------- #
# Reading the collected output
# --------------------------------------------------------------------------- #
def _load_json(path: Path):
    """`docker inspect` writes a JSON ARRAY of one element. Returns the first
    object, or None when the command failed and the file holds its error text."""
    text = read_text(path)
    if not text.strip():
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if isinstance(data, list):
        return data[0] if data and isinstance(data[0], dict) else None
    return data if isinstance(data, dict) else None


def _dig(obj, *keys, default=None):
    """`obj[k1][k2]...`, tolerating a missing key or a non-mapping on the way --
    two runtimes and several versions write this JSON and none of them promises
    the same shape twice."""
    cur = obj
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return default if cur is None else cur


def _ports(inspected) -> str:
    """`NetworkSettings.Ports` is {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]}
    and an unpublished port maps to null. Only the published ones are named: an
    exposed-but-unpublished port is not reachable from anywhere."""
    ports = _dig(inspected, "NetworkSettings", "Ports", default={}) or {}
    out = []
    if isinstance(ports, dict):
        for container_port, bindings in sorted(ports.items()):
            for b in bindings or []:
                if not isinstance(b, dict):
                    continue
                host = f"{b.get('HostIp') or '0.0.0.0'}:{b.get('HostPort', '')}"
                out.append(f"{host}->{container_port}")
    return "; ".join(out)


def _mounts(inspected) -> list[tuple[str, str, str, bool]]:
    """(kind, source on the host, destination in the container, writable).

    The KIND is read and not inferred. A named VOLUME's source is a path the
    runtime owns -- `/var/lib/docker/volumes/<name>/_data` -- which sits inside
    one of `_SENSITIVE_BINDS`, so judging it by its path alone flags the ordinary
    way containers persist data and the column stops separating anything.
    """
    out = []
    for m in _dig(inspected, "Mounts", default=[]) or []:
        if not isinstance(m, dict):
            continue
        out.append((str(m.get("Type", "") or ""), str(m.get("Source", "")),
                    str(m.get("Destination", "")), bool(m.get("RW", True))))
    return out


def _as_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str) and value:
        return [value]
    return []


# --------------------------------------------------------------------------- #
# What makes a container worth reading first
# --------------------------------------------------------------------------- #
def _container_flags(inspected, mounts) -> list[str]:
    flags = []
    host = _dig(inspected, "HostConfig", default={}) or {}
    if host.get("Privileged"):
        flags.append("privileged")
    if str(host.get("NetworkMode", "")).lower() == "host":
        flags.append("host_network")
    if str(host.get("PidMode", "")).lower() == "host":
        flags.append("host_pid")
    if str(host.get("IpcMode", "")).lower() == "host":
        flags.append("host_ipc")
    caps = {c.upper().removeprefix("CAP_") for c in _as_list(host.get("CapAdd"))}
    for cap in sorted(caps & _HOT_CAPS):
        flags.append(f"cap_{cap.lower()}")
    for opt in _as_list(host.get("SecurityOpt")):
        if "unconfined" in opt.lower():
            flags.append(opt.lower().replace(" ", "_"))
    for kind, source, _dest, _rw in mounts:
        # `bind` is the one that hands over a host path. An absent Type is read as
        # a bind: older daemons omit it and every mount they report is one.
        if kind not in ("", "bind"):
            continue
        if source == "/":
            flags.append("bind_root")
        elif any(source == s or source.startswith(s + "/") for s in _SENSITIVE_BINDS):
            flags.append(f"bind_{source}")
    return flags


def _change_flags(path: str, kind: str) -> list[str]:
    """A path `docker diff` reported, judged on the path alone -- the content is
    inside the container's layer and was not collected."""
    low = path.lower()
    flags = []
    if any(low.startswith(s) for s in _STAGING):
        flags.append("staging_dir")
    if any(f"/{r}/" in low + "/" or low.startswith(f"/{r}/") for r in _WEBROOTS):
        flags.append("web_root")
        if Path(low).suffix in _SCRIPT_EXTS:
            flags.append("server_side_script")
    if any(low.startswith(p) or p in low for p in _PERSISTENCE):
        flags.append("persistence_path")
    if kind == "D" and low.startswith(("/var/log/", "/etc/")):
        flags.append("deleted_system_path")
    return flags


# --------------------------------------------------------------------------- #
# Per-runtime readers
# --------------------------------------------------------------------------- #
def _oci_containers(cdir: Path, rows: list[list]) -> None:
    for path in sorted(cdir.glob("*_inspect_*.txt")):
        m = _INSPECT.match(path.name)
        if not m:            # network_inspect / volume_inspect: different objects
            continue
        runtime, ident = m.group(1).lower(), m.group(2)
        inspected = _load_json(path)
        if inspected is None:
            # The command ran and produced something that is not JSON: the id no
            # longer existed, or the daemon refused. Said, not dropped -- a
            # container the collector saw and could not describe is itself a fact.
            rows.append([runtime, ident, "", "", "", "unreadable", "", "", "", "",
                         f"{path.name} holds no JSON object", ""])
            continue
        mounts = _mounts(inspected)
        flags = _container_flags(inspected, mounts)
        cmd = " ".join(_as_list(_dig(inspected, "Config", "Entrypoint"))
                       + _as_list(_dig(inspected, "Config", "Cmd")))
        name = str(_dig(inspected, "Name", default="") or "").lstrip("/")
        image = str(_dig(inspected, "Config", "Image", default="")
                    or _dig(inspected, "ImageName", default="")
                    or _dig(inspected, "Image", default=""))
        rows.append([
            runtime,
            str(_dig(inspected, "Id", default=ident))[:12],
            name,
            image,
            str(_dig(inspected, "Created", default="")),
            str(_dig(inspected, "State", "Status", default="")),
            cmd,
            _ports(inspected),
            str(_dig(inspected, "HostConfig", "NetworkMode", default="")),
            "; ".join(f"{s}:{d}{'' if rw else ':ro'}" for _k, s, d, rw in mounts),
            ",".join(flags),
            "yes" if flags else "",
        ])


def _oci_changes(cdir: Path, rows: list[list]) -> None:
    for path in sorted(cdir.glob("*_diff_*.txt")):
        m = _DIFF.match(path.name)
        if not m:
            continue
        runtime, ident = m.group(1).lower(), m.group(2)
        for line in read_lines(path):
            parts = line.split(None, 1)
            # `A /path`, `C /path`, `D /path`. Anything else is the command's own
            # error text, which belongs nowhere near a filesystem-change table.
            if len(parts) != 2 or parts[0] not in ("A", "C", "D"):
                continue
            kind, p = parts[0], parts[1].strip()
            flags = _change_flags(p, kind)
            rows.append([runtime, ident, kind, p, ",".join(flags), "yes" if flags else ""])


def _col(head: list[str], *names: str) -> int:
    """The index of the first column whose header is one of `names`; -1 if the
    table does not have it."""
    return next((i for i, h in enumerate(head) if h in names), -1)


def _oci_procs(cdir: Path, rows: list[list]) -> None:
    for path in sorted(cdir.glob("*_top_*.txt")):
        m = _TOP.match(path.name)
        if not m:
            continue
        runtime, ident = m.group(1).lower(), m.group(2)
        lines = read_lines(path)
        if not lines:
            continue
        # Every column is located BY ITS HEADER, not by position. docker's default
        # descriptors are `UID PID PPID C STIME TTY TIME CMD` and podman's are
        # `USER PID PPID %CPU ELAPSED TTY TIME COMMAND`: same count, and column 4
        # is a clock time in one and a duration in the other.
        head = [h.upper() for h in lines[0].split()]
        cmd_i = next((i for i, h in enumerate(head)
                      if h in ("CMD", "COMMAND", "ARGS")), -1)
        if cmd_i < 1:          # no header: the file holds the command's error text
            continue

        want = tuple(_col(head, *names) for names in
                      (("UID", "USER"), ("PID",), ("PPID",),
                       ("STIME", "START"), ("ELAPSED",)))
        for raw in lines[1:]:
            # The command is the rest of the line and holds spaces, so the split
            # stops where the command starts.
            p = raw.split(None, cmd_i)
            if len(p) <= cmd_i:
                continue
            cells = [p[i] if 0 <= i < cmd_i else "" for i in want]
            rows.append([runtime, ident, *cells, p[cmd_i].strip()])


def _lxc_privileged(cdir: Path, name: str) -> list[str]:
    """What `lxc config show <name>` says about the container's isolation. YAML,
    read line by line: the shapes that matter are flat `key: value` under
    `config:` and a `source:` under a disk device, and a YAML parse would make
    this handler fail on a file lxc wrote in a version this does not know.

    The host path is `source`, NOT `path`. `path` is the mountpoint INSIDE the
    container, so reading it gets the question backwards twice over: a device
    exposing the host's `/etc` at `/mnt/hostetc` says nothing, and the ordinary
    root device every container has (`path: /`, with a storage pool and no
    source at all) says everything.
    """
    flags = []
    for line in read_lines(cdir / f"lxc_config_show_{name}.txt"):
        s = line.strip()
        if s.startswith("security.privileged:") and "true" in s.lower():
            flags.append("privileged")
        elif s.startswith("security.nesting:") and "true" in s.lower():
            flags.append("nesting")
        elif s.startswith("raw.lxc:") and "apparmor" in s.lower():
            flags.append("raw_lxc_apparmor")
        elif s.startswith("source:"):
            host_path = s.split(":", 1)[1].strip()
            if host_path == "/" or any(host_path == b or host_path.startswith(b + "/")
                                       for b in _SENSITIVE_BINDS):
                flags.append(f"bind_{host_path}")
    return flags


def _lxc_containers(cdir: Path, rows: list[list]) -> None:
    """`lxc list --format compact`: a header line, then one container per line.
    The columns are whitespace-separated and the IPv4 cell carries its interface
    in parentheses, so the NAME and the STATE are read by position from the left
    (both are single tokens) and the rest is kept as detail rather than guessed
    into columns that may not be there."""
    lines = [ln for ln in read_lines(cdir / "lxc_list.txt") if ln.strip()]
    if not lines:
        return
    header = lines[0].split()
    if not header or header[0].upper() not in ("NAME", "PROJECT"):
        return
    offset = 1 if header[0].upper() == "PROJECT" else 0
    for raw in lines[1:]:
        toks = raw.split()
        if len(toks) < offset + 2:
            continue
        name, state = toks[offset], toks[offset + 1]
        flags = _lxc_privileged(cdir, name)
        rows.append(["lxc", "", name, "", "", state.lower(), "", "", "", "",
                     ",".join(flags), "yes" if flags else ""])


# --------------------------------------------------------------------------- #
def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    containers: list[list] = []
    changes: list[list] = []
    procs: list[list] = []
    if lr:
        cdir = lr / "containers"
        if cdir.is_dir():
            _oci_containers(cdir, containers)
            _lxc_containers(cdir, containers)
            _oci_changes(cdir, changes)
            _oci_procs(cdir, procs)

    containers.sort(key=lambda r: (r[-1] != "yes", r[0], r[2], r[1]))
    changes.sort(key=lambda r: (r[-1] != "yes", r[0], r[1], r[3]))
    procs.sort(key=lambda r: (r[0], r[1], r[3]))

    write_csv(ctx.out, "containers.csv", CONTAINER_HEADER, containers)
    write_csv(ctx.out, "container_changes.csv", CHANGE_HEADER, changes)
    write_csv(ctx.out, "container_procs.csv", PROC_HEADER, procs)
