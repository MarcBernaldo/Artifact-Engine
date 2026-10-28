"""Handler: what storage this host had, and what of it the acquisition covers.
Output: art_storage.csv

The honesty table (backlog §40). The bodyfile is what UAC walked, and every
filesystem timeline here -- bodyfile, collection artefacts, the atime
method for exfiltration -- reads only that. A network
mount, a second disk, a logical volume left unmounted are not in it, and until
now nothing said so: a quiet timeline read the same as a host with nothing on
its other disks. One row per real filesystem turns that silence into a line.

Sources, all from UAC `live_response/storage`: `mount.txt` (what was mounted,
how), `df.txt` (sizes), `blkid.txt` (filesystems the host HAS, mounted or not).
Kernel pseudo-filesystems (proc, sysfs, cgroup...) are not storage and are left
out; tmpfs is kept, since `/dev/shm` and a tmpfs `/tmp` are where payloads are
staged, and it never reaches the disk image.

`in_bodyfile` is measured, not inferred: one binary pass over the bodyfile looks
for an entry BELOW each mountpoint and stops as soon as every one is found.
`noatime` is said because the atime method for proving reads depends on atime
being updated; `relatime` (the usual default) keeps it valid and is not noted.
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

HEADER = ["device", "mountpoint", "fstype", "kind", "options", "size_kb", "used_kb",
          "in_bodyfile", "note"]

# Kernel interfaces, not storage: nothing on them is evidence a timeline misses.
_PSEUDO = {
    "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "debugfs", "tracefs",
    "securityfs", "pstore", "bpf", "configfs", "fusectl", "hugetlbfs", "autofs",
    "binfmt_misc", "rpc_pipefs", "nsfs", "efivarfs", "devtmpfs", "selinuxfs",
    "fuse.gvfsd-fuse", "fuse.portal",
}
_MEMORY = {"tmpfs", "ramfs"}
_NETWORK = {"nfs", "nfs4", "cifs", "smb3", "smbfs", "sshfs", "fuse.sshfs", "glusterfs",
            "fuse.glusterfs", "ceph", "fuse.ceph", "9p", "davfs", "fuse.davfs2",
            "fuse.s3fs", "fuse.rclone", "fuse.goofys", "afs", "lustre", "beegfs"}
_CONTAINER = {"overlay", "aufs", "shiftfs"}
# blkid types that are not a filesystem one can read files from.
_NOT_A_FILESYSTEM = {"swap", "LVM2_member", "linux_raid_member", "crypto_LUKS",
                     "zfs_member", "ddf_raid_member", "isw_raid_member", "BitLocker"}

# Where container runtimes and the kubelet mount each container's layers,
# secrets and volumes. A k3s node carries hundreds (measured: 576 of 606 rows on
# one): kept as rows -- a pod's NFS volume is real storage -- but not asked of
# the bodyfile, which a container's plumbing was never going to be in.
_RUNTIME_ROOTS = ("/var/lib/kubelet/", "/run/k3s/", "/run/containerd/",
                  "/var/lib/docker/", "/var/lib/containers/", "/run/containers/",
                  "/var/lib/rancher/", "/run/netns/", "/var/snap/lxd/", "/var/lib/lxd/")

_MOUNT = re.compile(r"^(?P<dev>\S+) on (?P<mp>.+?) type (?P<fs>\S+) \((?P<opts>[^)]*)\)\s*$")
_BLKID = re.compile(r'^(?P<dev>[^:\s]+):\s.*?\bTYPE="(?P<fs>[^"]+)"')
_CHUNK = 16 * 1024 * 1024


def _kind(fstype: str) -> str:
    if fstype in _MEMORY:
        return "memory"
    if fstype in _NETWORK or fstype.startswith("nfs"):
        return "network"
    if fstype in _CONTAINER:
        return "container"
    return "disk"


def _unescape(path: str) -> str:
    """`mount` writes a space in a path as \\040 (octal), as /proc/mounts does."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def _mounts(lr: Path) -> list[dict]:
    out = []
    for line in read_lines(lr / "storage" / "mount.txt"):
        m = _MOUNT.match(line.strip())
        if not m:
            continue
        mp, fs = _unescape(m["mp"]), m["fs"]
        if fs in _PSEUDO or mp.startswith(("/proc/", "/sys/")):
            continue
        if fs in _MEMORY and mp.startswith("/run/credentials/"):
            continue        # systemd's per-unit secrets, one tiny tmpfs per service
        out.append({"device": m["dev"], "mountpoint": mp, "fstype": fs,
                    "options": m["opts"]})
    return out


def _df(lr: Path) -> dict[str, tuple[str, str]]:
    """mountpoint -> (size_kb, used_kb) from `df` (1K blocks)."""
    sizes: dict[str, tuple[str, str]] = {}
    for line in read_lines(lr / "storage" / "df.txt")[1:]:
        parts = line.split()
        # Filesystem 1K-blocks Used Available Use% Mounted-on; the mountpoint may
        # hold spaces, so it is everything after the fifth column.
        if len(parts) < 6 or not parts[1].isdigit() or not parts[2].isdigit():
            continue
        mp = line.split(None, 5)[5].strip()
        sizes.setdefault(mp, (parts[1], parts[2]))
    return sizes


def _unmounted(lr: Path, mounted_devices: set[str]) -> list[dict]:
    rows = []
    for line in read_lines(lr / "storage" / "blkid.txt"):
        m = _BLKID.match(line.strip())
        if not m or m["fs"] in _NOT_A_FILESYSTEM or m["dev"] in mounted_devices:
            continue
        rows.append({"device": m["dev"], "mountpoint": "", "fstype": m["fs"], "options": ""})
    return rows


def _in_bodyfile(bodyfile: Path, mountpoints: list[str]) -> dict[str, bool] | None:
    """Which mountpoints have at least one bodyfile entry below them. None when
    there is no bodyfile to ask. One pass, in binary chunks, stopping early."""
    if not bodyfile.is_file():
        return None
    found = {mp: False for mp in mountpoints}
    want = {("/" if mp == "/" else mp.rstrip("/") + "/").encode("utf-8", "surrogateescape"): mp
            for mp in mountpoints}
    # A name is the bodyfile's second field: `md5|name|inode|...`.
    needle = re.compile(b"\\|(" + b"|".join(re.escape(k) for k in
                                           sorted(want, key=len, reverse=True)) + b")")
    keep = max(len(k) for k in want) + 1
    tail = b""
    try:
        with open(bodyfile, "rb") as fh:
            while True:
                block = fh.read(_CHUNK)
                if not block:
                    break
                buf = tail + block
                for m in needle.finditer(buf):
                    found[want[m.group(1)]] = True
                if all(found.values()):
                    break
                tail = buf[-keep:]
    except OSError:
        return None
    return found


def _note(row: dict, covered: bool | None, used_kb: str) -> str:
    notes = []
    if not row["mountpoint"]:
        notes.append("a filesystem on this host that was not mounted: none of it was collected")
    if row["kind"] == "network":
        notes.append("network filesystem: its files live on another host")
    if covered is False and used_kb == "0":
        notes.append("empty when collected (df: 0 used), so nothing is missing from the bodyfile")
    elif covered is False:
        notes.append("NOT in the bodyfile: its files are absent from every filesystem timeline")
    if row["mountpoint"].startswith(_RUNTIME_ROOTS):
        notes.append("a container's mount: see the containers table")
    if "noatime" in row["options"].split(","):
        notes.append("noatime: reads leave no atime here, so atime cannot prove a file was read")
    return "; ".join(notes)


def run(ctx) -> None:
    lr = live_response(Path(ctx.evidence))
    if lr is None or not (lr / "storage" / "mount.txt").is_file():
        return
    mounts = _mounts(lr)
    rows = mounts + _unmounted(lr, {r["device"] for r in mounts})
    for r in rows:
        r["kind"] = _kind(r["fstype"])
    sizes = _df(lr)
    asked = [r["mountpoint"] for r in rows if r["mountpoint"] and r["kind"] != "container"
             and not r["mountpoint"].startswith(_RUNTIME_ROOTS)]
    coverage = _in_bodyfile(Path(ctx.evidence) / "bodyfile" / "bodyfile.txt", asked) \
        if asked else None
    out = []
    for r in rows:
        covered = coverage.get(r["mountpoint"]) if coverage and r["mountpoint"] else None
        size, used = sizes.get(r["mountpoint"], ("", ""))
        out.append([r["device"], r["mountpoint"], r["fstype"], r["kind"], r["options"],
                    size, used, "" if covered is None else ("yes" if covered else "no"),
                    _note(r, covered, used)])
    write_csv(ctx.out, "art_storage.csv", HEADER, out)
