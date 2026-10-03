"""Handler: virtual machines declared on this host. Output: vms.csv

The weaker half of the container work, and deliberately so: a VM inventory is
CONTEXT, not activity. Knowing a hypervisor host runs eleven guests does not say
anything happened on any of them -- but it is what tells the analyst that eleven
machines exist which this acquisition does not cover, which is the difference
between "the host is clean" and "the host is clean and here is what was not
looked at". Nothing here is flagged, for the same reason: there is no claim to
make.

UAC's `full` profile collects `live_response/vms/*` from whichever hypervisor
CLI the host has. Each writes a human table of its own, so each gets its own
small reader and anything that does not match is skipped rather than guessed --
a row invented out of a misread column would be a machine that does not exist.

`virsh dominfo`, `qm config`, `VBoxManage showvminfo` and the vim-cmd summaries
are collected per guest and are NOT read here: they describe a guest's hardware,
which is a different question from which guests exist. The disk paths are the
exception, since those name the files an analyst would ask for next.
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.handlers._lincommon import live_response, read_lines, read_text, write_csv

HEADER = ["hypervisor", "vm", "state", "id", "disks", "detail"]

_UUID_LINE = re.compile(r'^"(?P<name>.+)"\s+\{(?P<uuid>[0-9a-fA-F-]+)\}\s*$')


def _virsh(vdir: Path, rows: list[list]) -> None:
    """`virsh list --all`:

        Id   Name    State
       ---------------------
        1    web01   running
        -    db01    shut off

    The state holds a space ("shut off"), so it is everything after the name
    rather than the third token."""
    seen = False
    for raw in read_lines(vdir / "virsh_list_--all.txt"):
        s = raw.strip()
        if not s:
            continue
        if set(s) <= set("- "):
            seen = True
            continue
        if not seen:                 # the header, before the rule line
            continue
        parts = s.split(None, 2)
        if len(parts) < 2:
            continue
        vm_id, name = parts[0], parts[1]
        state = parts[2].strip() if len(parts) > 2 else ""
        # No disks: `virsh dominfo` does not carry them and the domain XML, which
        # would, is not collected. An empty cell is readable; an invented path
        # would send an analyst looking for a file that does not exist.
        rows.append(["libvirt", name, state, "" if vm_id == "-" else vm_id, "", ""])


def _qm(vdir: Path, rows: list[list]) -> None:
    """Proxmox `qm list`:

        VMID NAME    STATUS   MEM(MB)  BOOTDISK(GB)  PID
         100 web01   running  2048     32.00         1234
    """
    for raw in read_lines(vdir / "qm_list.txt"):
        toks = raw.split()
        if len(toks) < 3 or not toks[0].isdigit():
            continue
        vmid, name, status = toks[0], toks[1], toks[2]
        rows.append(["proxmox", name, status, vmid, _qm_disks(vdir, vmid),
                     f"pid={toks[5]}" if len(toks) > 5 and toks[5].isdigit() else ""])


def _qm_disks(vdir: Path, vmid: str) -> str:
    """`qm config <vmid> --current` is flat `key: value`; the disks are the keys
    that name a bus (`scsi0:`, `virtio1:`, `ide2:`, `sata0:`) and their value
    starts with the storage the volume lives on."""
    disks = []
    for raw in read_lines(vdir / f"qm_config_{vmid}_--current.txt"):
        key, _, value = raw.partition(":")
        if re.fullmatch(r"(scsi|virtio|ide|sata|efidisk|tpmstate)\d+", key.strip()):
            disks.append(value.strip().split(",")[0])
    return "; ".join(disks)


def _vbox(vdir: Path, rows: list[list]) -> None:
    """`VBoxManage list vms` and `list runningvms` both write `"name" {uuid}`;
    the second is the subset that is up, which is the only state VirtualBox
    reports here."""
    running = set()
    for raw in read_lines(vdir / "VBoxManage_list_runningvms.txt"):
        m = _UUID_LINE.match(raw.strip())
        if m:
            running.add(m.group("uuid"))
    for raw in read_lines(vdir / "VBoxManage_list_vms.txt"):
        m = _UUID_LINE.match(raw.strip())
        if not m:
            continue
        uuid = m.group("uuid")
        rows.append(["virtualbox", m.group("name"),
                     "running" if uuid in running else "stopped", uuid,
                     _vbox_disks(vdir, uuid), ""])


def _vbox_disks(vdir: Path, uuid: str) -> str:
    """`VBoxManage showvminfo <uuid>` writes the attachments as
    `SATA (0, 0): /path/disk.vdi (UUID: ...)`."""
    disks = []
    for raw in read_lines(vdir / f"VBoxManage_showvminfo_{uuid}.txt"):
        m = re.match(r"^\S[^:]*\(\d+,\s*\d+\):\s*(?P<path>.+?)\s*\(UUID:", raw)
        if m:
            disks.append(m.group("path"))
    return "; ".join(disks)


def _vimcmd(vdir: Path, rows: list[list]) -> None:
    """ESXi `vim-cmd vmsvc/getallvms`:

        Vmid   Name    File                          Guest OS       Version
        1      web01   [datastore1] web01/web01.vmx  ubuntu64Guest  vmx-14

    The File column holds spaces and brackets, so the row is anchored on the
    `.vmx` instead of split by column: everything from `[` to the first `.vmx`
    is the file, and the name is what sits between the vmid and it. The PATH may
    hold spaces too -- an ESXi folder is named after the guest -- so the anchor
    must not stop at one, or the guest disappears from the inventory whose whole
    purpose is naming the machines this acquisition does not cover."""
    for raw in read_lines(vdir / "vim-cmd_vmsvc_getallvms.txt"):
        s = raw.rstrip()
        toks = s.split()
        if len(toks) < 3 or not toks[0].isdigit():
            continue
        m = re.search(r"(\[[^\]]*\].*?\.vmx)", s)
        if not m:
            continue
        name = s[len(toks[0]):m.start()].strip()
        rest = s[m.end():].split()
        rows.append(["esxi", name, _esxi_state(vdir, toks[0]), toks[0],
                     m.group(1).strip(), " ".join(rest[:2])])


def _esxi_state(vdir: Path, vmid: str) -> str:
    """`vim-cmd vmsvc/get.summary <vmid>` carries `powerState = "poweredOn"`
    inside the runtime block."""
    m = re.search(r'powerState\s*=\s*"?(\w+)"?',
                  read_text(vdir / f"vim-cmd_vmsvc_get.summary_{vmid}.txt"))
    return m.group(1) if m else ""


def _esxcli(vdir: Path, rows: list[list]) -> None:
    """`esxcli vm process list` is a block per running VM: the first line is the
    display name and the indented lines are `Key: value`. Only the VMs that are
    RUNNING appear, which is what it is -- the inventory above covers the rest."""
    name, fields = "", {}
    blocks = []
    for raw in read_lines(vdir / "esxcli_vm_process_list.txt"):
        if not raw.strip():
            continue
        if raw[0].isspace():
            key, _, value = raw.strip().partition(":")
            fields[key.strip()] = value.strip()
        else:
            if name:
                blocks.append((name, fields))
            name, fields = raw.strip(), {}
    if name:
        blocks.append((name, fields))
    for vm_name, f in blocks:
        rows.append(["esxi", f.get("Display Name", vm_name), "running",
                     f.get("World ID", ""), f.get("Config File", ""), ""])


def _vmctl(vdir: Path, rows: list[list]) -> None:
    """OpenBSD `vmctl status`:

        ID  PID VCPUS MAXMEM CURMEM TTY        OWNER  STATE  NAME
         1 1234     1   1.0G   256M /dev/ttyp0 root   running web01
    """
    lines = read_lines(vdir / "vmctl_status.txt")
    if not lines or "NAME" not in lines[0].upper():
        return
    for raw in lines[1:]:
        toks = raw.split()
        if len(toks) < 9:
            continue
        rows.append(["vmm", toks[-1], toks[-2], toks[0], "", f"owner={toks[-3]}"])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    rows: list[list] = []
    if lr and (lr / "vms").is_dir():
        vdir = lr / "vms"
        for reader in (_virsh, _qm, _vbox, _vimcmd, _esxcli, _vmctl):
            reader(vdir, rows)
    # `esxcli` and `vim-cmd` describe the same ESXi guests from two angles; a VM
    # named by both is one machine, and the richer row (the one with a config
    # file) is the one kept.
    best: dict[tuple[str, str], list] = {}
    for r in rows:
        key = (r[0], r[1])
        if key not in best or (len(r[4]) > len(best[key][4])):
            best[key] = r
    out = sorted(best.values(), key=lambda r: (r[0], r[1].lower()))
    write_csv(ctx.out, "vms.csv", HEADER, out)
