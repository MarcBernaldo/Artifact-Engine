"""Handler: eBPF programs + pinned objects. Output: ebpf.csv

eBPF is a modern rootkit / C2 vector (TripleCross, ebpfkit, Symbiote): code
runs in the kernel without a loadable module, so it does not taint the kernel
or show in lsmod. UAC collects two views:
- bpftool_prog_list.txt : every loaded eBPF program.
- ls -la /sys/fs/bpf    : the bpf filesystem where programs/maps are *pinned*.

What is reliably flaggable here is narrow. Program type and loader uid are not:
on real hosts systemd loads cgroup_skb/cgroup_sock_addr/sched_cls and EDR
sensors (Defender, Sophos) load hundreds of kprobes -- Sophos even as a
non-root uid. So programs are emitted only as a grouped inventory (by
type/uid/loader) for the analyst to eyeball, never auto-flagged.

A *pinned* object in /sys/fs/bpf is different: pinning makes a program/map
survive the process that loaded it, which is exactly how an eBPF implant
persists. Any pin (anything beyond . and ..) is flagged.

Self-gating: hosts where UAC collected no eBPF data are skipped.
"""

from __future__ import annotations

import re
from collections import Counter

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

# First line of a program record: "<id>: <type>  name <name>  tag <tag> ...".
_PROG = re.compile(r"^(\d+):\s+(\S+)")
_UID = re.compile(r"\buid\s+(\d+)")
_PIDS = re.compile(r"\bpids\s+(\S+?)\(\d+\)")   # first "proc(pid)" -> proc


def _programs(lines: list[str], rows: list[list]) -> None:
    # Records are delimited by a "<id>:" line; the following indented lines
    # (uid, pids, ...) belong to it. Collapse into counts by (type, uid,
    # loader) so an EDR's hundreds of probes become a handful of rows.
    groups: Counter = Counter()
    cur: list | None = None  # [type, uid, loader]
    for ln in lines:
        m = _PROG.match(ln)
        if m:
            if cur:
                groups[tuple(cur)] += 1
            cur = [m.group(2), "", ""]
            continue
        if cur is None:
            continue
        u = _UID.search(ln)
        if u:
            cur[1] = u.group(1)
        p = _PIDS.search(ln)
        if p:
            cur[2] = p.group(1)
    if cur:
        groups[tuple(cur)] += 1

    for (ptype, uid, loader), n in groups.items():
        detail = f"count={n}"
        if uid:
            detail += f" uid={uid}"
        if loader:
            detail += f" loaded_by={loader}"
        rows.append(["prog", ptype, detail, ""])


def _pins(lines: list[str], rows: list[list]) -> None:
    for ln in lines:
        s = ln.rstrip()
        if not s or s.startswith("total"):
            continue
        parts = s.split(None, 8)
        if len(parts) < 9:                       # not an "ls -la" entry line
            continue
        name = parts[8]
        if name in (".", ".."):
            continue
        rows.append(["pin", name, "pinned object under /sys/fs/bpf (persists without loader)", "yes"])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    sysd = (lr / "system") if lr else None
    prog_f = sysd / "bpftool_prog_list.txt" if sysd else None
    pin_f = sysd / "ls_-la_sys_fs_bpf.txt" if sysd else None
    if not sysd or not ((prog_f and prog_f.exists()) or (pin_f and pin_f.exists())):
        raise HandlerSkip("no eBPF data collected")

    rows: list[list] = []
    _pins(read_lines(pin_f), rows)
    _programs(read_lines(prog_f), rows)
    # Flagged pins first, then the program inventory by type.
    rows.sort(key=lambda r: (r[3] != "yes", r[0], r[1]))
    write_csv(ctx.out, "ebpf.csv", ["kind", "name", "detail", "suspicious"], rows)
