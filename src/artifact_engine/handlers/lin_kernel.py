"""Handler: loaded kernel modules + kernel taint state. Output: art_kernel_modules.csv

From UAC live_response/system: lsmod.txt (the modules loaded at acquisition
time) and cat_proc_sys_kernel_tainted.txt (the kernel taint bitmask). Together
these are the main triage signal for a loadable-kernel-module rootkit: an
unsigned / force-loaded / force-unloaded module taints the kernel, and the
module list is the inventory to review (a stealth rootkit hides from lsmod, but
its side effects -- the taint bits -- remain).

Also checks core_pattern: a crash handler piped to a non-standard program
(not systemd-coredump/apport/abrt) is a code-exec-on-crash backdoor.

Output rows of kinds (`kind` column): one per loaded `module`, one per set
`taint` flag (plus the raw value) and one `core_pattern`. It does not assert
maliciousness.

THE RAW VALUE SAYS WHICH BITS IT IS (v0.7.170). It was flagged whenever it was
not zero, so a SUSE kernel's "externally supported" bit -- set on every such
host -- was a finding. Now it is flagged when a bit about a loaded MODULE is set
(`_MODULE_BITS`): the rootkit ones, and the proprietary / out-of-tree ones that
are not flagged on their own row because NVIDIA and DKMS set them, but which on a
kernel without module signing are the only trace an LKM leaves. Hardware, oops
and distribution bits alone do not flag it. Bits past the kernel.org list (19
and up; SUSE and RHEL define some) are named `distro_bit_<n>` and listed.
"""

from __future__ import annotations

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

# Kernel taint bit -> (name, suspicious). Only the bits that point at a
# rogue/loadable-module rootkit are flagged; proprietary/livepatch/out-of-tree
# are common on legitimate systems (NVIDIA, kGraft, DKMS) so they are listed
# but not flagged.
_TAINT = {
    0: ("proprietary_module", ""),
    1: ("forced_module_load", "yes"),
    2: ("smp_unsafe", ""),
    3: ("forced_module_unload", "yes"),
    4: ("machine_check", ""),
    5: ("bad_page", ""),
    6: ("user_tainted", ""),
    7: ("oops_or_warning", ""),
    8: ("acpi_override", ""),
    9: ("warning", ""),
    10: ("staging_driver", ""),
    11: ("firmware_workaround", ""),
    12: ("out_of_tree_module", ""),
    13: ("unsigned_module", "yes"),
    14: ("soft_lockup", ""),
    15: ("live_patch", ""),
    16: ("aux_tainted", ""),
    17: ("struct_randomization", ""),
    18: ("in_kernel_test", ""),
}


# The bits a loaded module sets: any of them keeps the raw value flagged.
_MODULE_BITS = {0, 1, 3, 12, 13}


def _modules(lines: list[str], rows: list[list]) -> None:
    for ln in lines:
        if not ln.strip() or ln.startswith("Module"):   # header
            continue
        p = ln.split()
        if len(p) < 3:
            continue
        name, size, used = p[0], p[1], p[2]
        used_by = " ".join(p[3:])
        detail = f"size={size} used_by_count={used}" + (f" used_by={used_by}" if used_by else "")
        rows.append(["module", name, detail, ""])


# Standard core-dump handlers piped via core_pattern. Anything else after the
# '|' (e.g. |/tmp/x) means crashes are routed to an attacker program.
_COREDUMP_OK = {"systemd-coredump", "apport", "abrt-hook-ccpp", "abrt"}


def _core_pattern(lines: list[str], rows: list[list]) -> None:
    val = next((s.strip() for s in lines if s.strip()), "")
    if not val:
        return
    susp = ""
    if val.startswith("|"):
        prog = val[1:].strip().split()[0] if val[1:].strip() else ""
        base = prog.rsplit("/", 1)[-1]
        susp = "" if base in _COREDUMP_OK else "yes"
    rows.append(["core_pattern", "core_pattern", val, susp])


def _taint(lines: list[str], rows: list[list]) -> None:
    raw = next((s.strip() for s in lines if s.strip().lstrip("-").isdigit()), "")
    if raw == "":
        return
    value = int(raw) & (2**64 - 1)          # a negative read is the same bits
    names: list[str] = []
    loud = False
    for bit in range(value.bit_length()):
        if not value & (1 << bit):
            continue
        if bit in _TAINT:
            name, susp = _TAINT[bit]
            detail = f"bit {bit}"
        else:
            name, susp = f"distro_bit_{bit}", ""
            detail = f"bit {bit}: not a kernel.org flag, defined by the distribution"
        rows.append(["taint", name, detail, susp])
        names.append(name)
        loud = loud or bit in _MODULE_BITS
    rows.append(["taint", "taint_value",
                 f"{value} = {' + '.join(names)}" if names else str(value),
                 "yes" if loud else ""])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    rows: list[list] = []
    if lr:
        sysd = lr / "system"
        _taint(read_lines(sysd / "cat_proc_sys_kernel_tainted.txt"), rows)
        _core_pattern(read_lines(sysd / "core_pattern.txt"), rows)
        _modules(read_lines(sysd / "lsmod.txt"), rows)
    # Flagged first, then taint/core_pattern, then modules.
    rows.sort(key=lambda r: (r[3] != "yes", r[0] == "module", r[0], r[1]))
    write_csv(ctx.out, "art_kernel_modules.csv", ["kind", "name", "detail", "suspicious"], rows)
