"""Handlers: Volatility 3 over a LINUX memory image, one plugin per parser (v0.7.113).

The Linux counterpart of `mem_volatility` (read that module's docstring first: the
UTF-8 child, the scratch file renamed into place only on exit 0, the CSV
un-escaping and the plugin-per-parser layout are the same, and its helpers are
used here as they are). What differs is where the kernel's symbols come from.

Volatility reads a Windows kernel with symbols it downloads from Microsoft by
the PDB's GUID. A Linux kernel has no such server: it needs an ISF built from
that exact kernel's debug package (`dwarf2json`), which an analyst rarely has.
So every plugin is run with `--remote-isf-url` pointing at a public index of
prebuilt ISFs (Ubuntu, Debian, Kali, AlmaLinux, Rocky -- `REMOTE_ISF`), which
Volatility matches against the image's banner, downloads once and caches. It
says which kernel the image holds to that host, as the Windows download says
which build to Microsoft's; the ISFs are never shipped with the engine. An ISF
the analyst put in Volatility's own `symbols/linux` folder is found first.

`linmem_info` runs first, alone (every other parser depends on it), for the same
reason `mem_info` does: the first plugin over the image fetches the symbols, and
thirty plugins doing it at once would fetch the same file thirty times. It runs
`linux.boottime` -- a small plugin that needs the kernel's symbols to answer --
and adds the banner, the Volatility version and the image. When it fails, every
other parser skips naming it, and its error says what is missing: usually the
symbols for this kernel.

Left out after a run over a real image: `linux.sockscan` and `linux.kmsg` raise
inside Volatility 2.28 on a 6.5 kernel (the first after 765 rows), and
`linux.library_list` repeats `linux.elfs` at several times the cost.
"""

from __future__ import annotations

import csv
import os
import re
import subprocess
from pathlib import Path

from artifact_engine.core.memory import image_of
from artifact_engine.core.runner import HandlerSkip, marker_path
from artifact_engine.handlers.mem_volatility import (
    _last_line,
    _run_to_file,
    _unescape,
    vol_command,
    vol_version,
)

REMOTE_ISF = ("https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/"
              "banners/banners.json")
_TIMEOUT = 3600
_INFO = "linmem_info"
_NO_KERNEL = "Unable to validate the plugin requirements"
_BANNER_FILE = "memory.linux"     # core/memory_os.LINUX, read without importing it

# When a plugin raises, Volatility prints "Volatility encountered an unexpected
# situation" and keeps the exception's own words for -vvv, which also prints
# megabytes of debug lines. This launcher writes that one line to stderr first,
# marked, so a plugin that does not support this kernel can say so (v0.7.114).
_REASON = "AENG-VOLATILITY-REASON: "
_LAUNCH = ("import sys; sys.argv[0] = 'vol'\n"
           "from volatility3 import cli\n"
           "_said = cli.CommandLine.process_exceptions\n"
           "def _say(self, excp):\n"
           f"    sys.stderr.write('\\n{_REASON}' + type(excp).__name__ + ': ' + str(excp) + '\\n')\n"
           "    sys.stderr.flush()\n"
           "    return _said(self, excp)\n"
           "cli.CommandLine.process_exceptions = _say\n"
           "sys.exit(cli.main())\n")
# What Volatility's Linux plugins raise when this kernel lacks what they read,
# measured on Debian 7 / Debian 10 kernels: kthreads ("only works with kernels
# >= 5.8"), capabilities ("Unsupported kernel capabilities implementation"),
# ebpf ("Cannot find the eBPF prog idr. Unsupported kernel").
_UNSUPPORTED = re.compile(r"unsupported|only works with kernels?|not supported",
                          re.IGNORECASE)


def _command() -> list[str] | None:
    """`vol_command()`, with the launcher above when Volatility is a module of
    this interpreter (a standalone `vol` is run as it is)."""
    cmd = vol_command()
    if cmd and len(cmd) == 3 and cmd[1] == "-c":
        return [cmd[0], "-c", _LAUNCH]
    return cmd


def _reason(err: str) -> str:
    lines = [ln[len(_REASON):].strip() for ln in err.splitlines() if ln.startswith(_REASON)]
    return lines[-1][:300] if lines else ""


def kernel_found(unit: Path) -> bool:
    """Whether `linmem_info` succeeded on this unit (its `.done` marker)."""
    return marker_path(unit / "CSVs" / "Memory", _INFO).is_file()


def _banner(unit: Path) -> str:
    try:
        return (unit / _BANNER_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def run_plugin(ctx, plugin: str, table: str, timeout: int = _TIMEOUT) -> Path | None:
    """`mem_volatility.run_plugin` for a Linux image: the same steps, with the
    remote symbol index, and the Linux answer when no kernel can be read."""
    unit = Path(ctx.evidence)
    image = image_of(unit)
    if image is None:
        raise HandlerSkip("not a memory unit (no memory.image pointer)")
    if not image.is_file():
        raise HandlerSkip(f"memory image {image.name} is not where the unit says")
    cmd = _command()
    if cmd is None:
        raise HandlerSkip("Volatility 3 is not installed "
                          "(pip install volatility3, or put `vol` on PATH)")
    if table != _INFO and not kernel_found(unit):
        raise HandlerSkip(f"{_INFO} did not succeed on this image, so no plugin can read "
                          f"it -- its error says why")
    out = Path(ctx.out)
    out.mkdir(parents=True, exist_ok=True)
    final = out / f"{table}.csv"
    part = out / f".{table}.csv.part"
    try:
        rc, err = _run_to_file([*cmd, "-q", "-r", "csv", "--remote-isf-url", REMOTE_ISF,
                                "-f", str(image), plugin], part, timeout)
    except subprocess.TimeoutExpired:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"volatility {plugin}: no answer after {timeout}s") from None
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    if rc != 0:
        part.unlink(missing_ok=True)
        if _NO_KERNEL in err:
            if table != _INFO:
                # linmem_info read this kernel, so it is this plugin that does not
                # apply to it (a structure this kernel version does not have).
                raise HandlerSkip(f"{plugin} cannot run on this kernel "
                                  f"({_NO_KERNEL.lower()})")
            raise RuntimeError(
                f"volatility {plugin}: no symbols for this Linux kernel "
                f"({_banner(unit)[:120] or 'banner unknown'}) -- it is not in the "
                f"public index, or this host is offline. Build its ISF with dwarf2json "
                f"from the kernel's debug package and put it in Volatility's "
                f"symbols/linux folder")
        why = _reason(err)
        if why and table != _INFO and _UNSUPPORTED.search(why):
            raise HandlerSkip(f"{plugin} does not support this kernel: {why}")
        raise RuntimeError(f"volatility {plugin} exited {rc}: {why or _last_line(err)}")
    clean = out / f".{table}.csv.clean"
    try:
        rows = _unescape(part, clean)
    except BaseException:
        clean.unlink(missing_ok=True)
        raise
    finally:
        part.unlink(missing_ok=True)
    if not rows:
        clean.unlink(missing_ok=True)
        return None
    os.replace(clean, final)
    if ctx.log:
        ctx.log.debug(f"memory: {plugin} -> {final.name}")
    return final


def _plugin(plugin: str, table: str):
    def run(ctx) -> None:
        run_plugin(ctx, plugin, table)
    run.__doc__ = f"Volatility 3 `{plugin}` -> {table}.csv"
    return run


def info(ctx) -> None:
    """`linux.boottime`, plus the kernel banner, the Volatility version, the
    image's name and its size."""
    path = run_plugin(ctx, "linux.boottime.Boottime", _INFO)
    if path is None:
        raise RuntimeError("linux.boottime read the kernel and returned nothing")
    unit = Path(ctx.evidence)
    image = image_of(unit)
    with path.open("a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([0, "Kernel banner", _banner(unit)])
        w.writerow([0, "Volatility 3", vol_version() or "(standalone vol)"])
        w.writerow([0, "Image file", image.name])
        w.writerow([0, "Image size (bytes)", image.stat().st_size])


# --- processes ------------------------------------------------------------------
pslist = _plugin("linux.pslist.PsList", "linmem_pslist")
psscan = _plugin("linux.psscan.PsScan", "linmem_psscan")
pstree = _plugin("linux.pstree.PsTree", "linmem_pstree")
psaux = _plugin("linux.psaux.PsAux", "linmem_psaux")
pidhashtable = _plugin("linux.pidhashtable.PIDHashTable", "linmem_pidhashtable")
envars = _plugin("linux.envars.Envars", "linmem_envars")
bash = _plugin("linux.bash.Bash", "linmem_bash")
capabilities = _plugin("linux.capabilities.Capabilities", "linmem_capabilities")
ptrace = _plugin("linux.ptrace.Ptrace", "linmem_ptrace")
lsof = _plugin("linux.lsof.Lsof", "linmem_lsof")
elfs = _plugin("linux.elfs.Elfs", "linmem_elfs")
kthreads = _plugin("linux.kthreads.Kthreads", "linmem_kthreads")
# --- network --------------------------------------------------------------------
sockstat = _plugin("linux.sockstat.Sockstat", "linmem_sockstat")
ip_addr = _plugin("linux.ip.Addr", "linmem_ip_addr")
ip_link = _plugin("linux.ip.Link", "linmem_ip_link")
netfilter = _plugin("linux.malware.netfilter.Netfilter", "linmem_netfilter")
# --- kernel, modules and hooks --------------------------------------------------
lsmod = _plugin("linux.lsmod.Lsmod", "linmem_lsmod")
modxview = _plugin("linux.malware.modxview.Modxview", "linmem_modxview")
mountinfo = _plugin("linux.mountinfo.MountInfo", "linmem_mountinfo")
ebpf = _plugin("linux.ebpf.EBPF", "linmem_ebpf")
check_syscall = _plugin("linux.malware.check_syscall.Check_syscall", "linmem_check_syscall")
check_idt = _plugin("linux.malware.check_idt.Check_idt", "linmem_check_idt")
check_afinfo = _plugin("linux.malware.check_afinfo.Check_afinfo", "linmem_check_afinfo")
check_creds = _plugin("linux.malware.check_creds.Check_creds", "linmem_check_creds")
keyboard_notifiers = _plugin("linux.malware.keyboard_notifiers.Keyboard_notifiers",
                             "linmem_keyboard_notifiers")
tty_check = _plugin("linux.malware.tty_check.Tty_Check", "linmem_tty_check")
ftrace = _plugin("linux.tracing.ftrace.CheckFtrace", "linmem_ftrace")
tracepoints = _plugin("linux.tracing.tracepoints.CheckTracepoints", "linmem_tracepoints")
# --- code that should not be there ----------------------------------------------
malfind = _plugin("linux.malware.malfind.Malfind", "linmem_malfind")
process_spoofing = _plugin("linux.malware.process_spoofing.ProcessSpoofing",
                           "linmem_process_spoofing")
# --- files still in memory ------------------------------------------------------
pagecache = _plugin("linux.pagecache.Files", "linmem_pagecache")
