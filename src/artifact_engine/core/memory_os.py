"""Which kernel a memory image holds, decided once when its unit is staged (v0.7.113).

A memory unit is detected by its pointer (`memory.image`, see `core/memory.py`),
and until this version every unit was a Windows one: a Linux image ran the 44
Windows plugins and reported one `art_mem_info` error, "no Windows kernel". The
profile has to be chosen before phase 3, so the image itself is asked first,
the way Volatility's own automagic asks it -- by the names a kernel leaves in
memory:

  - a Windows kernel's PDB name (`ntkrnlmp.pdb`, ... -- Volatility's
    `KERNEL_MODULE_NAMES`): its debug record is in every running Windows kernel;
  - a Linux banner, `Linux version X.Y.Z (builder) (compiler) #...`, the string
    `/proc/version` prints and Volatility matches its symbol tables against.

A banner and no Windows kernel name is Linux; a Windows name and no banner is
Windows; neither leaves the unit as it was before (the Windows profile, whose
`art_mem_info` then says what it found). BOTH is the hard case, and it is not rare
in either direction: a Windows host running WSL2, Docker Desktop or a Linux VM
holds a Linux banner, and a Linux hypervisor with Windows guests, or a server
holding Windows files in its page cache, holds a Windows kernel's name. Nothing
this cheap tells the two apart, so it goes Windows -- the commoner of the two
on an analyst's desk -- with a WARNING naming both and saying how to overrule it.
The whole image is read for that (about 10 s for 4 GB), once.

The answer is a file in the unit folder: `memory.linux` (holding the banner) or
`memory.windows` (holding the kernel name), written once and never re-scanned
-- and an analyst who knows better renames one into the other. `memory.linux`
is what `profiles/linux_memory.yaml` detects.

A module of its own, not part of `core/memory.py`: that one is imported by the
Windows memory handlers, and editing it would re-fingerprint all of their
parsers and re-run them on every memory case already analysed.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

from artifact_engine.core.memory import COLLECTOR, image_of
from artifact_engine.logging_setup import get_logger

log = get_logger()

LINUX = "memory.linux"
WINDOWS = "memory.windows"

# Volatility's `constants.windows.KERNEL_MODULE_NAMES`, stated here so staging
# does not import Volatility.
_PDB = tuple(f"{n}.pdb".encode() for n in ("ntkrnlmp", "ntkrnlpa", "ntkrpamp", "ntoskrnl"))
_BANNER = re.compile(rb"Linux version [0-9]+\.[0-9]+\.[0-9]+[^\x00\n\r]{0,400}")
_PREFIX = b"Linux version "
CHUNK = 64 * 1024 * 1024
_OVERLAP = 512


def scan(image: Path) -> tuple[str, str]:
    """(the first Windows kernel name found, the most frequent Linux banner);
    either is "" when the image holds none."""
    banners: Counter[bytes] = Counter()
    windows = ""
    with open(image, "rb") as fh:
        carry = b""
        while True:
            block = fh.read(CHUNK)
            data = carry + block
            if not data:
                break
            if not windows:
                windows = next((n.decode() for n in _PDB if n in data), "")
            # A banner is counted where it STARTS: before the last _OVERLAP bytes,
            # which are carried into the next round (a banner is shorter than
            # that, so it is always whole where it is counted).
            limit = len(data) - _OVERLAP if block else len(data)
            i = data.find(_PREFIX)
            while 0 <= i < limit:
                m = _BANNER.match(data, i)
                if m:
                    banners[m.group(0)] += 1
                i = data.find(_PREFIX, i + 1)
            if not block:
                break
            carry = data[max(limit, 0):]
    banner = banners.most_common(1)[0][0].decode("utf-8", "replace").strip() if banners else ""
    return windows, banner


def classify(unit: Path) -> str:
    """The unit's kernel: "linux", "windows" or "" (unknown), scanning the image
    the first time and recording the answer in the unit folder."""
    unit = Path(unit)
    if (unit / LINUX).is_file():
        return "linux"
    if (unit / WINDOWS).is_file():
        return "windows"
    image = image_of(unit)
    if image is None or not image.is_file():
        return ""
    try:
        windows, linux = scan(image)
    except OSError as e:
        log.warning(f"[!] memory image {image.name}: could not be read to tell its "
                    f"kernel ({e}); analysed as Windows")
        return ""
    if not windows and not linux:
        log.info(f"[=] memory image {image.name}: no Windows kernel name and no Linux "
                 f"banner found; analysed as Windows")
        return ""
    kind, what = ("windows", windows) if windows else ("linux", linux)
    if windows and linux:
        log.warning(f"[!] memory image {image.name} holds a Windows kernel name "
                    f"({windows}) AND a Linux banner ({linux[:60]}): analysed as "
                    f"Windows -- a Windows host running WSL2 or a Linux VM. If it is a "
                    f"Linux host (a hypervisor with Windows guests, a server holding "
                    f"Windows files), rename {WINDOWS} to {LINUX} in {unit.name} and "
                    f"run again")
    try:
        (unit / (LINUX if kind == "linux" else WINDOWS)).write_text(what + "\n",
                                                                    encoding="utf-8")
    except OSError as e:
        log.warning(f"[!] memory unit {unit.name}: cannot record its kernel: {e}")
    log.info(f"[+] memory image {image.name}: a {kind.capitalize()} kernel ({what[:60]})")
    return kind


def check_profiles(machines) -> None:
    """Say so when a unit recorded as Linux was taken by another profile -- an
    overriding `windows_memory.yaml` in a profile folder searched before the
    built-in one (an older copy matches the pointer alone) would otherwise run
    the Windows plugins over it in silence."""
    for m in machines:
        if m.collector == COLLECTOR and m.os != "linux" and (m.path / LINUX).is_file():
            log.warning(f"[!] memory unit {m.path.name} holds a Linux kernel but was "
                        f"detected by profile {m.profile_id} ({m.os}) -- a profile file "
                        f"overriding the built-in ones? Its Linux plugins do not run")


def classify_units(units: list[Path]) -> None:
    for unit in units:
        classify(unit)


def banner(unit: Path) -> str:
    try:
        return (Path(unit) / LINUX).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


# Rows of the environment table read to name a unit.
_ENV_SAMPLE = 50_000
# `SESSION_MANAGER=local/<host>:@/tmp/.ICE-unix/<pid>` -- set in every process of
# a desktop session. NOT `HOSTNAME`: bash keeps it as a shell variable and rarely
# exports it, and the processes that do carry it are mostly containers' -- Docker
# and Kubernetes set it to the container id or pod name in each one, so on a
# container node it would name the host after a container (found by review).
_SESSION = re.compile(r"^(?:local|unix)/([^:/]+):")
# Not a host: GNOME on RHEL/CentOS 7 writes `local/unix:@/tmp/.ICE-unix/<pid>`
# in every process of the session (v0.7.114: a unit was named "unix").
_NOT_A_HOST = {"unix", "localhost", "localhost.localdomain"}


def name_linux_units(machines) -> list:
    """Rename each Linux memory unit after the host in its desktop session's
    SESSION_MANAGER. Returns the renamed; a unit with none (a server) keeps its
    image's name."""
    renamed = []
    for m in machines:
        if m.collector != COLLECTOR or m.os != "linux":
            continue
        session: Counter[str] = Counter()
        for p in sorted((m.path / "CSVs").rglob("art_linmem_envars.csv")):
            try:
                with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                    for i, row in enumerate(csv.DictReader(fh)):
                        if i >= _ENV_SAMPLE:
                            break
                        key = (row.get("KEY") or "").upper()
                        value = (row.get("VALUE") or "").strip()
                        if key == "SESSION_MANAGER":
                            hit = _SESSION.match(value)
                            if hit and hit.group(1).lower() not in _NOT_A_HOST:
                                session[hit.group(1)] += 1
            except (OSError, csv.Error) as e:
                log.debug(f"name_linux_units: {p.name}: {e}")
        if session:
            host = session.most_common(1)[0][0]
            if host != m.name:
                log.info(f"[+] memory unit {m.name}: its processes name host {host} -- "
                         f"naming the machine after it")
                m.name = host
                renamed.append(m)
    return renamed
