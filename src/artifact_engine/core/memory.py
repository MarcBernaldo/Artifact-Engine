"""Memory images: find each one and give it a unit of its own (v0.7.88).

Every other kind of evidence the engine reads is a DIRECTORY -- an extracted
acquisition, a drop folder -- and a machine is a directory its outputs are written
into. A memory image is one file, usually lying at the case root beside other
evidence, so it cannot be the machine: its CSVs and its `.db` would land in the
case root next to every other unit's.

So each image gets a sibling folder, `<stem>_memory/`, and that folder is the
machine. It holds nothing but two small files written here and the outputs the
run writes into it:

- `memory.image` -- the image's file name. The image is never moved, copied or
  linked: it stays where the analyst put it, the custody record of phase 0 hashes
  it there, and the parsers find it as `<unit>/../<name>`.
- `memory.name` -- what the machine is called until the image itself says
  otherwise (the file's stem; see `name_memory_units`).

Detection is then the ordinary kind: `profiles/windows_memory.yaml` matches a
folder holding `memory.image`. Staging is idempotent and never overwrites a
pointer that names a different image; two images with one stem in one folder
are reported, and the second is left for the analyst to rename.

What counts as an image is decided by the extension AND the size. `.dmp` is
also what a process minidump is called, and a minidump is not a memory image of
a machine; nothing smaller than `MIN_IMAGE_BYTES` is taken for one. Formats a
name does not reveal (`.img`, `.bin`) are left out on purpose: they are as often
disk images, and running thirty memory plugins over a disk image is half an hour
of errors.
"""

from __future__ import annotations

import csv
import os
from collections import Counter
from pathlib import Path

from artifact_engine.logging_setup import get_logger

log = get_logger()

POINTER = "memory.image"
NAME_FILE = "memory.name"
UNIT_SUFFIX = "_memory"
COLLECTOR = "memory"

IMAGE_SUFFIXES = (".raw", ".mem", ".vmem", ".lime", ".dmp", ".mddramimage")
MIN_IMAGE_BYTES = 256 * 1024 * 1024

# How deep under the case root an image is looked for: the root itself, an
# acquisition folder, and one level inside it (an image that came zipped is
# extracted into a folder of its own). An extracted Windows tree keeps
# `MEMORY.DMP` deeper than this (`<acq>/C/Windows/`), which is a crash dump of
# whatever the machine was doing when it last crashed -- not the acquisition.
_MAX_DEPTH = 2
_SKIP_DIRS = {"CSVs", "JSONs", "TXTs"}


def _is_image(p: Path) -> bool:
    if p.suffix.lower() not in IMAGE_SUFFIXES:
        return False
    try:
        return p.is_file() and p.stat().st_size >= MIN_IMAGE_BYTES
    except OSError:
        return False


def _is_disk_tree(d: Path) -> bool:
    """A folder that is the root of a filesystem a disk profile parses.

    Detection does not descend into a matched machine, so a unit created inside
    one would be staged, announced and never analysed -- and its folder would be
    written into the evidence tree. A Windows volume (`$MFT`, `Windows/System32`)
    or a UAC collection (`[root]`) is therefore not searched for images: what a
    volume holds as a `.dmp` is that system's crash dump, not the acquisition."""
    try:
        return ((d / "$MFT").exists() or (d / "Windows" / "System32").is_dir()
                or (d / "[root]").is_dir())
    except OSError:
        return False


def find_images(root: Path) -> list[Path]:
    """Every memory image under `root`, at most `_MAX_DEPTH` folders down.

    An image found INSIDE a disk tree is not taken, and is reported, so an
    analyst who dropped one there learns why it was not analysed."""
    root = Path(root)
    found: list[Path] = []
    for current, dirs, files in os.walk(root):
        here = Path(current)
        if _is_disk_tree(here):
            dirs[:] = []
            for f in files:
                if _is_image(here / f):
                    log.warning(f"[!] memory image {f} lies inside a disk acquisition "
                                f"({here.name}) and is not analysed -- move it beside "
                                f"the acquisition to analyse it")
            continue
        depth = len(here.relative_to(root).parts)
        if depth >= _MAX_DEPTH:
            dirs[:] = []
        # A unit's own folder holds outputs, never an image -- recognised by its
        # pointer, not by its name: an image zipped as `X_memory.zip` extracts to a
        # folder of that name. A snapshot or a Velociraptor side-collection is
        # pruned for the reasons detection gives.
        dirs[:] = [d for d in dirs
                   if d not in _SKIP_DIRS and not (here / d / POINTER).is_file()
                   and not d.upper().startswith("VSS") and d.lower() != "velociraptor"]
        found.extend(here / f for f in files if _is_image(here / f))
    return sorted(found)


def unit_dir(image: Path) -> Path:
    return image.parent / f"{image.stem}{UNIT_SUFFIX}"


def image_of(unit: Path) -> Path | None:
    """The image a unit folder points at, when the pointer is there and readable."""
    try:
        name = (Path(unit) / POINTER).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not name or Path(name).name != name:     # a bare file name, nothing else
        return None
    return Path(unit).parent / name


def stage_images(root: Path) -> list[Path]:
    """Create (or confirm) the unit folder of every image under `root`.

    Returns the unit folders that point at an image. Never touches the image."""
    units: list[Path] = []
    for image in find_images(root):
        unit = unit_dir(image)
        current = image_of(unit)
        if current is not None and current.name != image.name:
            log.warning(f"[!] memory image {image.name}: {unit.name} already belongs to "
                        f"{current.name} -- rename one of the two images so each gets "
                        f"its own unit; {image.name} is not analysed")
            continue
        if current is None:
            # A folder of that name that is not already a unit is the analyst's,
            # and may hold originals: writing the pointer into it would make phase
            # 0 prune it from the custody record for good. It is never adopted.
            try:
                taken = unit.exists() and (not unit.is_dir() or any(unit.iterdir()))
            except OSError:
                taken = True
            if taken:
                log.warning(f"[!] memory image {image.name}: {unit.name} already exists "
                            f"and is not a memory unit -- rename it or the image; "
                            f"{image.name} is not analysed")
                continue
            try:
                unit.mkdir(exist_ok=True)
                (unit / POINTER).write_text(image.name + "\n", encoding="utf-8")
                (unit / NAME_FILE).write_text(image.stem + "\n", encoding="utf-8")
            except OSError as e:
                log.warning(f"[!] memory image {image.name}: cannot create {unit.name}: {e}")
                continue
            log.info(f"[+] memory image {image.name}: analysed as unit {unit.name}")
        units.append(unit)
    return units


# Rows of the environment table read to name a unit: COMPUTERNAME is set in
# nearly every process, so the head is plenty.
_ENV_SAMPLE = 20_000


def name_memory_units(machines) -> list:
    """Rename each memory unit after the host its own processes name.

    Until phase 3 a unit is called after its image file, which is whatever the
    acquirer typed. Once the environment of the processes has been read, the
    most frequent `COMPUTERNAME` is the machine's own name for itself, and that is
    what every other unit of the same host is called -- so its memory and its disk
    then sit under one name in the outputs. Idempotent; returns the renamed."""
    renamed = []
    for m in machines:
        if m.collector != COLLECTOR:
            continue
        names: Counter[str] = Counter()
        for p in sorted((m.path / "CSVs").rglob("mem_envars.csv")):
            try:
                with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                    for i, row in enumerate(csv.DictReader(fh)):
                        if i >= _ENV_SAMPLE:
                            break
                        if (row.get("Variable") or "").upper() == "COMPUTERNAME":
                            value = (row.get("Value") or "").strip()
                            if value:
                                names[value] += 1
            except (OSError, csv.Error) as e:
                log.debug(f"name_memory_units: {p.name}: {e}")
        if names:
            host = names.most_common(1)[0][0]
            if host != m.name:
                log.info(f"[+] memory unit {m.name}: its processes name host {host} -- "
                         f"naming the machine after it")
                m.name = host
                renamed.append(m)
    return renamed
