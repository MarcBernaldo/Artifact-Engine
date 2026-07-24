"""Phase 2 - Machine detection: applies the profiles to the extracted tree.

A "machine" is a directory that satisfies a profile's `detect` rules
(e.g. contains `$MFT` -> Windows/KAPE, or `uac.log` -> Linux/UAC).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from artifact_engine.logging_setup import get_logger
from artifact_engine.models import DetectClause, MachineName, ParserManifest, ProfileManifest

log = get_logger()


@dataclass
class Volume:
    """A volume to parse: the live one (C) or a shadow copy (VSS)."""

    name: str
    path: Path
    is_live: bool = True


@dataclass
class Machine:
    name: str
    os: str
    collector: str
    profile_id: str
    path: Path
    source: str = ""   # source acquisition folder (first level under the root)
    volumes: list[Volume] = field(default_factory=list)
    display: str = ""  # unique console label (set by assign_display_names)
    is_vss: bool = False  # a VSS snapshot machine; parsers with on_vss=false skip it
    has_lr: bool = False  # Velociraptor LiveResponse present (host-global, live volume)


def _source_tag(source: str) -> str:
    """Acquisition date from the source folder name, e.g. ...-20260331164325 -> 2026-03-31."""
    mo = re.search(r"(\d{4})(\d{2})(\d{2})\d{0,6}$", source)
    return f"{mo.group(1)}-{mo.group(2)}-{mo.group(3)}" if mo else ""


def _provenance_label(m: Machine) -> str:
    """Base console label showing what the machine IS: `HOST` for the live disk,
    `HOST-VSS<n>` for a shadow-copy snapshot, and a `-LR` tag when the host also
    carries Velociraptor LiveResponse (which is parsed on the live volume, not a
    separate machine). So the analyst can tell disk / snapshot / +live-state apart
    at a glance instead of seeing the bare hostname repeated."""
    n = m.name.replace("_VSS", "-VSS") if m.is_vss else m.name
    return f"{n}-LR" if m.has_lr else n


def assign_display_names(machines: list[Machine]) -> None:
    """Give each machine a unique console label. The base label encodes provenance
    (disk / VSS<n> / +LR — see `_provenance_label`). Two acquisitions of the same
    host still collide on that label; disambiguate with the acquisition date
    (falling back to the source folder) so the user never sees the same label
    twice. Machines with a unique label keep it as-is."""
    from collections import Counter

    labels = {id(m): _provenance_label(m) for m in machines}
    counts = Counter(labels.values())
    seen: dict[str, int] = {}
    for m in machines:
        base = labels[id(m)]
        if counts[base] <= 1:
            m.display = base
            continue
        tag = _source_tag(m.source)
        label = f"{base} [{tag}]" if tag else f"{base} ({m.source})"
        # If even the tag collides, suffix an ordinal so labels stay unique.
        if label in seen:
            seen[label] += 1
            label = f"{label}#{seen[label]}"
        else:
            seen[label] = 1
        m.display = label


def _clause_matches(base: Path, clause: DetectClause) -> bool:
    if clause.exists is not None:
        return (base / clause.exists).exists()
    if clause.glob is not None:
        return any(base.glob(clause.glob))
    if clause.dir_name is not None:
        return re.fullmatch(clause.dir_name, base.name, re.IGNORECASE) is not None
    return False


def _profile_matches(base: Path, profile: ProfileManifest) -> bool:
    d = profile.detect
    if d.all_of and not all(_clause_matches(base, c) for c in d.all_of):
        return False
    if d.any_of and not any(_clause_matches(base, c) for c in d.any_of):
        return False
    return True


def _resolve_name(base: Path, spec: MachineName, root: Path) -> str:
    name = ""
    if spec.strategy == "file" and spec.file:
        f = base / spec.file
        if f.is_file():
            try:
                name = f.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                name = ""
    elif spec.strategy == "acquisition":
        # First component of the path relative to the root = acquisition folder
        rel = base.relative_to(root)
        top = rel.parts[0] if rel.parts else base.name
        name = top
        if spec.regex:
            m = re.match(spec.regex, top)
            if m and m.group(1):
                name = m.group(1)
    elif spec.strategy == "parent_dir":
        name = base.parent.name
    elif spec.strategy == "dir_name":
        name = base.name
    if not name:
        name = base.parent.name if spec.fallback == "parent_dir" else base.name
    return name + spec.suffix


def _collect_volumes(base: Path, profile_os: str) -> list[Volume]:
    """The machine's single live volume: the Windows drive letter (e.g. C) or, on
    Linux/UAC, "live". VSS snapshots are NOT extra volumes -- each is its own
    machine (see detect_machines), so it gets its own CSVs/JSONs and .db/.xlsx."""
    live_name = base.name if profile_os == "windows" else "live"
    return [Volume(live_name, base, is_live=True)]


_LR_SUBPATH = Path("Velociraptor") / "LiveResponse" / "results"


def _has_liveresponse(base: Path) -> bool:
    """Velociraptor LiveResponse sits at <collection>/Velociraptor/LiveResponse/
    results, a sibling of the volume root; mirror the handler's lookup (base and
    its parents) so the label matches what actually gets parsed."""
    return any((b / _LR_SUBPATH).is_dir() for b in (base, base.parent, base.parent.parent))


def _vss_siblings(base: Path) -> list[Path]:
    """Sibling VSS* snapshot dirs of a Windows machine base (e.g. <coll>/VSS1,
    siblings of <coll>/C). Each holds a full volume image ($MFT, Windows/, ...)."""
    try:
        return [d for d in sorted(base.parent.iterdir())
                if d.is_dir() and d.name.upper().startswith("VSS")]
    except OSError:
        return []


def detect_machines(
    root: Path,
    profiles: list[ProfileManifest],
    avoid_vss: bool = True,
    max_depth: int = 6,
) -> list[Machine]:
    """Detect machines with a shallow walk (does not descend into huge trees).

    Shadow copies (VSS*) are pruned from the walk so they are never detected on
    their own. Unless `avoid_vss`, each becomes its OWN machine named
    "<host>_<VSSn>" pointing at the VSS dir -- a snapshot of the same host, parsed
    and consolidated as an independent unit into its own VSSn/ folder (own
    CSVs/JSONs and .db/.xlsx). This keeps VSS out of the live machine's db and lets
    the pools parse/consolidate every snapshot in parallel.
    """
    machines: list[Machine] = []
    matched: set[Path] = set()
    root = root.resolve()

    for current, dirs, _files in os.walk(root):
        base = Path(current)
        depth = len(base.relative_to(root).parts)
        if depth >= max_depth:
            dirs[:] = []
        # Never walk into VSS snapshots (attached below as their own machines) or
        # a Velociraptor side-collection: its LiveResponse is parsed on the host
        # (has_lr, not a machine) and its QuickTriage `uploads/.../c%3A` tree —
        # a copy of the KAPE artifacts — otherwise matches windows_kape and shows
        # up as a duplicate/phantom machine.
        dirs[:] = [d for d in dirs
                   if not d.upper().startswith("VSS") and d.lower() != "velociraptor"]
        for profile in profiles:
            if _profile_matches(base, profile):
                rp = base.resolve()
                if rp in matched:
                    continue
                matched.add(rp)
                name = _resolve_name(base, profile.machine_name, root)
                rel = base.relative_to(root).parts
                source = rel[0] if rel else base.name
                machines.append(
                    Machine(name, profile.os, profile.collector, profile.id, base,
                            source, _collect_volumes(base, profile.os),
                            has_lr=_has_liveresponse(base))
                )
                log.debug(f"machine: ({profile.os}/{profile.collector}) {name} @ {base}")
                # Each VSS snapshot of this host becomes its own machine.
                if not avoid_vss and profile.os == "windows":
                    for vdir in _vss_siblings(base):
                        machines.append(
                            Machine(f"{name}_{vdir.name}", profile.os, profile.collector,
                                    profile.id, vdir, source, _collect_volumes(vdir, profile.os),
                                    is_vss=True)
                        )
                        log.debug(f"  vss machine: {name}_{vdir.name} @ {vdir}")
                dirs[:] = []  # don't descend into an already-detected machine
                break

    if not machines:
        log.warning("[!] no machines detected with the loaded profiles")
    return machines


def parsers_for(machine: Machine, parsers: list[ParserManifest]) -> list[ParserManifest]:
    """Applicable parsers: matching OS and all their `requires` present."""
    out: list[ParserManifest] = []
    for p in parsers:
        if p.os not in (machine.os, "any"):
            continue
        if all((machine.path / req).exists() for req in p.requires):
            out.append(p)
    return out
