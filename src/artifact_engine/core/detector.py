"""Phase 2 - Machine detection: applies the profiles to the extracted tree.

A "machine" is a directory that satisfies a profile's `detect` rules
(e.g. contains `$MFT` -> Windows/KAPE, or `uac.log` -> Linux/UAC).
"""

from __future__ import annotations

import csv
import os
import re
import shutil
from collections import Counter
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
    lr_only: list[Path] = []   # collection roots that carry a Velociraptor LiveResponse
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
        # Note any collection root that directly carries a LiveResponse; a KAPE/UAC
        # host attaches it via has_lr, but a LiveResponse-ONLY acquisition matches no
        # profile -- reconciled after the walk so it isn't dropped in silence.
        if (base / _LR_SUBPATH).is_dir():
            lr_only.append(base)
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

    # A Velociraptor LiveResponse shipped WITHOUT KAPE/UAC artifacts beside it
    # matches no profile, so its live-response state (netstat, listening ports, ARP,
    # logged-on users, running processes, ...) would be dropped in complete silence
    # -- no machine, no summary row, no warning. Register each such collection as its
    # own `-LR` machine so the LiveResponse is still parsed on the live volume. A
    # collection whose LiveResponse a detected KAPE/UAC machine already carries (its
    # base sits at/under the collection root) is skipped -- no duplicate.
    kape_name = next((p.machine_name for p in profiles if p.collector == "kape"), None)
    for col in lr_only:
        rp = col.resolve()
        if any(rp == c or rp in c.parents for c in matched):
            continue
        matched.add(rp)
        name = _resolve_name(col, kape_name, root) if kape_name else col.name
        rel = col.relative_to(root).parts
        source = rel[0] if rel else col.name
        machines.append(
            Machine(name, "windows", "velociraptor", "windows_liveresponse", col,
                    source, _collect_volumes(col, "windows"), has_lr=True)
        )
        log.info(f"[+] LiveResponse-only acquisition (no KAPE artifacts): {name} @ {col}")

    if not machines:
        log.warning("[!] no machines detected with the loaded profiles")
    return machines


_EVTX_LOGS_SUBPATH = Path("Windows") / "System32" / "winevt" / "Logs"


def prepare_evtx_drops(machines: list[Machine]) -> None:
    """Give every loose EVTX drop the layout the Windows toolchain expects.

    All 17 event-log parsers (EvtxECmd once per channel, chainsaw, hayabusa,
    DeepBlueCLI) are wired to `<evidence>/Windows/System32/winevt/Logs`. Rather than
    teach each of them a second layout -- and risk the acquisition path every case
    depends on -- a drop folder gets that path synthesised: every `*.evtx` in it is
    hard-linked into `<drop>/Windows/System32/winevt/Logs/`, falling back to a copy
    when linking is refused (different filesystem / no privilege).

    Once a log is staged, its ORIGINAL path in the drop is removed, so the folder
    holds each event log exactly once instead of showing the analyst the same
    Security.evtx twice. This loses nothing: a hard link is a second NAME for one
    set of bytes, so unlinking the original leaves the data intact under the staged
    path; on the copy fallback the staged copy is verified byte-for-byte in size
    before the original goes. If staging did not happen -- collision, failure -- the
    original is always left alone. The (now empty) subfolders are kept: removing
    directories from an evidence tree is not worth the tidiness.

    File names are preserved: EvtxECmd picks its channel BY NAME (`Security.evtx`,
    `Microsoft-Windows-Sysmon%4Operational.evtx`, ...), while chainsaw/hayabusa/
    DeepBlueCLI sniff content and so also read anything renamed. Two logs sharing a
    basename (usually a drop mixing several hosts, which should be one folder each)
    would collide, so the first wins and the rest are reported rather than
    overwritten -- and, being unstaged, they stay where they are. Re-runs are
    idempotent: nothing is left outside the staging dir to re-stage.
    """
    for m in machines:
        if m.collector != "evtx":
            continue
        logs = m.path / _EVTX_LOGS_SUBPATH
        # Anything already inside the staging dir is the product of an earlier run.
        sources = [p for p in sorted(m.path.rglob("*.evtx")) if logs not in p.parents]
        seen: dict[str, Path] = {}
        staged = pruned = 0
        for src in sources:
            key = src.name.lower()
            if key in seen:
                log.warning(f"[!] {m.name}: two event logs named {src.name} "
                            f"({src} vs {seen[key]}) -- keeping the first; "
                            f"logs from different hosts need one drop folder each")
                continue
            seen[key] = src
            dst = logs / src.name
            if not dst.exists():
                logs.mkdir(parents=True, exist_ok=True)
                try:
                    os.link(src, dst)
                except OSError:               # cross-device / unprivileged -> copy
                    shutil.copy2(src, dst)
                staged += 1
            # Drop the duplicate NAME now that the bytes live at the staged path.
            if _same_bytes(src, dst) and _unlink(src):
                pruned += 1
        if staged or pruned:
            log.info(f"[+] EVTX drop {m.name}: staged {staged} event log(s) for the "
                     f"Windows event-log toolchain" + (f", removed {pruned} duplicate "
                     f"path(s) from the drop root" if pruned else ""))


def _same_bytes(src: Path, dst: Path) -> bool:
    """True when `dst` certainly holds `src`'s data: the same inode (hard link) or a
    file of identical size. Guards the unlink below -- never remove an original whose
    staged counterpart is missing or truncated."""
    try:
        a, b = src.stat(), dst.stat()
    except OSError:
        return False
    if a.st_ino and a.st_ino == b.st_ino and a.st_dev == b.st_dev:
        return True                           # one set of bytes, two names
    return a.st_size == b.st_size and a.st_size > 0


def _unlink(p: Path) -> bool:
    try:
        p.unlink()
        return True
    except OSError as e:                      # locked by a viewer / read-only media
        log.debug(f"prepare_evtx_drops: could not remove {p}: {e}")
        return False


# Rows sampled per CSV when identifying an EVTX drop's host: the Computer field is
# constant within a channel, so the head is enough and a huge Security.csv is never
# read whole just to learn a name.
_EVTX_HOST_SAMPLE = 200


def name_evtx_drops(machines: list[Machine]) -> list[Machine]:
    """Rename each loose EVTX drop from its folder to the host its events name.

    Detection can only name a drop after its directory (`evtx-something`), which is
    not a host. Once phase 3 has parsed it, the events themselves carry the answer
    in their `Computer` field, so the machine is renamed to the most frequent one
    (short form, matching how acquired machines are named).

    Call it as soon as parsing is done and BEFORE anything is named after the
    machine: `run.json`, `<machine>.db`/`.xlsx`, `report.txt`, `run-summary` and the
    lateral graph then all agree on one name, instead of the folder in the outputs
    written early and the real host in the ones written late. Idempotent -- a second
    call (e.g. from `aeng lateral`, which re-detects from scratch) recomputes the
    same name. Returns the machines it actually renamed.
    """
    renamed: list[Machine] = []
    for m in machines:
        if m.collector != "evtx":
            continue
        names: Counter[str] = Counter()
        for csv_path in sorted((m.path / "CSVs" / "EventLogs").glob("evtx_*.csv")):
            try:
                with csv_path.open("r", encoding="utf-8-sig",
                                   errors="replace", newline="") as fh:
                    for i, row in enumerate(csv.DictReader(fh)):
                        if i >= _EVTX_HOST_SAMPLE:
                            break
                        comp = (row.get("Computer") or "").strip()
                        if comp:
                            names[comp.split(".")[0]] += 1
            except OSError as e:
                log.debug(f"name_evtx_drops: {csv_path.name}: {e}")
        if names:
            host = names.most_common(1)[0][0]
            if host != m.name:
                log.info(f"[+] EVTX drop {m.name}: events name host {host} -- "
                         f"naming the machine after it")
                m.name = host
                renamed.append(m)
    return renamed


def parsers_for(machine: Machine, parsers: list[ParserManifest]) -> list[ParserManifest]:
    """Applicable parsers: matching OS and all their `requires` present."""
    out: list[ParserManifest] = []
    for p in parsers:
        if p.os not in (machine.os, "any"):
            continue
        if all((machine.path / req).exists() for req in p.requires):
            out.append(p)
    return out
