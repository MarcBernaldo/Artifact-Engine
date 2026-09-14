"""Whether a delivered archive has finished arriving.

An unattended run is started by a clock, not by the end of a copy, and phase 1
cannot tell an archive that is still being written from one that was cut short.
MEASURED on a synthetic acquisition written at 60% of its length and then whole:
with a 7-Zip on the host the zip came out `partial` with 37 of 60 members and the
tar.gz with none, and because extraction is the phase a later run does not repeat
(`extractor.MARKER`) both stayed that way after the copy had finished. Phase 0 is
append-only, as a custody record must be, so it would have kept the hash of the
truncated file for good.

So a delivered archive is opened only once it has ARRIVED, decided in this order:

- **Sealed.** `<archive>.sha256` beside it, in `sha256sum` format -- what the
  Artifact-extract collector writes once the archive is finished. A seal that
  matches proves the whole archive, whatever its age and whichever of the two
  files was copied first. One that does not match is not opened: the archive is
  still arriving, or it was damaged on the way, and every run says which until
  it matches.
- **Settled.** No seal: unchanged for `settle_seconds`. Off Windows the last
  change is the later of mtime and ctime, because a copy that preserves
  timestamps sets the mtime back to the source's when it finishes, and that is
  itself a change the ctime records. Windows keeps no such ctime, so there the
  mtime is all there is to read.

`settle_seconds` defaults to 0, so an analyst who starts a run after a copy has
finished sees no difference; a seal is checked either way. A sealed archive is
not read before it has settled, so a large upload is not hashed on every pass.

Only what is DELIVERED is asked: containers at the case root and in the loose-drop
folders. A container found inside an extraction came out of an archive that had
already arrived, and an archive whose destination carries its marker was opened
by an earlier run -- a later change to it is `extractor`'s to report. Not covered,
said plainly: a loose file copied into a drop folder is read as it is found.
"""
from __future__ import annotations

import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from artifact_engine.core import extractor, hashing

SEAL_SUFFIX = ".sha256"
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")

READY = "ready"
WAITING = "waiting"
MISMATCH = "seal mismatch"


@dataclass(frozen=True)
class Arrival:
    archive: Path
    state: str
    detail: str = ""
    # Set when a seal was checked, so phase 0 does not read a large archive twice.
    sha256: str = ""

    @property
    def ready(self) -> bool:
        return self.state == READY


def seal_of(archive: Path) -> Path:
    return archive.with_name(archive.name + SEAL_SUFFIX)


def read_seal(seal: Path) -> str:
    """The SHA-256 a seal declares, lower-cased; '' when it holds none.

    The first token of the first non-empty line, which covers `sha256sum`'s text
    and binary forms (`<hash>  name`, `<hash> *name`) and a bare hash, with or
    without a byte-order mark."""
    try:
        text = seal.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return ""
    first = next((ln.split()[0] for ln in text.splitlines() if ln.strip()), "")
    return first.lower() if _HEX64.fullmatch(first) else ""


def _last_change(st: os.stat_result) -> float:
    if os.name == "nt":
        return st.st_mtime
    return max(st.st_mtime, st.st_ctime)


def _young(age: float, settle_seconds: int) -> str:
    return (f"changed {max(0, int(age))} s ago; opened once it has been still "
            f"for {settle_seconds} s")


def check(archive: Path, settle_seconds: int = 0, now: float | None = None) -> Arrival:
    """Whether `archive` has arrived, and if not, why not."""
    now = time.time() if now is None else now
    try:
        st = archive.stat()
    except OSError as e:
        return Arrival(archive, WAITING, f"cannot be read yet ({e.strerror or type(e).__name__})")
    age = now - _last_change(st)
    still = age >= settle_seconds
    seal = seal_of(archive)
    if seal.is_file():
        if not still:
            return Arrival(archive, WAITING, _young(age, settle_seconds))
        want = read_seal(seal)
        if not want:
            return Arrival(archive, MISMATCH, f"{seal.name} holds no SHA-256 to check it against")
        try:
            got = hashing.sha256_file(archive)
        except OSError as e:
            return Arrival(archive, WAITING,
                           f"cannot be read yet ({e.strerror or type(e).__name__})")
        if got != want:
            return Arrival(archive, MISMATCH, f"does not match {seal.name}: still being "
                                              f"copied, or damaged on the way")
        return Arrival(archive, READY, sha256=got)
    if not still:
        return Arrival(archive, WAITING, _young(age, settle_seconds))
    return Arrival(archive, READY)


def _inside_extraction(path: Path, root: Path) -> bool:
    here = path.parent
    while here != root and root in here.parents:
        if (here / extractor.MARKER).is_file():
            return True
        here = here.parent
    return False


def delivered(root: Path) -> list[Path]:
    """The containers an analyst delivered that no run has opened yet."""
    found = [p for p in root.iterdir() if extractor.is_container(p)]
    for drop in extractor.drop_dirs(root):
        found += [p for p in drop.rglob("*") if extractor.is_container(p)]
    return [p for p in sorted(set(found))
            if not (extractor.destination(p) / extractor.MARKER).is_file()
            and not _inside_extraction(p, root)]


def survey(root: Path, settle_seconds: int = 0, now: float | None = None,
           max_workers: int = 4) -> list[Arrival]:
    """`check` for every delivered archive. In parallel: a seal is checked by
    reading the whole archive."""
    archives = delivered(root)
    if not archives:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(archives)))) as ex:
        return list(ex.map(lambda p: check(p, settle_seconds, now), archives))


def held(arrivals: list[Arrival]) -> set[Path]:
    """What phases 0 and 1 leave alone this run: every archive that has not
    arrived, and its seal."""
    out: set[Path] = set()
    for a in arrivals:
        if not a.ready:
            out |= {a.archive, seal_of(a.archive)}
    return out


def hashes(arrivals: list[Arrival]) -> dict[Path, str]:
    return {a.archive: a.sha256 for a in arrivals if a.ready and a.sha256}


def not_arrived(arrivals: list[Arrival]) -> list[dict]:
    """The rows `run-summary.json` carries as `waiting_acquisitions`."""
    return [{"archive": a.archive.name, "status": a.state, "detail": a.detail}
            for a in arrivals if not a.ready]
