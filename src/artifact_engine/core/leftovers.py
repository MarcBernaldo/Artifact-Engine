"""Which machines were detected over an acquisition that did not extract whole.

Phase 2 detects machines from what is on disk and never reads the extraction
results, so whatever a failed or partial extraction left behind is detected and
parsed like any other tree -- and its report.txt read like a clean triage of a
quiet host. Detection is not changed to skip those trees: what did come out is
evidence, and the parsers over it are the only way to read it. What changes is
that the machine says where it came from (v0.7.128).

A machine is over an acquisition when

- its folder is inside the acquisition's destination (the leftovers ARE the
  machine);
- the destination is inside the machine's folder (an archive nested in the
  machine's tree failed);
- the acquisition is a Velociraptor sub-collection
  (`<collection>/Velociraptor/<name>.zip`) and the machine is inside that
  collection: a KAPE volume at `<collection>/C` reads it from beside itself.

A machine rooted at the case root contains every destination, so the second rule
holds for it only when the root is a loose-drop folder (`-p` pointed at one, whose
archives are that machine's own); otherwise one broken archive anywhere would flag
it. A `Velociraptor/` folder AT the root makes the root the collection (`-p`
pointed at one), and every machine under it is one of its volumes.
"""
from __future__ import annotations

from pathlib import Path

from artifact_engine.core.extractor import DROP_DIR


def _inside(p: Path, parent: Path) -> bool:
    try:
        p.relative_to(parent)
        return True
    except ValueError:
        return False


def _broken(acquisitions) -> list[tuple[Path, dict]]:
    """(resolved destination, entry) per acquisition that did not extract whole,
    in `extractor.incomplete_acquisitions`' order and shape (plus `dest`, which
    only `name_machines` reads). One dict per acquisition, shared by every
    machine over it."""
    out = []
    for r in acquisitions:
        if not r.ok:
            a = {"archive": r.archive.name, "status": "failed", "detail": r.error}
        elif r.partial:
            a = {"archive": r.archive.name, "status": "partial", "detail": r.warning_detail}
        else:
            continue
        dest = Path(r.dest).resolve()
        a["dest"] = str(dest)
        out.append((dest, a))
    return out


def machines_over(acquisitions, machines, root: Path) -> dict[int, list[dict]]:
    """`id(machine)` -> the incomplete acquisitions under it, each as
    `{"archive", "status", "detail", "dest"}`. Machines over none are absent."""
    broken = _broken(acquisitions)
    if not broken:
        return {}
    root = root.resolve()
    root_is_drop = bool(DROP_DIR.fullmatch(root.name))
    out: dict[int, list[dict]] = {}
    for m in machines:
        mp = Path(m.path).resolve()
        hits = []
        for dest, a in broken:
            vr_coll = dest.parent.parent if dest.parent.name.lower() == "velociraptor" else None
            if (_inside(mp, dest)
                    or (_inside(dest, mp) and (mp != root or root_is_drop))
                    or (vr_coll is not None and _inside(mp, vr_coll))):
                hits.append(a)
        if hits:
            out[id(m)] = hits
    return out


def name_machines(incomplete: list[dict], acquisitions, over: dict[int, list[dict]],
                  machines) -> None:
    """Add `"machines"` -- the names the run gave them, sorted -- to each entry of
    `incomplete` (`extractor.incomplete_acquisitions(acquisitions)`) that some
    machine was detected over. Matched by destination, not by name: two
    `LiveResponse.zip` failing with the same error are two acquisitions. Called
    after parsing, so a loose drop renamed after its host is named as every other
    output names it."""
    names: dict[str, set[str]] = {}
    for m in machines:
        for a in over.get(id(m), []):
            names.setdefault(a["dest"], set()).add(m.display or m.name)
    for entry, (dest, _a) in zip(incomplete, _broken(acquisitions)):
        if str(dest) in names:
            entry["machines"] = sorted(names[str(dest)])


def report_lines(acqs: list[dict]) -> list[str]:
    """The report.txt block for a machine (or merged host) over `acqs`."""
    if not acqs:
        return []
    lines = ["", "!! Built over an acquisition that did NOT extract whole:"]
    for a in acqs:
        detail = f"  -- {a['detail']}" if a.get("detail") else ""
        lines.append(f"   {a['archive']}: {a['status']}{detail}")
    lines += ["   The parsers below ran on what it left on disk. What they did not",
              "   report is not a finding about the machine."]
    return lines
