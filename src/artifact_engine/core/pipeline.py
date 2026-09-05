"""The pipeline's shared steps, so a command is a caller and not a second copy.

`aeng run` and `aeng lateral` both find machines and both build the graph, and they
did it with two sets of statements that were only supposed to agree: the same graph
summary line was formatted twice from the same f-string with a different prefix, and
only one of the two commands settled display labels.

Naming a loose EVTX drop after its host is NOT among the things that had drifted --
`lateral.build` has always done it first thing, and still does. Doing it here as well
means the machines are already right when they reach the graph, so `build` no longer
has to repair its own input; the call it keeps is a safety net for anyone calling it
directly, not the thing that makes the output correct.

Nothing here decides policy. It holds the sequence, so there is one place to read
when the question is "what does phase 2 actually do".
"""
from __future__ import annotations

import logging
from pathlib import Path

from . import detector, lateral, netclass
from .detector import Machine

log = logging.getLogger("aeng")


def detect(root: Path, cfg, profiles, *, stage_drops: bool) -> list[Machine]:
    """Phase 2: find the machines under `root` and settle what each is called.

    `stage_drops` gates the one step here that touches evidence: staging a loose
    EVTX drop into the `winevt/Logs` layout the event-log toolchain expects. A full
    run needs it before parsing. A graph rebuild must not do it -- that command
    exists to re-read what is already there, and restructuring a case folder is not
    something a read path should ever do on its way past.

    Naming a drop after its host is attempted either way, and costs nothing when
    there is nothing to read: before parsing there are no CSVs to ask, so it is a
    no-op and the run renames for real once phase 3 has written them. Afterwards --
    which is the only state `aeng lateral` ever sees -- the answer is already on
    disk. Display labels are assigned last because they are derived from the names.
    """
    machines = detector.detect_machines(root, profiles, avoid_vss=cfg.avoid_vss)
    if stage_drops:
        detector.prepare_evtx_drops(machines)
    detector.name_evtx_drops(machines)
    detector.assign_display_names(machines)
    return machines


def rename_parsed_drops(machines: list[Machine]) -> bool:
    """Re-ask the drops who they are now that phase 3 has written their CSVs.

    Returns whether any machine was renamed, which the caller needs: `run.json` was
    written under the old name and has to be rewritten before anything else is named
    after the machine. Idempotent, so calling it on a case that was already named
    changes nothing.
    """
    if not detector.name_evtx_drops(machines):
        return False
    detector.assign_display_names(machines)     # labels follow the new names
    return True


def lateral_graph(machines: list[Machine], root: Path,
                  internal_networks=()) -> dict:
    """Phase 5: correlate logons across machines into the graph and its CSV.

    `internal_networks` are the configured CIDRs the organisation owns; they
    reclassify a source address, they never drop a row."""
    return lateral.build(machines, root, netclass.parse(internal_networks))


def describe_graph(lat: dict) -> str:
    """The one-line summary of a built graph, shared so both callers report the
    same numbers in the same words. Returns "" when there is nothing to say."""
    if not lat["edges"]:
        return ""
    hidden = f" ({lat['graph_hidden']} peer(s) hidden)" if lat.get("graph_hidden") else ""
    # Only shown when ranges were actually declared, and it reports the MATCH
    # count: a declaration that matched nothing is the case worth noticing, and
    # printing the range count alone would hide it.
    declared = (f" | internal_networks: {lat['internal_hosts']} of {lat['hosts']} "
                f"host(s) reclassified as internal"
                if lat.get("internal_declared") else "")
    return (f"{lat['edges']} edge(s), {lat['hosts']} host(s), "
            f"{lat['suspicious']} suspicious, {lat.get('chains', 0)} pivot chain(s) "
            f"(lateral_movement.csv) | "
            f"graph {lat.get('graph_hosts', 0)} host(s){hidden} -> lateral_movement.html"
            f"{declared}")
