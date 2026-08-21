"""The pipeline's shared steps, so a command is a caller and not a second copy.

`aeng run` and `aeng lateral` both find machines and both build the graph, and for
a while they did it with two sets of statements that were only supposed to agree.
They stopped agreeing: the run asked a loose EVTX drop's parsed events which host
they belonged to and renamed the machine accordingly, and the standalone graph
rebuild did not -- so the same case produced nodes named after a directory or
named after a host depending on which command was used last, on a graph that keys
nodes on `Machine.name`.

Nothing here decides policy. It holds the sequence, so there is one place to read
when the question is "what does phase 2 actually do".
"""
from __future__ import annotations

import logging
from pathlib import Path

from . import detector, lateral
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


def lateral_graph(machines: list[Machine], root: Path) -> dict:
    """Phase 5: correlate logons across machines into the graph and its CSV."""
    return lateral.build(machines, root)


def describe_graph(lat: dict) -> str:
    """The one-line summary of a built graph, shared so both callers report the
    same numbers in the same words. Returns "" when there is nothing to say."""
    if not lat["edges"]:
        return ""
    hidden = f" ({lat['graph_hidden']} peer(s) hidden)" if lat.get("graph_hidden") else ""
    return (f"{lat['edges']} edge(s), {lat['hosts']} host(s), "
            f"{lat['suspicious']} suspicious, {lat.get('chains', 0)} pivot chain(s) "
            f"(lateral_movement.csv) | "
            f"graph {lat.get('graph_hosts', 0)} host(s){hidden} -> lateral_movement.html")
