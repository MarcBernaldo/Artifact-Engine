"""One console line per host (v0.7.122).

A host reaches the parser pool as several machines: its live volume, each VSS
snapshot, a LiveResponse shipped on its own, a second acquisition, a memory
image named after it. Each had its own bar, so a host with ten snapshots took
eleven rows and a 16-host case overflowed the window into the condensed view.

This module only decides which machines SHARE A LINE and what the line says.
Machine names, folders and outputs do not change. Kept out of detector.py and
consolidate.py on purpose: both are in consolidation's fingerprint closure, so
a display rule there would re-consolidate every case.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from artifact_engine.core.detector import Machine

_VSS_SUFFIX = re.compile(r"_VSS\d+$", re.IGNORECASE)

# Collectors whose machines are not a host's acquisition (a log drop, a firewall
# export): always a line of their own.
_OWN_LINE = {"weblogs", "fortigate", "evtx"}

# A name that says nothing about which host it is never joins another.
_NOT_A_HOST = {"", "localhost", "localhost.localdomain", "unknown", "(none)"}


def host_of(m: Machine) -> str:
    """The host a machine belongs to, as it should be shown: without the
    snapshot suffix and without the collector suffix a profile adds (`_uac`)."""
    name = _VSS_SUFFIX.sub("", m.name) if m.is_vss else m.name
    tail = f"_{m.collector}"
    if m.collector and name.lower().endswith(tail.lower()) and len(name) > len(tail):
        name = name[:-len(tail)]
    return name


def _key(i: int, m: Machine) -> tuple:
    host = host_of(m)
    if m.collector in _OWN_LINE or host.strip().lower() in _NOT_A_HOST:
        return ("own", i)
    return (m.os, host.lower())


def _tags(members: list[Machine]) -> list[str]:
    vss = sum(1 for m in members if m.is_vss)
    lr = any(m.has_lr for m in members)
    count = {}
    for m in members:
        if not m.is_vss and m.collector not in ("velociraptor", "kape"):
            count[m.collector] = count.get(m.collector, 0) + 1
    kape = sum(1 for m in members if m.collector == "kape" and not m.is_vss)
    tags = []
    if kape > 1:
        tags.append(f"KAPE x{kape}")
    if lr:
        tags.append("LR")
    if vss:
        tags.append(f"{vss} VSS")
    for collector, n in count.items():
        word = "mem" if collector == "memory" else collector.upper()
        tags.append(word if n == 1 else f"{word} x{n}")
    return tags


def label(members: list[Machine]) -> str:
    """`HOST-01 [LR, 10 VSS]`, `web-01 [UAC]`, `HOST-01 [UAC x2, mem]`; a host
    with one plain disk acquisition is its bare name."""
    first = members[0]
    if first.collector in _OWN_LINE:
        return first.display or first.name
    tags = _tags(members)
    host = host_of(first)
    return f"{host} [{', '.join(tags)}]" if tags else host


def group(machines: list[Machine]) -> list[tuple[str, list[int]]]:
    """[(line label, indexes into `machines`)], in order of first appearance.

    Two lines that would read the same (one host name on two OSes, or a name
    only the collector suffix told apart) keep the machines' own unique display
    labels instead, so no two lines are ever identical."""
    order: list[tuple] = []
    members: dict[tuple, list[int]] = {}
    for i, m in enumerate(machines):
        k = _key(i, m)
        if k not in members:
            members[k] = []
            order.append(k)
        members[k].append(i)
    out = [(label([machines[i] for i in members[k]]), members[k]) for k in order]
    seen: dict[str, int] = {}
    for text, _ in out:
        seen[text] = seen.get(text, 0) + 1
    fixed = []
    for text, idx in out:
        if seen[text] > 1:
            m = machines[idx[0]]
            own = m.display or m.name
            text = own if len(idx) == 1 else f"{own} [+{len(idx) - 1}]"
        fixed.append((text, idx))
    return fixed
