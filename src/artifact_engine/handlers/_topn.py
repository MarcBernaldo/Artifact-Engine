"""Keep the best N rows of an unbounded scan without holding all of them.

A $MFT or a bodyfile has millions of entries, and the ones a detector matches are
the attacker's to inflate. Collecting every match into a list and sorting it at
the end is the obvious implementation and the one that turns a hostile volume
into a memory error, so matches go through here instead: a bounded heap that
holds the best N and counts everything it discarded.

The count is the point as much as the bound. A table that quietly stops at two
thousand rows reads as a volume with two thousand matches, which is the same
mistake as a truncated archive reading as a quiet host -- so callers write what
`total` says next to the rows `best()` returns.
"""

from __future__ import annotations

import heapq
from typing import Any


class TopN:
    """The `n` rows with the smallest key, plus how many were offered in all.

    Keys are tuples where SMALLER means more interesting, which is how a sort key
    normally reads. Internally they are negated so the heap's root is the worst
    row held, i.e. the next one to drop.
    """

    def __init__(self, n: int) -> None:
        self.n = n
        self.total = 0
        self._seq = 0
        self._heap: list[tuple[tuple, int, Any]] = []

    def add(self, key: tuple, row: Any) -> None:
        self.total += 1
        self._seq += 1
        # The sequence number breaks ties so two equal keys never compare rows,
        # and keeps the order the scan produced them in (negated with the key).
        entry = (tuple(-k for k in key), -self._seq, row)
        if len(self._heap) < self.n:
            heapq.heappush(self._heap, entry)
        elif entry > self._heap[0]:
            heapq.heapreplace(self._heap, entry)

    @property
    def dropped(self) -> int:
        return max(0, self.total - len(self._heap))

    def best(self) -> list:
        """The kept rows, most interesting first."""
        return [row for _, _, row in sorted(self._heap, reverse=True)]
