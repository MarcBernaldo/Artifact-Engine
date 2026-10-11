"""Look for a value in the raw bytes of a memory image (v0.7.108).

`aeng sweep` searches what the parsers turned into tables, and in a memory image
that is only what Volatility's plugins know how to walk: process lists, command
lines, connections, handles. An address in a browser tab, a URL in a heap, a
password typed into a console, a command line of a process that already exited --
none of that is a table, and all of it is still in the image as text.

So with `--memory` the sweep also reads each image end to end and reports every
place a value occurs, as ASCII/UTF-8 and as UTF-16LE (what Windows keeps its
strings in), ignoring the case of ASCII letters. A hit is an OFFSET into the image with the
text around it -- a lead to open in a hex viewer or to map to a process later,
not a finding about which process held it.

The same boundary as the database sweep applies: `10.0.0.5` is not a hit inside
`10.0.0.50`, and `jdoe` is not a hit inside `jdoe2` or `jdoeé` -- a neighbour is
decoded in the hit's own encoding and judged as a character. Only Latin letters
count as continuing a name: beside binary data, two bytes decode to a CJK
ideograph more often than not, and a hit is not discarded for that. Case is ignored for
ASCII letters only: `JDOE` finds `jdoe`, but `É` does not find `é`.

What it cannot see: pages the image does not hold (paged out, or kept compressed
by Windows' memory compression), and text a program stored encoded. "No hits"
in memory is weaker than "no hits" in a table, and the sweep says which images
were read.

A value that occurs thousands of times (a domain the whole fleet talks to) is
listed `MAX_LISTED` times per image and counted in full.
"""

from __future__ import annotations

import os
import re
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

# Bytes per range, the unit one process reads and searches. Large enough that
# the per-range cost (lowering the buffer, one search per needle) is paid
# rarely; small enough to be a modest allocation on an analyst's laptop.
CHUNK = 64 * 1024 * 1024

# Up to this many needle encodings are searched with bytes.find (memchr-speed,
# one pass each); beyond it one alternation regex over the chunk is faster.
# Measured on 64 MiB: 40 encodings find 0.39 s vs regex 0.61 s; 400, 3.7 s vs 1.3 s.
_FIND_LIMIT = 48

# Hits listed per needle per image; the rest are counted.
MAX_LISTED = 100

# Bytes of context either side of a hit.
_CONTEXT = 64

_ADDRESS = frozenset("0123456789.")
_LATIN_END = 0x250          # past Latin Extended-B


@dataclass
class MemoryHit:
    needle: str
    encoding: str          # "ascii" or "utf16le"
    offset: int
    context: str


@dataclass
class ImageResult:
    hits: list[MemoryHit] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)     # needle -> every hit
    error: str = ""


@dataclass
class _Pattern:
    needle: str
    encoding: str
    data: bytes            # lowered
    address: bool          # continues with digits and dots, not word characters
    width: int             # bytes per character
    # A non-ASCII needle in UTF-16LE: `bytes.lower` also lowers the low byte of
    # other code units (U+0141 `41 01` -> `61 01`, which is U+0161), so such a
    # match is confirmed against the text it decodes to.
    text: str = ""


def patterns(needles: list[str]) -> list[_Pattern]:
    out = []
    for n in needles:
        if not n:
            continue
        address = bool(re.fullmatch(r"[0-9.]+", n))
        out.append(_Pattern(n, "ascii", n.encode("utf-8").lower(), address, 1))
        out.append(_Pattern(n, "utf16le", n.encode("utf-16-le").lower(), address, 2,
                            "" if n.isascii() else n.lower()))
    return out


def _char(buf: bytes, i: int, width: int, before: bool) -> str:
    """The character that ends just before `i` (`before`) or starts at `i`, decoded
    in the hit's encoding; "" at the edge of what was read or on bytes that are
    not one."""
    if width == 2:
        j = i - 2 if before else i
        if j < 0 or j + 2 > len(buf):
            return ""
        return chr(buf[j] | buf[j + 1] << 8)
    for n in (1, 2, 3, 4):              # a UTF-8 character is 1 to 4 bytes
        raw = buf[i - n:i] if before else buf[i:i + n]
        if len(raw) < n or (before and i - n < 0):
            break
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        return text[-1] if before else text[0]
    return ""


def _continues(c: str, p: _Pattern) -> bool:
    """Whether `c` is a character the value could continue with -- which makes the
    match a fragment of a longer value (as `sweep._boundary` decides in a table)."""
    if not c:
        return False
    if p.address:
        return c in _ADDRESS
    # Latin letters only. Any two bytes beside a UTF-16 string decode to SOME
    # character, and most of the BMP is CJK ideographs, which are letters: judged
    # by Unicode, a real hit next to binary data would be thrown away about as
    # often as kept. `jdoeé` is a longer name; `jdoe` + U+8483 is noise.
    return (c.isalnum() or c == "_") and ord(c) < _LATIN_END


def _render(raw: bytes, width: int) -> str:
    if width == 2:
        text = raw.decode("utf-16-le", "replace")
    else:
        text = raw.decode("latin-1")
    return "".join(c if c.isprintable() and c != "�" else "." for c in text)


def _finder(pats: list[_Pattern]):
    """(lowered chunk) -> iterable of (start, pattern index)."""
    if len(pats) <= _FIND_LIMIT:
        def run(low: bytes):
            for k, p in enumerate(pats):
                i = low.find(p.data)
                while i != -1:
                    yield i, k
                    i = low.find(p.data, i + 1)
        return run
    # The regex only says WHERE some needle starts; which ones do is asked of the
    # needles sharing that first byte. Restarting one byte later, rather than
    # after the match, keeps overlapping hits (`abab` twice in `ababab`, `ab`
    # and `abab` at one offset). A lookahead at every byte instead was measured
    # at under 5 MiB/s -- hours per image.
    rx = re.compile(b"|".join(re.escape(p.data) for p in pats))
    first: dict[int, list[int]] = {}
    for k, p in enumerate(pats):
        first.setdefault(p.data[0], []).append(k)

    def run(low: bytes):
        m = rx.search(low)
        while m:
            i = m.start()
            for k in first[low[i]]:
                if low.startswith(pats[k].data, i):
                    yield i, k
            m = rx.search(low, i + 1)
    return run


def _scan(image, needles: list[str], lo: int, hi: int) -> ImageResult:
    """The hits that START in [lo, hi) of `image`. The bytes read reach past both
    ends by a value's length and its context, so a value straddling the edge is
    whole here and its neighbour range, which does not own its start, skips it."""
    result = ImageResult(counts=dict.fromkeys(needles, 0))
    pats = patterns(needles)
    longest = max(len(p.data) for p in pats)
    first = max(0, lo - _CONTEXT - 2)
    try:
        with open(image, "rb") as fh:
            fh.seek(first)
            buf = fh.read(hi - first + longest + _CONTEXT + 2)
    except OSError as e:
        result.error = f"{type(e).__name__}: {e}"
        return result
    low = buf.lower()
    found: dict[tuple[str, str], list[MemoryHit]] = {}
    for start, k in _finder(pats)(low):
        at = first + start
        if not lo <= at < hi:
            continue
        p = pats[k]
        end = start + len(p.data)
        if p.text and buf[start:end].decode("utf-16-le", "replace").lower() != p.text:
            continue
        if _continues(_char(buf, start, p.width, True), p) or \
                _continues(_char(buf, end, p.width, False), p):
            continue
        result.counts[p.needle] += 1
        kept = found.setdefault((p.needle, p.encoding), [])
        if len(kept) < MAX_LISTED:      # each pattern is found in offset order
            a = max(0, start - _CONTEXT)
            if p.width == 2:
                a += (start - a) % 2
            kept.append(MemoryHit(p.needle, p.encoding, at,
                                  _render(buf[a:end + _CONTEXT], p.width)))
    result.hits = [h for kept in found.values() for h in kept]
    return result


def workers_for(size: int) -> int:
    """Processes to read an image of `size` bytes with: the search is CPU-bound
    (lowering the buffer, one pass per needle) and holds the GIL, so threads would
    not help. Measured on a real 1 GiB image, one process: 107 MiB/s for one
    value, about 40 MiB/s for twenty. Capped so a laptop keeps a few cores and
    the buffers (two of `CHUNK` per process) stay near a gigabyte."""
    if size <= 2 * CHUNK:
        return 1
    return max(1, min(8, (os.cpu_count() or 2) - 1))


def search(image: Path, needles: list[str], chunk: int = 0, workers: int = 0) -> ImageResult:
    """Every boundary-respecting occurrence of every needle in `image`, the first
    `MAX_LISTED` per needle (by offset) listed and all of them counted."""
    needles = [n for n in needles if n]
    result = ImageResult(counts=dict.fromkeys(needles, 0))
    if not needles:
        return result
    chunk = chunk or CHUNK
    try:
        size = os.path.getsize(image)
    except OSError as e:
        result.error = f"{type(e).__name__}: {e}"
        return result
    ranges = [(a, min(a + chunk, size)) for a in range(0, size, chunk)]
    workers = workers or workers_for(size)
    if workers > 1 and len(ranges) > 1:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            parts = list(pool.map(_scan, *zip(*[(image, needles, a, b) for a, b in ranges])))
    else:
        parts = [_scan(image, needles, a, b) for a, b in ranges]
    for part in parts:
        if part.error:
            return ImageResult(counts=result.counts, error=part.error)
        for n, c in part.counts.items():
            result.counts[n] += c
        result.hits.extend(part.hits)
    result.hits.sort(key=lambda h: (h.needle.lower(), h.offset))
    listed: dict[str, int] = {}
    kept = []
    for h in result.hits:
        listed[h.needle] = listed.get(h.needle, 0) + 1
        if listed[h.needle] <= MAX_LISTED:
            kept.append(h)
    result.hits = kept
    return result
