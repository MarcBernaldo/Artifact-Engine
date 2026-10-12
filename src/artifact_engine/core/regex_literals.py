"""Text every match of a regex must contain, so most lines skip the regex (v0.7.110).

`huntweb` checks every request against the analyst's `web_suspicious.txt`, one
case-insensitive regex per line, combined. Measured on a 7.3M-request web
server: 44-53 us per request, about 390 s of the parser's 561 -- for a list
that matches one request in a hundred. A case-insensitive alternation whose
branches open with `\\b` gives `re` nothing to skip ahead with, so it tries
every branch at every position.

Most of those regexes cannot match without some fixed text: `\\b(sqlmap|nikto)\\b`
needs `sqlmap` or `nikto`; `/\\.(env|git)\\b` needs `/.env` or `/.git`.
`candidates(rx)` reads the regex's own parse tree and returns such sets -- each
one alone is a condition every match satisfies: one of its strings occurs, once
text and strings are lowered. `LiteralGate` asks one trie-shaped regex over the
lowered text first, and the original regex only on the lines that pass it --
except a regex with no usable set, or whose set passes most lines, which is run
on every line. Either way the answer is the combined regex's own.

How a set is read off the tree:

  - a run of fixed text, together with neighbouring parts that can only be a
    few known strings (`(php|asp)`, `[3457]?`, an anchor), is the set of their
    concatenations: `\\.(php|conf)\\.(bak|old)` -> `.php.bak`, `.conf.old`, ...
  - an alternation is all its branches' sets together, or nothing if one
    branch has none;
  - a group or a repeat that must occur is its content's;
  - anything else (a class like `\\s`, `.`, a lookaround, a backreference) is
    nothing, and splits the runs around it.

A regex can offer several valid sets (`\\b(cmd|wso)\\.(php|asp)` needs a name
AND an extension: either set alone is valid). Which one lets fewest lines
through depends on the traffic -- `.php` is in every other URL of a PHP site --
so the gate measures it: the first `CALIBRATE` lines are answered by the regex
directly while every candidate's pass count is kept, and the most selective one
is used from then on. The choice changes only the speed.

Only ASCII strings are used. The parse tree is `re`'s own (`re._parser`,
`sre_parse` before 3.11), a private module: if it is missing or changes shape,
a regex gets no set and is simply run on every line, as before.
"""

from __future__ import annotations

import re

try:                                     # 3.11+
    from re import _constants as _c
    from re import _parser as _p
except ImportError:                      # 3.10
    import sre_constants as _c
    import sre_parse as _p

from artifact_engine.core.sigma_prefilter import trie_pattern

# Strings shorter than this pass too many lines to be worth a first look. Two
# is enough for `%{` or `()`; a short string that turns out common is caught by
# the calibration below, not here.
MIN_LITERAL = 2
# A part with more spellings than this is not expanded (`[a-z]` is 26).
_MAX_STRINGS = 256
_MAX_CLASS = 12
# Lines answered by the regexes directly while the candidates are measured.
CALIBRATE = 2000

# Characters `re.IGNORECASE` matches to an ASCII letter that `str.lower()` does
# not lower to it: `n` + U+0131 + `kto` matches `(?i)nikto`, and lowered it
# still has the U+0131.
# tests/test_regex_literals.py recomputes the list on the running interpreter.
_FOLD = str.maketrans({chr(0x130): "i", chr(0x131): "i", chr(0x17F): "s", chr(0x212A): "k"})


def fold(text: str) -> str:
    """`text` as the gate compares it: lowered, with the four characters above
    made the ASCII letters `re` takes them for."""
    return text.lower() if text.isascii() else text.translate(_FOLD).lower()


def _finite_node(op, av) -> set[str] | None:
    """Every string this node can match, when that is a short list; else None."""
    if op is _c.LITERAL:
        return {chr(av)}
    if op is _c.AT:
        return {""}                       # zero-width: adds nothing, breaks nothing
    if op is _c.IN:
        out: set[str] = set()
        for k, v in av:
            if k is _c.LITERAL:
                out.add(chr(v))
            elif k is _c.RANGE and v[1] - v[0] < _MAX_CLASS:
                out.update(chr(x) for x in range(v[0], v[1] + 1))
            else:
                return None               # NEGATE, CATEGORY, a wide range
        return out if len(out) <= _MAX_CLASS else None
    if op is _c.SUBPATTERN:
        return _finite(av[-1])
    if op is _c.BRANCH:
        out = set()
        for branch in av[1]:
            f = _finite(branch)
            if f is None:
                return None
            out |= f
        return out if len(out) <= _MAX_STRINGS else None
    if op in (_c.MAX_REPEAT, _c.MIN_REPEAT):
        lo, hi, body = av
        if hi > 1:
            return None
        f = _finite(body)
        if f is None:
            return None
        return (f | {""}) if lo == 0 else f
    return None


def _finite(items) -> set[str] | None:
    out = {""}
    for op, av in items:
        f = _finite_node(op, av)
        if f is None:
            return None
        out = {a + b for a in out for b in f}
        if len(out) > _MAX_STRINGS:
            return None
    return out


def _usable(strings) -> frozenset | None:
    if not strings or any(len(s) < MIN_LITERAL or not s.isascii() for s in strings):
        return None
    return frozenset(s.lower() for s in strings)


def _key(option: frozenset):
    return (min(map(len, option)), -len(option))


def _seq(items) -> list[frozenset]:
    """Every valid set this sequence offers."""
    options: list[frozenset] = []
    chain: set[str] | None = {""}

    def close():
        nonlocal chain
        if chain is not None:
            u = _usable(chain)
            if u is not None:
                options.append(u)
        chain = {""}

    for op, av in items:
        f = _finite_node(op, av)
        if f is not None:
            grown = {a + b for a in chain for b in f}
            if len(grown) <= _MAX_STRINGS:
                chain = grown
                continue
        close()
        options.extend(_node(op, av))
    close()
    return options


def _node(op, av) -> list[frozenset]:
    if op is _c.SUBPATTERN:
        return _seq(av[-1])
    if op is _c.BRANCH:
        # One set for the whole alternation: each branch's own best, together.
        out: set[str] = set()
        for branch in av[1]:
            opts = _seq(branch)
            if not opts:
                return []
            out |= max(opts, key=_key)
        return [frozenset(out)]
    if op in (_c.MAX_REPEAT, _c.MIN_REPEAT) or op is getattr(_c, "POSSESSIVE_REPEAT", None):
        lo, _, body = av
        return _seq(body) if lo >= 1 else []
    if op is getattr(_c, "ATOMIC_GROUP", None):
        return _seq(av)
    return []


def candidates(rx: re.Pattern) -> list[frozenset]:
    """Sets of lowered strings, each of which every match of `rx` contains one
    of; [] when the regex's tree says nothing certain."""
    if not isinstance(rx.pattern, str) or rx.flags & re.VERBOSE:
        return []
    try:
        return list(dict.fromkeys(_seq(_p.parse(rx.pattern, rx.flags))))
    except Exception:                     # noqa: BLE001 - a private API: never fatal
        return []


class LiteralGate:
    """`gate(text)` -> True exactly when one of `regexes` matches `text` (that
    is: `whole.search(text)`, their combination), asked first of a trie over
    the lowered text built from each regex's most selective set."""

    def __init__(self, regexes: list[re.Pattern], whole: re.Pattern | None):
        self.whole = whole
        self.regexes = regexes
        self.options = [candidates(rx) for rx in regexes]
        self.open = [rx for rx, o in zip(regexes, self.options) if not o]
        self.counts = [[0] * len(o) for o in self.options]
        self.probes = [[re.compile(trie_pattern(s)).search for s in o] for o in self.options]
        self.seen = 0
        self.first = None
        self.rest = None

    def _settle(self) -> None:
        lits: set[str] = set()
        for rx, opts, counts in zip(self.regexes, self.options, self.counts):
            if not opts:
                continue
            best = min(range(len(opts)), key=lambda i: (counts[i], [-x for x in _key(opts[i])]))
            if counts[best] * 2 > self.seen:
                self.open.append(rx)      # passes most lines anyway: just run it
            else:
                lits |= opts[best]
        self.first = re.compile(trie_pattern(sorted(lits))).search if lits else None
        # the regexes with no set are asked of every line, together
        self.rest = [rx.search for rx in self.open]
        self.probes = None

    def __call__(self, text: str) -> bool:
        if self.whole is None:
            return False
        if self.probes is not None:
            low = fold(text)
            for i, probes in enumerate(self.probes):
                for j, probe in enumerate(probes):
                    if probe(low):
                        self.counts[i][j] += 1
            self.seen += 1
            if self.seen >= CALIBRATE:
                self._settle()
            return self.whole.search(text) is not None
        if not ((self.first is not None and self.first(fold(text)))
                or any(search(text) for search in self.rest)):
            return False
        return self.whole.search(text) is not None

