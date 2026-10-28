"""What text a row must contain for a compiled Sigma rule to match it (v0.7.109).

`alert_web` loads every request into a SQLite table and runs each rule's SQL over
it. Measured on a 52.5M-request public web server, that insert-and-query step
was the largest single cost of the parser -- for a ruleset that matches a few
requests in a thousand. Almost every row could be dropped before it reaches the
table, IF it is certain that no rule would have matched it.

That certainty is derived from the rules themselves, never written by hand: a
hand-kept list goes stale the day SigmaHQ adds a rule, and a stale prefilter
loses detections in silence. `necessary(sql)` reads a rule's WHERE clause and
returns, per column, literals at least one of which must occur in the row
(ignoring ASCII case) for the rule to be true:

  - `col LIKE 'pat'`        -> the longest fixed run of `pat` between wildcards
  - `col = 'text'`          -> `text`
  - `a OR b`                -> what a needs, plus what b needs (both or nothing)
  - `a AND b`               -> whichever of the two narrows more
  - `NOT a`, `IS NULL`, a number, anything not recognised
                            -> nothing: the rule must see every row

So the answer is either a condition that every match satisfies, or None, and a
rule whose answer is None keeps reading every row. Nothing is guessed: a clause
this reader does not understand makes its rule unfiltered, never filtered wrong.

Only ASCII literals are used. SQLite's LIKE folds ASCII case only, and an ASCII
literal found in a value stays found when both are lowered; a non-ASCII one need
not (lowering some characters changes their length or depends on context).
"""

from __future__ import annotations

import re

# A literal shorter than this lets nearly every row through: the rule is then
# better run unfiltered than paid for twice.
MIN_LITERAL = 3

_TOKEN = re.compile(r"""
    \s*(?:
      (?P<str>'(?:[^']|'')*')
    | (?P<ident>`[^`]*`|"[^"]*"|[A-Za-z_][A-Za-z0-9_.\-]*)
    | (?P<num>-?\d+(?:\.\d+)?)
    | (?P<op><=|>=|<>|!=|=|<|>|\(|\)|,)
    )""", re.VERBOSE)

_KEYWORDS = {"AND", "OR", "NOT", "LIKE", "ESCAPE", "IS", "NULL", "IN", "GLOB",
             "REGEXP", "BETWEEN", "MATCH"}


def _tokens(text: str) -> list[tuple[str, str]] | None:
    out = []
    i = 0
    text = text.rstrip().rstrip(";")
    while i < len(text):
        if text[i:].strip() == "":
            break
        m = _TOKEN.match(text, i)
        if not m or m.end() == i:
            return None
        i = m.end()
        kind = m.lastgroup
        value = m.group(kind)
        if kind == "ident" and value.upper() in _KEYWORDS:
            kind, value = "kw", value.upper()
        elif kind == "ident":
            value = value[1:-1] if value[0] in "`\"" else value
        elif kind == "str":
            value = value[1:-1].replace("''", "'")
        out.append((kind, value))
    return out


def _like_literal(pattern: str, escape: str | None) -> str:
    """The longest run of `pattern` that is not a wildcard, with escapes resolved."""
    runs, cur, i = [], [], 0
    while i < len(pattern):
        c = pattern[i]
        if escape and c == escape and i + 1 < len(pattern):
            cur.append(pattern[i + 1])
            i += 2
            continue
        if c in "%_":
            runs.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    runs.append("".join(cur))
    return max(runs, key=len)


class Need(dict):
    """column -> frozenset of lowered literals. `exact` when any came from an
    equality (`cs-method = 'GET'`): a categorical value most rows share, so
    worse than any LIKE run when AND offers a choice."""

    exact = False


class _Parser:
    def __init__(self, toks):
        self.t = toks
        self.i = 0

    def peek(self, kind=None, value=None):
        if self.i >= len(self.t):
            return None
        k, v = self.t[self.i]
        if (kind and k != kind) or (value and v != value):
            return None
        return k, v

    def take(self, kind=None, value=None):
        tok = self.peek(kind, value)
        if tok is None:
            raise ValueError(f"expected {kind} {value} at {self.i}")
        self.i += 1
        return tok

    def expr(self):
        need = self.conj()
        while self.peek("kw", "OR"):
            self.take()
            need = _either(need, self.conj())
        return need

    def conj(self):
        need = self.unary()
        while self.peek("kw", "AND"):
            self.take()
            need = _both(need, self.unary())
        return need

    def unary(self):
        if self.peek("kw", "NOT"):
            self.take()
            self.unary()
            return None
        if self.peek("op", "("):
            self.take()
            need = self.expr()
            self.take("op", ")")
            return need
        return self.comparison()

    def comparison(self):
        if not self.peek("ident"):
            return self.opaque()
        _, col = self.take("ident")
        tok = self.peek()
        if tok == ("op", "("):
            return self.opaque()             # a function call
        if tok == ("kw", "LIKE"):
            self.take()
            _, pat = self.take("str")
            escape = None
            if self.peek("kw", "ESCAPE"):
                self.take()
                _, escape = self.take("str")
            return _leaf(col, _like_literal(pat, escape or None))
        if tok == ("op", "="):
            self.take()
            if self.peek("str"):
                need = _leaf(col, self.take()[1])
                if need is not None:
                    need.exact = True
                return need
            self.take()                      # a number or a column: no literal
            return None
        if tok == ("kw", "IS"):
            self.take()
            if self.peek("kw", "NOT"):
                self.take()
            self.take("kw", "NULL")
            return None
        return self.opaque()

    def opaque(self):
        """An operand this reader does not understand (`COALESCE(...)`, `IN`,
        `REGEXP`): consumed up to the next AND/OR/`)` outside its own brackets,
        and worth nothing -- AND keeps its other side, OR and NOT give up."""
        depth = 0
        while self.i < len(self.t):
            k, v = self.t[self.i]
            if depth == 0 and ((k == "kw" and v in ("AND", "OR")) or (k, v) == ("op", ")")):
                break
            depth += {"(": 1, ")": -1}.get(v, 0) if k == "op" else 0
            self.i += 1


def _leaf(col: str, literal: str) -> Need | None:
    if len(literal) < MIN_LITERAL or not literal.isascii():
        return None
    return Need({col: frozenset([literal.lower()])})


def _either(a: Need | None, b: Need | None) -> Need | None:
    if a is None or b is None:
        return None
    out = Need(a)
    for col, lits in b.items():
        out[col] = out.get(col, frozenset()) | lits
    out.exact = a.exact or b.exact
    return out


def _weakest(need: Need) -> int:
    return min(len(x) for lits in need.values() for x in lits)


def _both(a: Need | None, b: Need | None) -> Need | None:
    if a is None:
        return b
    if b is None:
        return a
    # Either side alone is a valid necessary condition; keep text over an
    # equality, then the one whose shortest literal is longest (the rarer
    # text), then the one with fewer.
    ka = (not a.exact, _weakest(a), -sum(map(len, a.values())))
    kb = (not b.exact, _weakest(b), -sum(map(len, b.values())))
    return a if ka >= kb else b


def necessary(sql: str, columns=None) -> Need | None:
    """Per column, literals one of which every row this rule matches contains
    (lowered); None when the rule must see every row.

    With `columns` (the table's column names), each column the rule names is
    resolved to one of them as SQLite would -- without regard to case -- and a
    name that does not resolve (`web.message`, a column the table lacks) makes
    the rule read every row: dropping rows on a column the gate cannot see would
    drop that rule's matches in silence."""
    m = re.match(r"\s*SELECT\s+\*\s+FROM\s+\S+\s+WHERE\s+(.*)\Z", sql, re.DOTALL | re.IGNORECASE)
    if not m:
        return None
    toks = _tokens(m.group(1))
    if not toks:
        return None
    p = _Parser(toks)
    try:
        need = p.expr()
    except (ValueError, IndexError):
        return None
    if p.i != len(toks):
        return None
    if need is None or columns is None:
        return need
    by_fold = {c.casefold(): c for c in columns}
    resolved = Need()
    resolved.exact = need.exact
    for col, lits in need.items():
        name = by_fold.get(col.casefold())
        if name is None:
            return None
        resolved[name] = resolved.get(name, frozenset()) | lits
    return resolved


def trie_pattern(words) -> str:
    """One regex matching any of `words`, as a trie: `abc|abd` -> `ab(?:c|d)`.
    Python's `re` tries every branch of a flat alternation at every position;
    sharing prefixes leaves it one branch per first character. Measured on the
    126 literals of the web rules: 8.1 us -> 1.6 us per URI."""
    trie: dict = {}
    for w in words:
        node = trie
        for c in w:
            node = node.setdefault(c, {})
        node[""] = {}

    def build(node) -> str:
        ends = "" in node
        branches = [re.escape(c) + build(node[c]) for c in sorted(k for k in node if k)]
        if not branches:
            return ""
        body = branches[0] if len(branches) == 1 and not ends \
            else "(?:" + "|".join(branches) + ")"
        return body + "?" if ends else body

    return build(trie)


class Gate:
    """One pass/fail test per row for a set of rules: a row passes when any rule
    could match it. `columns` maps a column name to its index in the row."""

    def __init__(self, needs: list[Need], columns: dict[str, int]):
        merged: dict[str, set[str]] = {}
        for need in needs:
            for col, lits in need.items():
                merged.setdefault(col, set()).update(lits)
        self.checks = []
        for col, lits in sorted(merged.items()):
            if col not in columns:       # `necessary(sql, columns)` resolves them
                raise KeyError(f"prefilter column {col!r} is not in the table")
            rx = re.compile(trie_pattern(lits))
            self.checks.append((columns[col], rx.search))

    def __call__(self, row) -> bool:
        for i, search in self.checks:
            v = row[i]
            if v is not None and search(str(v).lower()):
                return True
        return False
