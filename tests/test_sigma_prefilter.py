"""The prefilter web_sigma derives from its own rules (v0.7.109). All traffic is synthetic."""

import itertools
import re
import sqlite3

import pytest

from artifact_engine.core import sigma_engine
from artifact_engine.core import sigma_prefilter as P
from artifact_engine.handlers import lin_web_sigma as W

_COLS = {c: i for i, c in enumerate(W._COLS)}


def _rules():
    sigma_engine.load_web_rules.cache_clear()
    rules = sigma_engine.load_web_rules()
    if not rules:
        pytest.skip("pysigma or the bundled web ruleset is unavailable")
    return rules


def _fill(pattern: str) -> str:
    """A string a LIKE pattern matches: wildcards filled, escapes resolved."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            out.append(pattern[i + 1])
            i += 2
            continue
        out.append("x" if c in "%_" else c)
        i += 1
    return "".join(out)


def _row(text, method, status, ua, referer):
    row = [None] * len(W._COLS)
    for col in ("message", "cs-uri", "c-uri", "cs-uri-query", "c-uri-query", "x_uri"):
        row[_COLS[col]] = text
    row[_COLS["cs-uri-stem"]] = "/x"
    row[_COLS["cs-method"]] = row[_COLS["x_method"]] = method
    row[_COLS["sc-status"]] = status
    row[_COLS["cs-user-agent"]] = row[_COLS["c-useragent"]] = ua
    row[_COLS["cs-referer"]] = referer
    row[_COLS["x_ip"]] = "10.0.0.5"
    return row


def test_every_row_a_bundled_rule_matches_passes_the_gate():
    """The guarantee: the gate never drops a row some rule would have matched.
    Each rule is fed rows built from its own patterns (all of them at once, so an
    AND of two LIKEs is satisfied), in every method/status/UA/referer shape the
    rules test, and every row it matches must pass the gate built from it."""
    rules = _rules()
    q = lambda c: "`" + c + "`"
    for r in rules:
        texts = [_fill(p.replace("''", "'")) for p in re.findall(r"LIKE '((?:[^']|'')*)'", r.sql)]
        assert texts, r.title
        text = " ".join(texts)
        rows = [_row(t, m, s, ua, ref) for t, m, s, ua, ref in itertools.product(
            [text, text.upper()], ["GET", "POST", "OPTIONS"], [200, 301, 404],
            [None, text], [None, "-x"])]
        conn = sqlite3.connect(":memory:")
        conn.execute(f"CREATE TABLE web ({', '.join(q(c) for c in W._COLS)})")
        conn.executemany(f"INSERT INTO web VALUES ({', '.join('?' * len(W._COLS))})", rows)
        cols, matches = W._run_rule(conn, r.sql)
        conn.close()
        assert matches, f"{r.title}: the synthetic rows should exercise it"
        need = P.necessary(r.sql, W._COLS)
        assert need is not None, f"{r.title} reads every row (fine, but say so here)"
        gate = P.Gate([need], _COLS)
        for m in matches:
            row = [m[cols.index(c)] if c in cols else None for c in W._COLS]
            assert gate(row), f"{r.title}: a match the gate would drop"


def test_benign_traffic_does_not_pass_the_gate():
    rules = _rules()
    gate = P.Gate([n for r in rules if (n := P.necessary(r.sql, W._COLS)) is not None], _COLS)
    benign = ["/index.php?id=42", "/wp-admin/admin-ajax.php?action=heartbeat",
              "/static/app.js?v=3", "/search?q=hello+world&page=2"]
    for uri in benign:
        assert not gate(_row(uri, "GET", 200, "Mozilla/5.0 (Windows NT 10.0)", None)), uri


@pytest.mark.parametrize("where, expected", [
    ("message LIKE '%abc%' ESCAPE '\\'", {"message": {"abc"}}),
    ("message LIKE '%a\\%2Fb%' ESCAPE '\\'", {"message": {"a%2fb"}}),           # escape kept
    ("message LIKE '%ab%cdef%' ESCAPE '\\'", {"message": {"cdef"}}),            # longest run
    ("a LIKE '%abcd%' OR b LIKE '%efgh%'", {"a": {"abcd"}, "b": {"efgh"}}),
    ("a LIKE '%abcd%' OR b IS NULL", None),                                    # OR of nothing
    ("NOT a LIKE '%abcd%'", None),
    ("a LIKE '%ab%'", None),                                                   # too short
    ("a LIKE '%été%'", None),                                        # not ASCII
    ("`cs-method`='GET' AND x LIKE '%abc%'", {"x": {"abc"}}),                  # text over =
    ("`cs-method`='POST' AND (`sc-status`=200)", {"cs-method": {"post"}}),
    ("a LIKE '%abcd%' AND (NOT b LIKE '%z%')", {"a": {"abcd"}}),
    ("a REGEXP 'abcd'", None),                                                 # not understood
    ("a LIKE '%abcd%' AND (NOT COALESCE((`sc-status`=404), 0))",               # pySigma 1.x
     {"a": {"abcd"}}),
    ("a LIKE '%abcd%' OR COALESCE(b, 'efgh') = 'efgh'", None),                 # OR of nothing
    ("a IN ('abcd', 'efgh') AND b LIKE '%wxyz%'", {"b": {"wxyz"}}),
    ("a BETWEEN 1 AND 5", None),
    ("a LIKE '%it''s%'", {"a": {"it's"}}),
])
def test_what_a_clause_requires(where, expected):
    need = P.necessary(f"SELECT * FROM web WHERE {where}")
    assert (None if need is None else {k: set(v) for k, v in need.items()}) == expected


def test_the_trie_matches_exactly_what_the_alternation_does():
    words = ["abc", "abd", "ab", "x%2f", "=${", "={{"]
    rx = re.compile(P.trie_pattern(words))
    for s in ["zzabzz", "abd", "a", "x%2", "q=${x", "={", "x%2fy", ""]:
        assert bool(rx.search(s)) == any(w in s for w in words), s


def test_the_handler_finds_the_same_with_and_without_the_gate(tmp_path, monkeypatch):
    import csv
    import io
    import logging

    from artifact_engine.core.runner import ParserContext
    _rules()
    lines = [
        '10.0.0.5 - - [10/Oct/2026:13:00:01 +0000] "GET /s?q=%271%27%3D%271 HTTP/1.1" 200 1 "-" "Mozilla"',
        '10.0.0.6 - - [10/Oct/2026:13:00:02 +0000] "GET /.git/config HTTP/1.1" 404 1 "-" "curl/8"',
        '10.0.0.7 - - [10/Oct/2026:13:00:03 +0000] "GET /a?f=../../../etc/passwd HTTP/1.1" 200 1 "-" "x"',
        '10.0.0.8 - - [10/Oct/2026:13:00:04 +0000] "GET / HTTP/1.1" 200 1 "-" "WPScan v3.8"',
        '10.0.0.9 - - [10/Oct/2026:13:00:05 +0000] "GET /index.php?id=7 HTTP/1.1" 200 1 "-" "Mozilla"',
    ] * 3
    ap = tmp_path / "[root]" / "var" / "log" / "apache2"
    ap.mkdir(parents=True)
    (ap / "access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def run(out):
        W.run(ParserContext(evidence=tmp_path, out=out, tools=tmp_path, assets=tmp_path,
                            machine_name="HOST-01", volume="live",
                            log=logging.getLogger("aeng.test")))
        return sorted(map(tuple, csv.reader(io.StringIO(
            (out / "alert_web.csv").read_text(encoding="utf-8")))))

    gated = run(tmp_path / "gated")
    monkeypatch.setattr(W, "necessary", lambda sql, cols: None)       # every rule, every row
    assert gated == run(tmp_path / "ungated")
    assert len(gated) == 5                  # the header and four rules


@pytest.mark.parametrize("where, expected", [
    ("`CS-URI-QUERY` LIKE '%union select%'", {"cs-uri-query": {"union select"}}),
    ("Message LIKE '%union select%'", {"message": {"union select"}}),
    ("web.message LIKE '%union select%'", None),                 # not resolved: every row
    ("`cs-host` LIKE '%abcd%' OR nosuch LIKE '%efgh%'", None),
])
def test_a_column_resolves_as_sqlite_would_or_the_rule_sees_every_row(where, expected):
    need = P.necessary(f"SELECT * FROM web WHERE {where}", W._COLS)
    assert (None if need is None else {k: set(v) for k, v in need.items()}) == expected
    if need is not None:
        row = [None] * len(W._COLS)
        row[_COLS[next(iter(need))]] = "id=1 UNION SELECT 1"
        assert P.Gate([need], _COLS)(row)
