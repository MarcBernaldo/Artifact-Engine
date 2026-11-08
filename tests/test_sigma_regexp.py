"""The Sigma `|re` modifier compiles to SQLite REGEXP, which SQLite lacks.

Until v0.7.191 every rule using it failed with "no such function" and matched
nothing, in every Sigma parser (they all run rules through lin_sigma._run_rule).
"""

from __future__ import annotations

import sqlite3

import pytest

from artifact_engine.core.sigma_engine import _retable
from artifact_engine.handlers.lin_sigma import _run_rule

backends = pytest.importorskip("sigma.backends.sqlite")
from sigma.collection import SigmaCollection

RULE = """title: regex rule
id: 6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b
status: test
logsource: {product: windows, category: process_creation}
detection:
    sel:
        CommandLine|re: '-e(nc|ncodedcommand)?\\s+[A-Za-z0-9+/=]{8,}'
    condition: sel
level: high
"""


def _sql() -> str:
    q = backends.sqlite.sqliteBackend().convert(SigmaCollection.from_yaml(RULE))[0]
    return _retable(q, "proc")      # backend 1.x says <TABLE_NAME>, 2.x says logs


def test_re_modifier_matches():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE proc (CommandLine TEXT)")
    conn.executemany("INSERT INTO proc VALUES (?)", [
        ("powershell.exe -enc SQBFAFgAKABOAGUAdwA=",),
        ("powershell.exe -File C:\\scripts\\backup.ps1",),
        (None,),
    ])
    cols, rows = _run_rule(conn, _sql())
    assert [r[cols.index("CommandLine")] for r in rows] == ["powershell.exe -enc SQBFAFgAKABOAGUAdwA="]


def test_bad_pattern_matches_nothing_instead_of_failing():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (x TEXT)")
    conn.execute("INSERT INTO t VALUES ('abc')")
    assert _run_rule(conn, "SELECT * FROM t WHERE x REGEXP '([unclosed'")[1] == []
    assert _run_rule(conn, "SELECT * FROM t WHERE x REGEXP 'b'")[1] == [("abc",)]
