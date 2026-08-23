"""Searching a whole case for what one machine taught you."""
import sqlite3
from pathlib import Path

import pytest

from artifact_engine.core import sweep as S


def _machine(root: Path, name: str, rows: dict[str, list[tuple]]) -> Path:
    """A machine folder with the consolidated database `aeng run` leaves in it."""
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    db = d / f"{name}.db"
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE "evtx_Security" '
                 '("TimeCreated" TEXT, "RemoteHost" TEXT, "UserName" TEXT)')
    conn.execute('CREATE TABLE "amc_ProgramEntries" '
                 '("FullPath" TEXT, "SHA1" TEXT, "RunCount" INTEGER)')
    for table, values in rows.items():
        conn.executemany(f'INSERT INTO "{table}" VALUES (?,?,?)', values)
    conn.commit()
    conn.close()
    return db


@pytest.fixture
def case(tmp_path) -> Path:
    _machine(tmp_path, "HOST-01", {
        "evtx_Security": [("2026-03-14T08:21:00Z", "10.0.0.5", "CORP\\jdoe"),
                          ("2026-03-14T08:25:00Z", "10.0.0.50", "CORP\\other")],
        "amc_ProgramEntries": [(r"C:\Windows\Temp\bad.exe", "abc123", 3)]})
    _machine(tmp_path, "HOST-02", {
        "evtx_Security": [("2026-03-15T09:00:00Z", "10.0.0.50", "CORP\\svc")],
        "amc_ProgramEntries": [(r"C:\Users\Public\bad.exe", "abc123", 1)]})
    _machine(tmp_path, "HOST-03", {})
    return tmp_path


def test_an_address_does_not_match_a_longer_one(case):
    """`LIKE '%10.0.0.5%'` also matches 10.0.0.50, and that is not a near miss --
    it is a different host, named in a report. SQL does the coarse pass; the
    boundary check decides."""
    result = S.sweep(case, ["10.0.0.5"])
    assert [(h.machine, h.column) for h in result.hits] == [("HOST-01", "RemoteHost")]

    # and the longer one still finds itself, on both machines that carry it
    assert {h.machine for h in S.sweep(case, ["10.0.0.50"]).hits} == {"HOST-01", "HOST-02"}


def test_what_one_machine_taught_you_is_found_on_the_others(case):
    """The whole point: a hash learned on the machine being worked on, asked of the
    ones already finished, without re-parsing any of them."""
    result = S.sweep(case, ["abc123"])
    assert {h.machine for h in result.hits} == {"HOST-01", "HOST-02"}
    assert {h.table for h in result.hits} == {"amc_ProgramEntries"}
    # the paths differ, which is exactly the sort of thing a name-only search misses
    assert {h.context for h in S.sweep(case, ["bad.exe"]).hits} == {
        r"C:\Windows\Temp\bad.exe", r"C:\Users\Public\bad.exe"}


def test_a_machine_that_could_not_be_read_is_never_reported_as_clean(case):
    """The finding that matters more than the hits. A sweep over a case where one
    database is locked or corrupt has NOT established that machine is clean, and an
    answer that folds it in with the quiet ones is a false reassurance."""
    (case / "HOST-04").mkdir()
    (case / "HOST-04" / "HOST-04.db").write_bytes(b"not a database at all")

    result = S.sweep(case, ["abc123"])
    assert result.clean is False
    assert [m for m, _ in result.unreadable] == ["HOST-04"]
    assert "HOST-04" not in result.searched
    assert sorted(result.searched) == ["HOST-01", "HOST-02", "HOST-03"]


def test_a_case_that_reads_completely_says_so(case):
    result = S.sweep(case, ["abc123"])
    assert result.clean is True
    assert sorted(result.searched) == ["HOST-01", "HOST-02", "HOST-03"]


def test_every_hit_says_where_it_came_from(case):
    """A hit nobody can go and verify is worth nothing in a report."""
    hit = S.sweep(case, ["abc123"]).hits[0]
    assert hit.where() == f"{hit.machine}:amc_ProgramEntries.SHA1"
    assert hit.needle == "abc123"
    assert hit.context


def test_the_search_is_case_insensitive(case):
    """Accounts and hostnames arrive in whatever case the tool that wrote them
    used; the same account is not two accounts."""
    assert S.sweep(case, ["corp\\JDOE"]).hits
    assert S.sweep(case, ["BAD.EXE"]).hits


def test_the_cases_own_outputs_are_not_machines(tmp_path):
    """`case.db` and anything else at the root is the engine's view of the case,
    not a host. Sweeping it would report the case's own notes as evidence."""
    _machine(tmp_path, "HOST-01", {})
    (tmp_path / "case.db").write_bytes(b"")
    (tmp_path / "notes.db").write_bytes(b"")
    assert [label for label, _ in S.find_case_databases(tmp_path)] == ["HOST-01"]


def test_a_table_that_cannot_be_read_does_not_hide_the_rest(case, monkeypatch):
    """One corrupt page in an artifact nobody asked about must not turn into a
    silent zero for the whole machine."""
    real_connect = sqlite3.connect

    class Flaky:
        """A connection that fails on one table and works on the rest."""

        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *a, **kw):
            if 'FROM "evtx_Security"' in sql:
                raise sqlite3.DatabaseError("database disk image is malformed")
            return self._conn.execute(sql, *a, **kw)

        def __getattr__(self, name):
            return getattr(self._conn, name)

        def __setattr__(self, name, value):
            if name == "_conn":
                object.__setattr__(self, name, value)
            else:
                setattr(self._conn, name, value)

    monkeypatch.setattr(S.sqlite3, "connect",
                        lambda *a, **kw: Flaky(real_connect(*a, **kw)))
    result = S.sweep(case, ["abc123"])
    assert {h.machine for h in result.hits} == {"HOST-01", "HOST-02"}, \
        "a bad table took the readable ones with it"


def test_nothing_to_look_for_is_not_a_search(case):
    assert S.sweep(case, []).searched == []
    assert S.sweep(case, ["  "]).hits == []


def test_a_quoted_column_name_does_not_break_the_query(tmp_path):
    """Column names come from whatever an external tool called them: spaces, dots
    and the occasional quote. One of those in a table name is an injection into
    the query this builds."""
    d = tmp_path / "HOST-01"
    d.mkdir()
    conn = sqlite3.connect(d / "HOST-01.db")
    conn.execute('CREATE TABLE "weird ""table""" ("Event ID" TEXT, "a.b" TEXT)')
    conn.execute('INSERT INTO "weird ""table""" VALUES (?,?)', ("4624", "10.0.0.5"))
    conn.commit()
    conn.close()

    hits = S.sweep(tmp_path, ["10.0.0.5"]).hits
    assert [(h.table, h.column) for h in hits] == [('weird "table"', "a.b")]


def test_the_command_says_which_machines_it_could_not_search(case, caplog):
    """The console has to carry the same distinction the result does. An analyst
    reading "0 hits" and not seeing that two machines were skipped has been given
    a wrong answer, not an incomplete one."""
    import argparse
    import logging

    from artifact_engine import cli

    (case / "HOST-04").mkdir()
    (case / "HOST-04" / "HOST-04.db").write_bytes(b"not a database")

    with caplog.at_level(logging.INFO, logger="aeng"):
        rc = cli.cmd_sweep(argparse.Namespace(
            path=str(case), value=["abc123"], verbose=False))

    said = " ".join(r.message for r in caplog.records)
    assert "HOST-04" in said and "NOT searched" in said
    assert rc == cli.EXIT_INCOMPLETE, \
        "incomplete coverage must not exit clean: a script cannot see the warning"


def test_a_fully_covered_sweep_exits_clean(case):
    import argparse

    from artifact_engine import cli

    assert cli.cmd_sweep(argparse.Namespace(
        path=str(case), value=["abc123"], verbose=False)) == 0


def test_a_case_with_nothing_consolidated_is_an_error_not_an_empty_answer(tmp_path):
    """`aeng run` has not been run, or produced nothing. Reporting "0 hits" would
    say something about the case; there is nothing to say anything about yet."""
    import argparse

    from artifact_engine import cli

    assert cli.cmd_sweep(argparse.Namespace(
        path=str(tmp_path), value=["abc123"], verbose=False)) == 1
