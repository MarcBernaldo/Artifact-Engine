"""The indexes and views of a machine's `.db` (core/dbnav.py).

The `.db` is opened in a SQLite browser and worked there, so what these pin is
what that browser gets: a question by time that does not read the whole table, a
view that holds the same findings report.txt prints, and a logon whose type is a
word. And what it must not cost: a build, or a reader that lists tables. Every
value is invented.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from artifact_engine.core import consolidate, dbnav, findings, sweep
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.core.mcp_tools import Workspace


def _db(path: Path, tables: dict[str, tuple[list[str], list[tuple]]]) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    for name, (cols, rows) in tables.items():
        conn.execute(f'CREATE TABLE "{name}" ({", ".join(chr(34) + c + chr(34) for c in cols)})')
        conn.executemany(f'INSERT INTO "{name}" VALUES ({",".join("?" * len(cols))})', rows)
    conn.commit()
    return conn


def _plan(conn: sqlite3.Connection, sql: str) -> str:
    return " ".join(r[-1] for r in conn.execute("EXPLAIN QUERY PLAN " + sql))


def _indexes(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}


# --------------------------------------------------------------------------- #
# Indexes
# --------------------------------------------------------------------------- #
def test_a_big_table_is_asked_by_time_without_being_read_whole(tmp_path):
    conn = _db(tmp_path / "h.db", {
        "art_mft": (["FileName", "Created0x10", "LastModified0x10", "Created0x30"],
                    [(f"f{i}.txt", f"2026-05-{i % 28 + 1:02d} 10:00:00", "2026-05-01", "x")
                     for i in range(50)]),
        "art_users": (["user", "pw_changed_utc"], [("jdoe", "2026-05-01")] * 5),
    })
    made = dbnav.create_indexes(conn, min_rows=20)

    assert made == 3
    assert _indexes(conn) == {"ix_art_mft_Created0x10", "ix_art_mft_LastModified0x10",
                              "ix_art_mft_FileName"}, "the small table and the 0x30 time stay bare"
    by_time = 'SELECT * FROM art_mft WHERE "Created0x10" >= \'2026-05-10\' ORDER BY "Created0x10"'
    assert "USING INDEX ix_art_mft_Created0x10" in _plan(conn, by_time)
    assert "USING INDEX ix_art_mft_FileName" in _plan(
        conn, "SELECT * FROM art_mft WHERE FileName = 'f1.txt'")


def test_an_event_log_is_asked_by_event_id(tmp_path):
    conn = _db(tmp_path / "h.db", {"art_evtx_security": (
        ["TimeCreated", "EventId"], [("2026-05-01 10:00:00", 4624)] * 30)})
    dbnav.create_indexes(conn, min_rows=20)
    assert _indexes(conn) == {"ix_art_evtx_security_TimeCreated", "ix_art_evtx_security_EventId"}


@pytest.mark.parametrize("cols, want", [
    # as logged AND that moment in UTC: asked by the second
    (["timestamp", "timestamp_utc", "user"], ["timestamp_utc"]),
    # a bodyfile is asked by all four
    (["path", "atime_utc", "mtime_utc", "ctime_utc", "crtime_utc"],
     ["atime_utc", "mtime_utc", "ctime_utc", "crtime_utc"]),
    # the offset is in the value: no suffix, still the time column
    (["timestamp", "source_ip", "uri"], ["timestamp"]),
    # only a local clock to go by
    (["timestamp_local", "package"], ["timestamp_local"]),
    (["vector", "detail", "suspicious"], []),
])
def test_which_columns_are_time(cols, want):
    assert dbnav.time_columns(cols) == want


def test_an_index_that_cannot_be_made_costs_only_itself(tmp_path):
    """One table SQLite refuses must not take the next table's index with it."""
    conn = _db(tmp_path / "h.db", {
        "art_a": (["timestamp_utc"], [("2026-05-01",)] * 30),
        "art_b": (["timestamp_utc"], [("2026-05-01",)] * 30),
    })
    conn.execute('CREATE TABLE "ix_art_a_timestamp_utc" (x)')     # the name is taken
    assert dbnav.create_indexes(conn, min_rows=20) == 1
    assert "ix_art_b_timestamp_utc" in _indexes(conn)


# --------------------------------------------------------------------------- #
# v_alerts
# --------------------------------------------------------------------------- #
@pytest.fixture
def machine_db(tmp_path) -> Path:
    path = tmp_path / "HOST-01.db"
    _db(path, {
        "alert_win_sigma": (["level", "rule", "first_seen", "match"], [
            ("medium", "Rule B", "2026-05-02 09:00:00", "b.exe"),
            ("critical", "Rule A", "2026-05-01 08:00:00", "a.exe"),
            ("low", "Rule C", "2026-05-03 07:00:00", "c.exe"),
            ("informational", "Rule D", "2026-05-03 07:00:00", "d.exe"),
        ]),
        "art_persistence": (["vector", "detail", "suspicious"], [
            ("run key", "C:\\Users\\jdoe\\x.exe", "yes"), ("service", "spooler", None),
        ]),
        # every row a finding, and neither column to say so
        "alert_rmm": (["tool", "path", "first_seen_utc"], [
            ("ExampleDesk", "C:\\Tools\\ed.exe", "2026-05-04 06:00:00"),
        ]),
        # `Level` here is the event's log level, not a rating
        "art_evtx_system": (["TimeCreated", "Level", "EventId"], [("2026-05-01", "high", 7045)]),
        "art_mft": (["FileName", "Created0x10"], [("a.txt", "2026-05-01")]),
        # both columns: a flagged row that is also rated sits in its rating, once
        "alert_hayabusa": (["level", "rule", "hits", "suspicious"], [
            ("high", "Rule H", 3, "yes"), ("low", "Rule L", 9, None),
            ("informational", "Rule I", 1, "yes"), ("info", "Rule J", 1, None),
        ]),
    }).close()
    return path


def test_v_alerts_holds_every_finding_most_severe_first(machine_db):
    conn = sqlite3.connect(machine_db)
    assert dbnav.create_views(conn) == ["v_alerts", "v_timeline"]
    rows = conn.execute("SELECT priority, level, source_table, source_rowid, rule, "
                        "timestamp, summary FROM v_alerts").fetchall()

    assert [(r[1], r[2]) for r in rows] == [
        ("critical", "alert_win_sigma"), ("high", "alert_hayabusa"),
        ("flagged", "alert_hayabusa"), ("flagged", "alert_rmm"),
        ("flagged", "art_persistence"), ("medium", "alert_win_sigma"),
        ("low", "alert_hayabusa"), ("low", "alert_win_sigma")], \
        "no informational row, no log level, no bare artifact"
    assert [r[0] for r in rows] == sorted(r[0] for r in rows)
    crit = rows[0]
    assert (crit[4], crit[5], crit[6]) == ("Rule A", "2026-05-01 08:00:00", "a.exe")
    assert rows[4][6] == "run key | C:\\Users\\jdoe\\x.exe"

    # the pointer is the row itself
    table, rowid = crit[2], crit[3]
    assert conn.execute(f'SELECT match FROM "{table}" WHERE rowid = ?',
                        (rowid,)).fetchone() == ("a.exe",)


def test_v_alerts_and_the_report_count_the_same_rows(machine_db):
    """Two front pages reading two definitions of a finding would disagree in
    front of the analyst. Table by table, tier by tier, they are one count."""
    conn = sqlite3.connect(machine_db)
    dbnav.create_views(conn)
    view = dict(conn.execute(
        "SELECT source_table || '/' || level, COUNT(*) FROM v_alerts GROUP BY 1"))
    report = {}
    for t in findings.collect(machine_db).tables:
        for _, label, _ in t.rows:
            key = f"{t.table}/{label}"
            report[key] = report.get(key, 0) + 1

    assert report and all(view.get(k) == n for k, n in report.items()), (view, report)
    # ...and the view adds only what the prefix promises: an alert_ table
    assert set(view) - set(report) == {"alert_rmm/flagged"}


def test_an_alert_table_with_a_level_that_is_no_rating_is_left_as_the_report_leaves_it(tmp_path):
    """`alert_` with NEITHER column is all findings. With a `level` the report
    cannot read as a rating it is not "neither": listed whole as flagged, the
    rows its parser called low or informational would sit above every medium."""
    conn = _db(tmp_path / "h.db", {
        "alert_odd": (["level", "what"], [("informational", "a"), ("warning", "b"), ("low", "c")]),
        "alert_ok": (["level", "what"], [("high", "d")]),
    })
    dbnav.create_views(conn)
    assert conn.execute("SELECT source_table, level FROM v_alerts").fetchall() \
        == [("alert_ok", "high")]
    assert "alert_odd" in findings.collect(tmp_path / "h.db").unflagged


def test_a_table_with_its_own_rowid_column_keeps_a_true_pointer(tmp_path):
    """SQLite gives a column named `rowid` precedence over the row number. An
    external tool's table that has one must not have it read as the pointer, nor
    as the number of rows -- a text value there once ended the whole build."""
    conn = _db(tmp_path / "h.db", {
        "art_ext": (["RowId", "timestamp_utc", "what", "suspicious"],
                    [(f"a-{i}", "2026-05-01", f"w{i}", "yes" if i == 7 else None)
                     for i in range(30)]),
    })
    assert dbnav.create_indexes(conn, min_rows=20) == 1
    dbnav.create_views(conn)
    (pointer,) = conn.execute("SELECT source_rowid FROM v_alerts").fetchone()
    assert pointer == 8
    assert conn.execute("SELECT what FROM art_ext WHERE _rowid_ = ?",
                        (pointer,)).fetchone() == ("w7",)


def test_the_hayabusa_timeline_is_not_listed_beside_its_aggregate(tmp_path):
    conn = _db(tmp_path / "h.db", {
        "alert_hayabusa": (["level", "rule", "hits"], [("high", "Rule A", 3)]),
        "alert_hayabusa_timeline": (["Timestamp", "Level", "RuleTitle"],
                                    [("2026-05-01", "high", "Rule A")] * 3),
    })
    dbnav.create_views(conn)
    assert conn.execute("SELECT source_table, COUNT(*) FROM v_alerts GROUP BY 1").fetchall() \
        == [("alert_hayabusa", 1)]


def test_one_table_sqlite_refuses_costs_its_rows_not_the_view(tmp_path, monkeypatch):
    conn = _db(tmp_path / "h.db", {
        "alert_a": (["level", "rule"], [("high", "Rule A")]),
        "alert_b": (["level", "rule"], [("high", "Rule B")]),
    })
    real = dbnav._alert_select
    monkeypatch.setattr(dbnav, "_alert_select", lambda c, t: (
        "SELECT no_such_column FROM alert_a" if t == "alert_a" else real(c, t)))
    assert dbnav.create_views(conn) == ["v_alerts", "v_timeline"]
    assert conn.execute("SELECT source_table FROM v_alerts").fetchall() == [("alert_b",)]


def test_a_machine_with_no_finding_column_gets_no_empty_view(tmp_path):
    conn = _db(tmp_path / "h.db", {"art_mft": (["FileName"], [("a.txt",)])})
    assert dbnav.create_views(conn) == []


# --------------------------------------------------------------------------- #
# v_logons
# --------------------------------------------------------------------------- #
def test_a_windows_logon_reads_its_type_as_a_word(tmp_path):
    cols = ["TimeCreated", "EventId", "Computer", "UserName", "RemoteHost",
            "PayloadData1", "PayloadData2"]
    conn = _db(tmp_path / "h.db", {"art_evtx_security": (cols, [
        ("2026-05-01 10:00:00", 4624, "HOST-01", "EXAMPLE\\jdoe", "WS-07 (10.0.0.5)",
         "Target: EXAMPLE\\jdoe", "LogonType 10"),
        ("2026-05-01 11:00:00", 4625, "HOST-01", "EXAMPLE\\admin", "- (10.0.0.9)",
         "Target: EXAMPLE\\admin", "LogonType 3"),
        ("2026-05-01 12:00:00", 4672, "HOST-01", "EXAMPLE\\jdoe", "", "", ""),
    ])})
    assert dbnav.create_views(conn) == ["v_logons", "v_timeline"]
    rows = conn.execute("SELECT timestamp_utc, result, event, logon_type, logon, user, "
                        "source_address, host, source_table, source_rowid FROM v_logons").fetchall()
    assert rows == [
        ("2026-05-01 11:00:00", "failed", "failed logon", 3, "network", "EXAMPLE\\admin",
         "- (10.0.0.9)", "HOST-01", "art_evtx_security", 2),
        ("2026-05-01 10:00:00", "ok", "logon", 10, "remote interactive (RDP)",
         "EXAMPLE\\jdoe", "WS-07 (10.0.0.5)", "HOST-01", "art_evtx_security", 1),
    ], "newest first, and 4672 is not a logon"


def test_a_linux_logon_has_the_same_columns(tmp_path):
    cols = ["timestamp_utc", "timestamp_local", "end_local", "result", "type", "user",
            "tty", "source_address", "source", "source_file"]
    conn = _db(tmp_path / "h.db", {"art_logins": (cols, [
        ("2026-05-01 10:00:00", "", "", "ok", "", "jdoe", "pts/0", "10.0.0.5", "wtmp", "x"),
        ("2026-05-01 09:00:00", "", "", None, "BOOT_TIME", "reboot", "~", "", "wtmp", "x"),
    ])})
    dbnav.create_views(conn)
    assert conn.execute("SELECT timestamp_utc, result, event, user, source_address, detail, "
                        "source_table FROM v_logons").fetchall() == [
        ("2026-05-01 10:00:00", "ok", "wtmp", "jdoe", "10.0.0.5", "pts/0", "art_logins")]
    # a boot is in the same table and is not a logon


# --------------------------------------------------------------------------- #
# The timeline (AE-046)
# --------------------------------------------------------------------------- #
def _timeline(conn) -> list[tuple]:
    return conn.execute("SELECT time_utc, kind, source_table, source_rowid, summary "
                        "FROM v_timeline").fetchall()


def test_the_timeline_puts_alerts_logons_and_programs_in_one_utc_order(tmp_path):
    conn = _db(tmp_path / "h.db", {
        # hayabusa's form: a space, then the offset -- 10:30 at +02:00 is 08:30 UTC
        "alert_win_sigma": (["level", "rule", "first_seen", "match"], [
            ("high", "Rule A", "2026-05-01 10:30:00.123 +02:00", "a.exe")]),
        "art_evtx_security": (["TimeCreated", "EventId", "UserName", "RemoteHost",
                               "PayloadData2"], [
            ("2026-05-01T08:00:00.1234567Z", 4624, "EXAMPLE\\jdoe", "10.0.0.5", "LogonType 10")]),
        "art_prefetch": (["ExecutableName", "RunCount", "LastRun", "FilesLoaded"], [
            ("EVIL.EXE", "2", "2026-05-01 08:15:00", "x")]),
        "art_service_installs": (["timestamp_utc", "service_name", "path", "runas"], [
            ("2026-05-01 09:00:00", "ExampleSvc", "C:\\Windows\\Temp\\s.exe", "LocalSystem")]),
        "art_mft": (["FileName", "Created0x10"], [("a.txt", "2026-05-01 08:20:00")]),
    })
    dbnav.create_views(conn)
    assert _timeline(conn) == [
        ("2026-05-01 08:00:00", "logon", "art_evtx_security", 1,
         "EXAMPLE\\jdoe | remote interactive (RDP) | 10.0.0.5 | ok"),
        ("2026-05-01 08:15:00", "execution (prefetch)", "art_prefetch", 1, "EVIL.EXE | 2"),
        ("2026-05-01 08:30:00", "alert high", "alert_win_sigma", 1, "Rule A | a.exe"),
        ("2026-05-01 09:00:00", "service install", "art_service_installs", 1,
         "ExampleSvc | C:\\Windows\\Temp\\s.exe | LocalSystem"),
    ], "the MFT is not a source: the timeline points at an hour, the indexes do the rest"


def test_a_linux_logon_is_a_logon_in_the_timeline_not_the_file_it_came_from(tmp_path):
    cols = ["timestamp_utc", "result", "type", "user", "tty", "source_address", "source"]
    conn = _db(tmp_path / "h.db", {"art_logins": (cols, [
        ("2026-05-01 10:00:00", "ok", "", "jdoe", "pts/0", "10.0.0.5", "wtmp"),
        ("2026-05-01 11:00:00", "failed", "", "root", "ssh", "10.0.0.9", "btmp")])})
    dbnav.create_views(conn)
    assert [(r[1], r[4]) for r in _timeline(conn)] == [
        ("logon", "jdoe | 10.0.0.5 | ok"), ("failed logon", "root | 10.0.0.9 | failed")]


def test_a_time_that_is_local_empty_or_unset_stays_out_of_the_timeline(tmp_path):
    conn = _db(tmp_path / "h.db", {
        # a table whose only time is the host's clock would sort hours away
        "alert_rmm": (["tool", "seen_local"], [("ExampleDesk", "2026-05-01 12:00:00")]),
        "art_shell_history": (["user", "timestamp_utc", "command_line"], [
            ("jdoe", "2026-05-01 07:00:00", "id"), ("jdoe", "", "whoami"),
            ("jdoe", "1601-01-01 00:00:00", "uname -a"), ("jdoe", "not a time", "ls")]),
    })
    dbnav.create_views(conn)
    assert _timeline(conn) == [
        ("2026-05-01 07:00:00", "shell command", "art_shell_history", 1, "jdoe | id")]


def test_a_machine_with_nothing_dated_gets_no_timeline(tmp_path):
    conn = _db(tmp_path / "h.db", {"art_mft": (["FileName", "Created0x10"], [("a", "2026")]),
                                   "art_prefetch": (["ExecutableName"], [("X.EXE",)])})
    assert dbnav.create_views(conn) == []


def test_a_timeline_source_sqlite_refuses_costs_its_rows_not_the_view(tmp_path, monkeypatch):
    conn = _db(tmp_path / "h.db", {
        "art_packages": (["name", "version", "install_time_utc"], [("pkg", "1", "2026-05-01")]),
        "art_log_cron": (["timestamp_utc", "kind", "user", "detail"],
                         [("2026-05-02 00:00:00", "run", "root", "job")]),
    })
    real = dbnav._summary_sql
    monkeypatch.setattr(dbnav, "_summary_sql",
                        lambda cols, skip: "no_such_col" if "name" in cols else real(cols, skip))
    assert dbnav.create_views(conn) == ["v_timeline"]
    assert [r[2] for r in _timeline(conn)] == ["art_log_cron"]


# --------------------------------------------------------------------------- #
# In a real build, and what it must not disturb
# --------------------------------------------------------------------------- #
def _machine(tmp_path: Path, rows: int = 30) -> Machine:
    base = tmp_path / "HOST-01"
    files = {
        "EventLogs/art_evtx_security.csv":
            "TimeCreated,EventId,Computer,UserName,RemoteHost,PayloadData1,PayloadData2\n"
            + "".join(f"2026-05-01 10:{i:02d}:00,4624,HOST-01,EXAMPLE\\jdoe,WS-07 (10.0.0.5),"
                      f"Target: EXAMPLE\\jdoe,LogonType 3\n" for i in range(rows)),
        "Detections/alert_win_sigma.csv": "level,rule,first_seen,match\nhigh,Rule A,2026-05-01,a.exe\n",
    }
    for rel, text in files.items():
        f = base / "CSVs" / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    return Machine("HOST-01", "windows", "kape", "windows_kape", base, "acq",
                   [Volume("C", base, True)])


def _objects(db: Path, kind: str) -> set[str]:
    conn = sqlite3.connect(db)
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = ?", (kind,))}
    finally:
        conn.close()


def test_a_built_database_has_its_views_and_indexes(tmp_path, monkeypatch):
    monkeypatch.setattr(dbnav, "INDEX_MIN_ROWS", 20)
    monkeypatch.setattr(dbnav.create_indexes, "__defaults__", (20,))
    m = _machine(tmp_path)
    assert consolidate.build(m, emit_xlsx=False) == []
    db = tmp_path / "HOST-01" / "HOST-01.db"

    assert _objects(db, "view") == {"v_alerts", "v_logons", "v_timeline"}
    assert _objects(db, "index") == {"ix_art_evtx_security_TimeCreated",
                                     "ix_art_evtx_security_EventId"}
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*), MIN(logon) FROM v_logons").fetchone() == (30, "network")
    conn.close()


def test_db_indexes_false_keeps_the_views_and_rebuilds_the_unit(tmp_path, monkeypatch):
    monkeypatch.setattr(dbnav.create_indexes, "__defaults__", (20,))
    unit = consolidate.plan_units([(_machine(tmp_path), [])])[0][0]
    db = unit.output(".db")

    consolidate.build_unit(unit, emit_xlsx=False)
    assert _objects(db, "index")
    assert consolidate.build_unit(unit, emit_xlsx=False).get("cached")

    st = consolidate.build_unit(unit, emit_xlsx=False, db_indexes=False)
    assert not st.get("cached"), "the setting changes the output: a marker must not hide it"
    assert _objects(db, "index") == set()
    assert _objects(db, "view") == {"v_alerts", "v_logons", "v_timeline"}


def test_a_host_merged_with_its_snapshots_gets_them_too(tmp_path, monkeypatch):
    """The merged build is its own code path, with a VACUUM at the end of it."""
    monkeypatch.setattr(dbnav.create_indexes, "__defaults__", (20,))
    machines = []
    for label in ("C", "VSS1"):
        m = _machine(tmp_path / label)
        live = label == "C"
        base = tmp_path / "acq" / label
        base.parent.mkdir(exist_ok=True)
        m.path.rename(base)
        machines.append(Machine("HOST" if live else f"HOST_{label}", "windows", "kape",
                                "windows_kape", base, "acq", [Volume(label, base, live)],
                                is_vss=not live))
    units = consolidate.plan_units([(m, []) for m in machines], merge_vss=True)
    assert len(units) == 1 and units[0][0].merged
    unit = units[0][0]

    consolidate.build_unit(unit, emit_xlsx=False)
    db = unit.output(".db")
    assert _objects(db, "view") == {"v_alerts", "v_logons", "v_timeline"}
    assert "ix_art_evtx_security_TimeCreated" in _objects(db, "index")


class _NoRoomToVacuum(sqlite3.Connection):
    def execute(self, sql, *args):
        if str(sql).strip().upper() == "VACUUM":
            raise sqlite3.OperationalError("database or disk is full")
        return super().execute(sql, *args)


def test_a_vacuum_with_no_room_costs_file_size_not_the_views(tmp_path, monkeypatch):
    monkeypatch.setattr(dbnav.create_indexes, "__defaults__", (20,))
    machines = []
    for label in ("C", "VSS1"):
        m = _machine(tmp_path / label)
        base = tmp_path / "acq" / label
        base.parent.mkdir(exist_ok=True)
        m.path.rename(base)
        machines.append(Machine("HOST" if label == "C" else f"HOST_{label}", "windows", "kape",
                                "windows_kape", base, "acq",
                                [Volume(label, base, label == "C")], is_vss=label != "C"))
    unit = consolidate.plan_units([(m, []) for m in machines], merge_vss=True)[0][0]
    real = sqlite3.connect
    monkeypatch.setattr(consolidate.sqlite3, "connect",
                        lambda path, *a, **k: real(path, *a, factory=_NoRoomToVacuum, **k))

    consolidate.build_unit(unit, emit_xlsx=False)
    monkeypatch.undo()
    db = unit.output(".db")
    assert _objects(db, "view") == {"v_alerts", "v_logons", "v_timeline"}
    assert "ix_art_evtx_security_TimeCreated" in _objects(db, "index")


def test_running_out_of_memory_on_an_index_does_not_cost_the_database(tmp_path, monkeypatch):
    """SQLite out of memory is a MemoryError, not a sqlite3.Error."""
    def boom(conn, min_rows=0):
        raise MemoryError
    monkeypatch.setattr(dbnav, "create_indexes", boom)
    m = _machine(tmp_path)

    assert consolidate.build(m, emit_xlsx=False) == []
    db = tmp_path / "HOST-01" / "HOST-01.db"
    assert _objects(db, "view") == {"v_alerts", "v_logons", "v_timeline"}


def test_an_index_is_sorted_on_disk_not_in_memory(tmp_path):
    conn = _db(tmp_path / "h.db", {"art_a": (["timestamp_utc"], [("2026-05-01",)] * 3)})
    conn.execute("PRAGMA temp_store=MEMORY")
    dbnav.finish(conn)
    assert conn.execute("PRAGMA temp_store").fetchone()[0] == 1       # 1 = FILE


def test_a_view_that_cannot_be_made_does_not_cost_the_database(tmp_path, monkeypatch):
    def boom(conn):
        raise sqlite3.OperationalError("no such luck")
    monkeypatch.setattr(dbnav, "_alerts_view", boom)
    m = _machine(tmp_path)

    assert consolidate.build(m, emit_xlsx=False) == []
    db = tmp_path / "HOST-01" / "HOST-01.db"
    assert _objects(db, "view") == {"v_logons", "v_timeline"}
    assert "alert_win_sigma" in _objects(db, "table")


def test_the_readers_of_a_database_see_tables_only(tmp_path):
    """A view restates rows a table holds. Counted by the report, searched by a
    sweep or written as a sheet, each of those rows would be there twice."""
    m = _machine(tmp_path)
    consolidate.build(m)                                   # the .xlsx too
    db = tmp_path / "HOST-01" / "HOST-01.db"

    got = findings.collect(db)
    assert {t.table for t in got.tables} | set(got.unflagged) == {"alert_win_sigma",
                                                                 "art_evtx_security"}
    hits, why, _ = sweep.sweep_database("HOST-01", db, ["a.exe"])
    assert why == "" and {h.table for h in hits} == {"alert_win_sigma"}

    import openpyxl
    book = openpyxl.load_workbook(tmp_path / "HOST-01" / "HOST-01.xlsx", read_only=True)
    assert set(book.sheetnames) == {"alert_win_sigma", "art_evtx_security"}


def test_an_assistant_can_read_a_view_through_the_mcp_tools(tmp_path):
    case = tmp_path / "cases" / "CASE-01"
    m = _machine(case)
    consolidate.build(m, emit_xlsx=False)
    (case / "HOST-01" / "report.txt").write_text("LOG COVERAGE", encoding="utf-8")
    ws = Workspace([tmp_path / "cases"])

    res = ws.query("CASE-01", "HOST-01", "SELECT level, rule FROM v_alerts")
    assert res["rows"] == [["high", "Rule A"]]
