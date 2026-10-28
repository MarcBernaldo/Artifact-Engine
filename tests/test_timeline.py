"""v0.7.172: the `timeline` view of a machine's .db -- every row whose time is
known to be UTC, from every table, in one shape. Synthetic tables only."""
from __future__ import annotations

import sqlite3

from artifact_engine.core import consolidate, timeline
from artifact_engine.core.detector import Machine, Volume


def _db() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE art_log_auth (timestamp, time_utc, event, user, source, detail,"
              " suspicious)")
    c.executemany("INSERT INTO art_log_auth VALUES (?,?,?,?,?,?,?)", [
        ("May 24 00:06:48", "2026-05-24 00:06:48", "ssh_accepted", "root", "10.0.0.9", "", ""),
        ("May 24 00:07:00", "", "ssh_failed", "jdoe", "203.0.113.9", "", ""),   # no time
        ("2026-05-23T10:00:00+00:00", "2026-05-23T10:00:00", "user_add", "backup2", "", "",
         "yes"),
    ])
    c.execute('CREATE TABLE art_evtx_security ("TimeCreated", "EventId", "MapDescription",'
              ' "UserName")')
    c.execute("INSERT INTO art_evtx_security VALUES "
              "('2026-05-24 00:05:00.1234567', '4624', 'Successful logon', 'CORP\\jdoe')")
    # another table's time names a different moment: not in the view
    c.execute("CREATE TABLE art_bodyfile (mtime_utc, path)")
    c.execute("INSERT INTO art_bodyfile VALUES ('2026-05-24 00:00:00', '/tmp/x')")
    # a table with `TimeCreated` that is not an EvtxECmd channel: not in the view
    c.execute('CREATE TABLE art_other ("TimeCreated", note)')
    c.execute("INSERT INTO art_other VALUES ('2026-05-24 00:00:00', 'n')")
    return c


def test_every_utc_row_of_every_table_in_one_shape_and_order():
    c = _db()
    assert timeline.create(c) == 2
    rows = list(c.execute("SELECT * FROM timeline ORDER BY time_utc"))
    assert rows == [
        ("2026-05-23 10:00:00", "art_log_auth", 3, "yes", "event=user_add | user=backup2"),
        ("2026-05-24 00:05:00", "art_evtx_security", 1, "",
         "MapDescription=Successful logon | UserName=CORP\\jdoe"),
        ("2026-05-24 00:06:48", "art_log_auth", 1, "",
         "event=ssh_accepted | user=root | source=10.0.0.9"),
    ]
    # the row id leads back to the whole row
    assert c.execute("SELECT event FROM art_log_auth WHERE rowid = 3").fetchone() == ("user_add",)


def test_recreating_it_replaces_it_and_no_timed_table_leaves_no_view():
    c = _db()
    timeline.create(c)
    c.execute("CREATE TABLE art_logins (time_utc, user)")
    c.execute("INSERT INTO art_logins VALUES ('2026-05-25 08:00:00', 'jdoe')")
    assert timeline.create(c) == 3
    empty = sqlite3.connect(":memory:")
    empty.execute("CREATE TABLE art_bodyfile (mtime_utc, path)")
    assert timeline.create(empty) == 0
    assert empty.execute("SELECT name FROM sqlite_master WHERE type = 'view'").fetchall() == []


def test_a_table_named_like_the_view_costs_the_view_not_the_db(caplog):
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE timeline (time_utc)")
    assert timeline.create(c) == 0
    assert "timeline view not created" in caplog.text


def test_the_consolidated_db_carries_the_view(tmp_path):
    host = tmp_path / "HOST-01"
    logs = host / "CSVs" / "EventLogs"
    logs.mkdir(parents=True)
    (logs / "art_logins.csv").write_text(
        "time_utc,user,host,source\n2026-05-25 08:00:00,jdoe,10.0.0.5,wtmp\n", encoding="utf-8")
    m = Machine("HOST-01", "linux", "uac", "linux_uac", host, "src",
                [Volume("live", host, True)])
    unit = consolidate.plan_units([(m, [])])[0][0]
    consolidate.build_unit(unit, emit_db=True, emit_xlsx=False)
    db = next(tmp_path.rglob("*.db"))
    with sqlite3.connect(db) as c:
        assert c.execute("SELECT tbl, summary FROM timeline").fetchall() == [
            ("art_logins", "user=jdoe | source=wtmp | host=10.0.0.5")]
