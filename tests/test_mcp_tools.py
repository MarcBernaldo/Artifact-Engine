"""v0.7.167: what `aeng mcp` lets an assistant do with a case (core.mcp_tools).
No MCP SDK needed: the server only registers these. Values are invented."""
from __future__ import annotations

import csv
import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from artifact_engine.core import mcp_tools as T
from artifact_engine.core.mcp_tools import ToolError, Workspace


def _machine(case: Path, name: str, rows: int = 3) -> Path:
    d = case / name
    d.mkdir(parents=True)
    (d / "report.txt").write_text("LOG COVERAGE\n" + "x" * 20000, encoding="utf-8")
    db = d / f"{name}.db"
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE "logins" ("time_utc" TEXT, "user" TEXT, "host" TEXT)')
    conn.executemany('INSERT INTO "logins" VALUES (?,?,?)',
                     [(f"2026-01-0{i % 9 + 1} 10:00:00", "jdoe", "10.0.0.5") for i in range(rows)])
    conn.execute('CREATE TABLE "notes" ("text" TEXT)')
    conn.execute('INSERT INTO "notes" VALUES (?)', ("y" * 1000,))
    conn.commit()
    conn.close()
    with open(d / "findings.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["table", "rowid", "flagged_in_table", "rows_in_table", "summary"])
        for i in range(1, 8):
            w.writerow(["logins", i, 7, rows, f"jdoe from 10.0.0.{i}"])
    return db


@pytest.fixture
def ws(tmp_path) -> Workspace:
    root = tmp_path / "cases"
    case = root / "CASE-01"
    _machine(case, "HOST-01", rows=120)
    _machine(case, "HOST-02")
    ev = case / "HOST-01" / "C" / "Users" / "jdoe"
    ev.mkdir(parents=True)
    (ev / "History.db").write_bytes(b"SQLite format 3\x00")        # evidence, not a machine
    (case / "run-summary.json").write_text(json.dumps(
        {"status": "complete", "finished_at": "2026-01-02T10:00:00Z",
         "totals": {"ok": 10, "errors": 0}}), encoding="utf-8")
    with open(case / "lateral_movement.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["src", "dst", "user", "logon_type", "suspicious"])
        w.writerow(["10.0.0.5", "HOST-01", "jdoe", "RDP", "yes"])
        w.writerow(["HOST-01", "HOST-02", "admin", "Network", ""])
    (root / "CASE-02").mkdir()
    (tmp_path / "outside").mkdir()
    return Workspace([root])


def test_a_case_is_reached_only_under_its_roots(ws, tmp_path):
    assert ws.case_path("CASE-01").name == "CASE-01"
    for bad in ("..", "../outside", "CASE-01/../../outside", str(tmp_path / "outside"),
                "C:outside", "", "NOPE"):
        with pytest.raises(ToolError):
            ws.case_path(bad)


def test_cases_say_their_machines_and_last_run(ws):
    cases = {c["case"]: c for c in ws.list_cases()}
    assert cases["CASE-01"]["machines"] == 2
    assert cases["CASE-01"]["last_run"]["status"] == "complete"
    assert cases["CASE-02"] == {**cases["CASE-02"], "machines": 0, "last_run": None}


def test_machines_are_the_engines_databases_not_the_evidence(ws):
    assert [m["machine"] for m in ws.list_machines("CASE-01")] == ["HOST-01", "HOST-02"]
    with pytest.raises(ToolError, match="machines: HOST-01, HOST-02"):
        ws.list_tables("CASE-01", "History")


def test_tables_and_their_rows(ws):
    assert ws.list_tables("CASE-01", "HOST-01") == [
        {"table": "logins", "rows": 120}, {"table": "notes", "rows": 1}]
    assert ws.list_tables("CASE-01", "HOST-01", "LOG") == [{"table": "logins", "rows": 120}]
    d = ws.describe_table("CASE-01", "HOST-01", "logins")
    assert d["columns"] == ["time_utc", "user", "host"] and len(d["sample"]) == 3


def test_a_query_is_paged_and_says_how_much_there_is(ws):
    q = ws.query("CASE-01", "HOST-01", 'SELECT * FROM "logins"', limit=50)
    assert (q["returned"], q["has_more"], q["rows_total"]) == (50, True, 120)
    q = ws.query("CASE-01", "HOST-01", 'SELECT * FROM "logins"', limit=50, offset=100)
    assert (q["returned"], q["has_more"]) == (20, False)
    many = ("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 500) "
            "SELECT x FROM c")
    q = ws.query("CASE-01", "HOST-01", many, limit=10_000)
    assert (q["returned"], q["has_more"], q["rows_total"]) == (T.MAX_ROWS, True, 500)
    q = ws.query("CASE-01", "HOST-01", "WITH n AS (SELECT text FROM notes) SELECT * FROM n;")
    assert q["rows"][0][0].startswith("y" * T.MAX_CELL) and "+700 chars" in q["rows"][0][0]


@pytest.mark.parametrize("sql", [
    "PRAGMA writable_schema=1", "ATTACH DATABASE '{x}' AS x", "DELETE FROM logins",
    "INSERT INTO logins VALUES (1,2,3)", "DROP TABLE logins", "VACUUM",
])
def test_only_a_select_is_taken(ws, tmp_path, sql):
    db = ws._machine_db("CASE-01", "HOST-01")
    before = db.read_bytes()
    with pytest.raises(ToolError, match="only reading is allowed"):
        ws.query("CASE-01", "HOST-01", sql.format(x=tmp_path / "x.db"))
    assert db.read_bytes() == before and not (tmp_path / "x.db").exists()


@pytest.mark.parametrize("sql", [
    "SELECT 1; DROP TABLE logins", "SELECT load_extension('evil')",
    "SELECT * FROM pragma_table_info('logins') JOIN logins",
    "WITH t AS (SELECT 1) DELETE FROM logins",
])
def test_a_select_that_reaches_for_more_is_refused(ws, sql):
    db = ws._machine_db("CASE-01", "HOST-01")
    before = db.read_bytes()
    with pytest.raises(ToolError):
        ws.query("CASE-01", "HOST-01", sql)
    assert db.read_bytes() == before


def test_a_query_that_runs_too_long_is_stopped(ws, monkeypatch):
    monkeypatch.setattr(T, "SQL_SECONDS", 0.2)
    with pytest.raises(ToolError, match="ran past"):
        ws.query("CASE-01", "HOST-01",
                 "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) "
                 "SELECT max(x) FROM c")


def test_findings_report_and_lateral_are_paged(ws):
    f = ws.findings("CASE-01", "HOST-01", limit=5)
    assert (len(f["findings"]), f["total"], f["has_more"]) == (5, 7, True)
    r = ws.report("CASE-01", "HOST-01")
    assert r["text"].startswith("LOG COVERAGE") and r["next_offset"] == T.REPORT_CHARS
    assert ws.report("CASE-01", "HOST-01", offset=r["total_chars"] - 5)["next_offset"] is None
    assert ws.lateral("CASE-01", suspicious_only=True)["total"] == 1
    assert ws.lateral("CASE-01", host="host-02")["total"] == 1
    assert ws.lateral("CASE-01", user="ADMIN")["rows"][0]["dst"] == "HOST-02"


def test_sweep_groups_hits_and_names_what_was_not_found(ws):
    s = ws.sweep("CASE-01", ["10.0.0.5", "zz-not-there"])
    assert s["state"] == "finished"
    assert s["searched"] == ["HOST-01", "HOST-02"] and s["unreadable"] == []
    assert {(h["machine"], h["table"], h["hits"]) for h in s["hits"]} == {
        ("HOST-01", "logins", 120), ("HOST-02", "logins", 3)}
    assert s["not_found"] == ["zz-not-there"]
    with pytest.raises(ToolError):
        ws.sweep("CASE-01", [])


def _fake(ws, monkeypatch, code: str):
    monkeypatch.setattr(Workspace, "_command",
                        lambda self, kind, case, args: [sys.executable, "-c", code])


def _wait(ws, run_id: str) -> dict:
    for _ in range(100):
        st = ws.run_status(run_id)
        if st["state"] != "running" and ws._runs[run_id].finished:
            return st
        time.sleep(0.1)
    raise AssertionError("run did not finish")


def test_a_run_is_started_in_the_background_and_followed(ws, monkeypatch):
    _fake(ws, monkeypatch, "print('[+] Parsing'); print('[+] Done')")
    started = ws.start_run("CASE-01")
    st = _wait(ws, started["run_id"])
    assert st["state"] == "finished" and st["last_output"] == ["[+] Parsing", "[+] Done"]
    assert st["summary"]["status"] == "complete"
    assert ws.list_runs() == [{"run_id": started["run_id"], "kind": "run",
                               "case": "CASE-01", "running": False}]


def test_one_run_at_a_time_per_case(ws, monkeypatch):
    _fake(ws, monkeypatch, "import time; time.sleep(3)")
    first = ws.start_run("CASE-01")
    with pytest.raises(ToolError, match="already running"):
        ws.start_lateral("CASE-01")
    ws.start_lateral("CASE-02")                       # another case is fine
    ws._runs[first["run_id"]].proc.kill()
    with pytest.raises(ToolError):
        ws.run_status("nope")


def test_the_command_is_aeng_with_the_servers_interpreter(ws):
    case = ws.case_path("CASE-01")
    assert ws._command("run", case, ["--force"]) == [
        sys.executable, "-m", "artifact_engine", "run", "-p", str(case), "--force"]


def test_the_server_registers_every_tool(tmp_path):
    pytest.importorskip("mcp")
    import asyncio

    from artifact_engine import mcp_server
    server = mcp_server.build([tmp_path])
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == {"list_cases", "list_machines", "list_tables", "describe_table", "query",
                     "findings", "report", "sweep", "sweep_result", "lateral", "start_run",
                     "start_lateral", "run_status", "list_runs"}


def test_the_connection_itself_refuses_attach_pragma_and_writes(ws, tmp_path):
    """The second and third walls, behind the SELECT-only check: an authorizer
    that allows reading only, and a read-only open."""
    db = ws._machine_db("CASE-01", "HOST-01")
    x = tmp_path / "x.db"
    conn = ws._connect(db)
    try:
        for sql in (f"ATTACH DATABASE '{x}' AS x", "PRAGMA query_only=0"):
            with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
                conn.execute(sql)
    finally:
        conn.close()
    bare = ws._open(db)                                 # even without it: read-only
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            bare.execute("DELETE FROM logins")
    finally:
        bare.close()
    assert not x.exists()


@pytest.mark.parametrize("bad", ["CASE-01/HOST-01", "CASE-01\\HOST-01", ".", "CASE-01:x"])
def test_a_case_is_one_folder_name_not_a_path_into_it(ws, bad):
    """Refused before it is resolved, with what to give instead."""
    with pytest.raises(ToolError, match="by its folder name"):
        ws.case_path(bad)


def test_runs_do_not_overlap_a_case_and_a_folder_inside_it(ws, monkeypatch, tmp_path):
    """Two roots where one holds the other: a run on the case, and one on a
    machine folder of it through the second root, would write one tree twice."""
    root = tmp_path / "cases"
    nested = Workspace([root, root / "CASE-01"])
    _fake(nested, monkeypatch, "import time; time.sleep(3)")
    first = nested.start_run("CASE-01")
    try:
        with pytest.raises(ToolError, match="already running"):
            nested.start_run("HOST-01")
    finally:
        nested._runs[first["run_id"]].proc.kill()


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are Windows")
def test_a_junction_does_not_lead_out_of_a_case_or_a_root(ws, tmp_path):
    import _winapi
    away = tmp_path / "outside"
    _machine(away, "HOST-09")
    _winapi.CreateJunction(str(away), str(tmp_path / "cases" / "CASE-01" / "LINK"))
    _winapi.CreateJunction(str(away), str(tmp_path / "cases" / "CASE-09"))
    assert [m["machine"] for m in ws.list_machines("CASE-01")] == ["HOST-01", "HOST-02"]
    assert "CASE-09" not in {c["case"] for c in ws.list_cases()}
    assert ws.sweep("CASE-01", ["jdoe"])["searched"] == ["HOST-01", "HOST-02"]
    with pytest.raises(ToolError):
        ws.case_path("CASE-09")


def test_a_linked_database_out_of_the_case_is_not_a_machine(ws, tmp_path):
    """The walk keeps out of linked folders; a linked FILE is still listed, and
    must resolve inside the case to be read."""
    away = _machine(tmp_path / "outside", "HOST-09")
    d = tmp_path / "cases" / "CASE-01" / "HOST-08"
    d.mkdir()
    (d / "report.txt").write_text("x", encoding="utf-8")
    try:
        (d / "HOST-08.db").symlink_to(away)
    except OSError:
        pytest.skip("creating a symlink needs developer mode or admin here")
    assert [m["machine"] for m in ws.list_machines("CASE-01")] == ["HOST-01", "HOST-02"]
    assert ws.sweep("CASE-01", ["jdoe"])["searched"] == ["HOST-01", "HOST-02"]


@pytest.mark.skipif(sys.platform != "win32", reason="UNC paths are Windows")
def test_a_database_on_a_share_is_opened(ws):
    """A root on a share: `as_uri` writes `file://server/...`, which SQLite refuses."""
    db = ws._machine_db("CASE-01", "HOST-01").resolve()
    unc = Path(f"\\\\localhost\\{db.drive[0]}$" + str(db)[2:])
    try:
        unc.stat()
    except OSError:
        pytest.skip("the administrative share is not reachable")
    conn = ws._open(unc)
    try:
        assert conn.execute('SELECT count(*) FROM "logins"').fetchone() == (120,)
    finally:
        conn.close()


def test_a_long_sweep_goes_on_in_the_background(ws, monkeypatch):
    """A sweep over a large case takes minutes, longer than a client waits for one
    call: past SWEEP_WAIT the answer is an id, and sweep_result collects it."""
    import threading
    gate = threading.Event()
    real = T.sweepmod.sweep_database

    def slow(*a, **k):
        gate.wait(10)
        return real(*a, **k)

    monkeypatch.setattr(T.sweepmod, "sweep_database", slow)
    monkeypatch.setattr(T, "SWEEP_WAIT", 0.05)
    first = ws.sweep("CASE-01", ["10.0.0.5"])
    assert (first["state"], first["machines_searched"]) == ("running", 0)
    with pytest.raises(ToolError, match="already running"):
        ws.sweep("CASE-01", ["jdoe"])
    gate.set()
    ws._sweeps[first["sweep_id"]].done.wait(10)
    done = ws.sweep_result(first["sweep_id"])
    assert done["state"] == "finished" and done["groups_total"] == 2
    with pytest.raises(ToolError):
        ws.sweep_result("nope")


def test_a_sweep_that_fails_says_so(ws, monkeypatch):
    def boom(*a, **k):
        raise MemoryError("too much")

    monkeypatch.setattr(T.sweepmod, "sweep_database", boom)
    s = ws.sweep("CASE-01", ["jdoe"])
    assert s["state"] == "failed" and "MemoryError" in s["error"]


def test_a_sweep_answers_while_the_case_is_still_being_walked(ws, monkeypatch):
    """A large evidence tree takes a while just to list: that walk is in the
    thread too, not in front of the answer."""
    import threading
    gate = threading.Event()
    real = T.sweepmod.find_case_databases

    def slow(*a, **k):
        gate.wait(10)
        return real(*a, **k)

    monkeypatch.setattr(T.sweepmod, "find_case_databases", slow)
    monkeypatch.setattr(T, "SWEEP_WAIT", 0.05)
    began = time.monotonic()
    first = ws.sweep("CASE-01", ["10.0.0.5"])
    assert time.monotonic() - began < 5
    assert (first["state"], first["machines_total"]) == ("running", None)
    gate.set()
    ws._sweeps[first["sweep_id"]].done.wait(10)
    assert ws.sweep_result(first["sweep_id"])["searched"] == ["HOST-01", "HOST-02"]


def test_a_sweep_and_a_run_do_not_share_a_case(ws, monkeypatch):
    """A run deletes and rebuilds the databases a sweep reads: a machine read half
    built would be 'searched' with values reported not found."""
    import threading
    _fake(ws, monkeypatch, "import time; time.sleep(3)")
    run = ws.start_run("CASE-01")
    try:
        with pytest.raises(ToolError, match="already running"):
            ws.sweep("CASE-01", ["jdoe"])
    finally:
        ws._runs[run["run_id"]].proc.kill()
        ws._runs[run["run_id"]].proc.wait()
    gate = threading.Event()
    real = T.sweepmod.sweep_database
    monkeypatch.setattr(T.sweepmod, "sweep_database",
                        lambda *a, **k: (gate.wait(10), real(*a, **k))[1])
    monkeypatch.setattr(T, "SWEEP_WAIT", 0.05)
    sw = ws.sweep("CASE-01", ["jdoe"])
    try:
        with pytest.raises(ToolError, match="sweep is already running"):
            ws.start_run("CASE-01")
    finally:
        gate.set()
        ws._sweeps[sw["sweep_id"]].done.wait(10)


def test_a_linked_run_summary_out_of_the_case_is_not_read(ws, tmp_path):
    case = tmp_path / "cases" / "CASE-02"
    away = tmp_path / "outside" / "run-summary.json"
    away.write_text(json.dumps({"status": "complete"}), encoding="utf-8")
    try:
        (case / "run-summary.json").symlink_to(away)
    except OSError:
        pytest.skip("creating a symlink needs developer mode or admin here")
    cases = {c["case"]: c for c in ws.list_cases()}
    assert cases["CASE-02"]["last_run"] is None
