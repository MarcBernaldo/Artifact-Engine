"""case.html (core/casepage.py, AE-048) and the findings per host in run-summary.
Every value is invented."""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from artifact_engine.core import casedb, casepage, dbnav, report


def _machine_db(path: Path, rows: list[tuple]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE alert_win_sigma (level, rule, first_seen, "match")')
    conn.executemany("INSERT INTO alert_win_sigma VALUES (?,?,?,?)", rows)
    conn.commit()
    dbnav.create_views(conn)
    conn.close()
    (path.parent / "report.txt").write_text("report", encoding="utf-8")
    return path


def _case(tmp_path: Path) -> tuple[Path, list[dict]]:
    quiet = _machine_db(tmp_path / "HOST-01" / "HOST-01.db", [
        ("low", "Rule L", "2026-05-01 10:00:00", "l.exe")] * 3)
    loud = _machine_db(tmp_path / "HOST-02" / "HOST-02.db", [
        ("critical", "Rule <script>alert(1)</script>", "2026-05-02 09:00:00", "c.exe"),
        ("high", "Rule H", "2026-05-02 08:00:00", "h.exe")]
        + [("medium", f"Rule M{i}", "2026-05-02 07:00:00", "m.exe") for i in range(20)])
    db = casedb.build(tmp_path, [("HOST-01", quiet), ("HOST-02", loud)])
    return db, casedb.host_findings(db)


def test_the_page_lists_the_most_severe_host_first_with_its_counts(tmp_path):
    db, hosts = _case(tmp_path)
    page = casepage.write(tmp_path, db, hosts).read_text(encoding="utf-8")
    assert page.index("HOST-02</a></td>") < page.index("HOST-01</a></td>")
    row = re.search(r"<tr><td><a href='#h-HOST-02'>HOST-02</a></td>(.*?)</tr>", page).group(1)
    assert re.findall(r"<td class=n>(\d*)</td>", row) == ["1", "1", "20", "", ""]
    assert 'href="HOST-02/report.txt"' in page and 'href="HOST-02/HOST-02.db"' in page


def test_a_hosts_list_is_its_most_severe_findings_and_says_how_many_more(tmp_path):
    db, hosts = _case(tmp_path)
    page = casepage.write(tmp_path, db, hosts).read_text(encoding="utf-8")
    section = page[page.index("<h2 id='h-HOST-02'>"):page.index("<h2 id='h-HOST-01'>")]
    assert section.count("<span class='lv ") == casepage.TOP_PER_HOST
    assert section.index("lv critical") < section.index("lv high") < section.index("lv medium")
    assert f"the {casepage.TOP_PER_HOST} most severe of 22" in section


def test_every_value_is_escaped(tmp_path):
    db, hosts = _case(tmp_path)
    page = casepage.write(tmp_path, db, hosts).read_text(encoding="utf-8")
    assert "<script>" not in page and "&lt;script&gt;" in page


def test_no_case_db_or_no_host_writes_no_page(tmp_path):
    assert casepage.write(tmp_path, None, [{"host": "x"}]) is None
    assert casepage.write(tmp_path, tmp_path / "case.db", []) is None
    assert not (tmp_path / casepage.CASE_PAGE).exists()


def test_the_run_summary_names_the_findings_per_host(tmp_path):
    _db, hosts = _case(tmp_path)
    summary = report.build_run_summary(tmp_path, [], hosts=hosts)
    assert [(h["host"], h["critical"], h["high"], h["medium"], h["low"])
            for h in summary["findings_per_host"]] == [("HOST-02", 1, 1, 20, 0),
                                                       ("HOST-01", 0, 0, 0, 3)]
    text = (tmp_path / "run-summary.txt").read_text(encoding="utf-8")
    block = text[text.index("Findings per host"):]
    assert block.index("HOST-02") < block.index("HOST-01")
    assert summary["status"] == "incomplete", "no machine parsed: the verdict is unchanged"


def test_a_hash_in_the_case_folder_name_still_lists_the_findings(tmp_path):
    root = tmp_path / "Case #12"
    db, hosts = _case(root)
    page = casepage.write(root, db, hosts).read_text(encoding="utf-8")
    assert "lv critical" in page


# --------------------------------------------------------------------------- #
# Found by review (v0.7.200)
# --------------------------------------------------------------------------- #
def test_a_run_with_no_case_db_removes_the_last_runs_page(tmp_path):
    db, hosts = _case(tmp_path)
    page = casepage.write(tmp_path, db, hosts)
    assert page.is_file()
    assert casepage.write(tmp_path, None, []) is None
    assert not page.exists(), "an earlier run's counts must not read as this run's"


def test_a_host_that_was_not_read_is_unknown_not_clean(tmp_path):
    db, hosts = _case(tmp_path)
    hosts.append({"host": "HOST-03", "db": "HOST-03/HOST-03.db",
                  "status": "not rebuilt this run: PermissionError: locked",
                  **{lv: 0 for lv in casedb.LEVELS}})
    page = casepage.write(tmp_path, db, hosts).read_text(encoding="utf-8")
    section = page[page.index("<h2 id='h-HOST-03'>"):]
    assert "Not read:" in section and "PermissionError: locked" in section
    assert "No findings." not in section


def test_links_are_percent_encoded_and_never_leave_the_case_root(tmp_path):
    folder = tmp_path / "HOST-01 #2"
    db_path = _machine_db(folder / "HOST-01 #2.db", [("high", "R", "2026-05-01", "x")])
    outside = _machine_db(tmp_path.parent / f"{tmp_path.name}-out" / "HOST-09.db",
                          [("low", "R", "2026-05-01", "x")])
    db = casedb.build(tmp_path, [("HOST-01", db_path), ("HOST-09", outside)])
    page = casepage.write(tmp_path, db, casedb.host_findings(db)).read_text(encoding="utf-8")
    assert 'href="HOST-01%20%232/HOST-01%20%232.db"' in page
    assert 'href="HOST-01%20%232/report.txt"' in page
    row = re.search(r"<tr><td><a href='#h-HOST-09'>.*?</tr>", page).group(0)
    assert "<a href=\"" not in row, "a .db outside the root gets no link"
