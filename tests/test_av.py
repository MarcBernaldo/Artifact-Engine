"""What the endpoint product saw, and what this engine did not read of it.

Two things are under test here and the second matters as much as the first: the
three readers, and the inventory that says a product's logs arrived and were not
parsed. A detections table alone would read as a clean machine on a host running
any of the products with no reader.

The vendor log lines below are INVENTED to the shape of each format. Every host
name, user name, path and threat name is made up.
"""
from __future__ import annotations

import csv
import logging
from pathlib import Path

from artifact_engine.core import coverage
from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import win_av as A

ASSET = Path(A.__file__).resolve().parents[1] / "data" / "assets" / A.ASSET


def _ctx(evidence: Path, out: Path, assets: Path) -> ParserContext:
    return ParserContext(
        evidence=evidence, out=out, tools=evidence, assets=assets,
        machine_name="HOST-01", volume="C", log=logging.getLogger("aeng.test"),
    )


def _rows(out: Path, name: str) -> list[dict]:
    path = out / name
    if not path.is_file():
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _run(tmp_path: Path, asset_text: str | None = None):
    """Run the handler over tmp_path/evidence and return both tables."""
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    assets = tmp_path / "assets"
    assets.mkdir(exist_ok=True)
    (assets / A.ASSET).write_text(
        asset_text if asset_text is not None else ASSET.read_text(encoding="utf-8"),
        encoding="utf-8")
    out = tmp_path / "out"
    A.run(_ctx(evidence, out, assets))
    return _rows(out, "av_detections.csv"), _rows(out, "av_products.csv")


def _write(evidence: Path, rel: str, body: str, encoding: str = "utf-8") -> Path:
    path = evidence / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding=encoding)
    return path


# --- the inventory, and the gap it exists to state -----------------------

def test_a_product_with_no_reader_is_still_inventoried(tmp_path):
    evidence = tmp_path / "evidence"
    _write(evidence, "ProgramData/Emsisoft/Reports/scan_240101.txt", "whatever\n")
    det, prod = _run(tmp_path)
    assert det == []
    mine = [r for r in prod if r["product"] == "Emsisoft"]
    assert len(mine) == 1
    assert mine[0]["reader"] == "" and mine[0]["files"] == "1"
    assert mine[0]["rows"] == "0" and mine[0]["files_read"] == "0"
    assert mine[0]["first_modified_utc"] and mine[0]["last_modified_utc"]


def test_report_marks_the_products_nothing_was_read_from(tmp_path):
    evidence = tmp_path / "evidence"
    _write(evidence, "ProgramData/Emsisoft/Reports/scan.txt", "x\n")
    _write(evidence, "Windows/Debug/msert.log",
           "Started On Fri Oct 03 10:00:00 2026\n"
           "Found Trojan:Win32/Invented and Removed!\n")
    _, prod = _run(tmp_path)
    text = "\n".join(coverage.render_av(prod))
    assert "Emsisoft" in text
    # The whole point: the unread product is marked, and the mark is explained.
    emsi = [ln for ln in text.splitlines() if "Emsisoft" in ln][0]
    assert emsi.lstrip().startswith("!")
    assert "no reader" in emsi
    assert "1 of 2 found here" in text
    scanner = [ln for ln in text.splitlines() if "Safety Scanner" in ln][0]
    assert not scanner.lstrip().startswith("!") and "1 detection(s) read" in scanner


def test_report_is_printed_even_when_everything_was_read(tmp_path):
    """Silence would be ambiguous between `no endpoint product here` and `the
    parser did not run`, and those lead to opposite conclusions."""
    evidence = tmp_path / "evidence"
    _write(evidence, "Windows/Debug/msert.log",
           "Started On Fri Oct 03 10:00:00 2026\n"
           "Found Trojan:Win32/Invented and Removed!\n")
    _, prod = _run(tmp_path)
    text = "\n".join(coverage.render_av(prod))
    assert "Endpoint-security products" in text
    assert "!" not in text and "?" not in text
    assert "Every product found here was read" in text


def test_no_product_means_no_block_and_no_table(tmp_path):
    det, prod = _run(tmp_path)
    assert det == [] and prod == []
    assert coverage.render_av([]) == []


def test_quarantine_files_are_counted_and_not_opened(tmp_path):
    """A quarantine directory holds samples, not logs. It is evidence that a
    sample exists; opening it would parse a payload as a log."""
    evidence = tmp_path / "evidence"
    base = "ProgramData/Symantec/Symantec Endpoint Protection/14.3/Data/Quarantine"
    _write(evidence, f"{base}/AB01CD02.VBN", "binary-ish\n")
    _, prod = _run(tmp_path)
    row = [r for r in prod if r["path"].endswith("Quarantine")][0]
    assert row["files"] == "1" and row["files_read"] == "0" and row["rows"] == "0"


def test_user_patterns_expand_to_every_profile(tmp_path):
    evidence = tmp_path / "evidence"
    for user in ("jdoe", "asmith"):
        _write(evidence,
               f"Users/{user}/AppData/Roaming/SUPERAntiSpyware/Logs/scan.log", "x\n")
    _, prod = _run(tmp_path)
    mine = sorted(r["path"] for r in prod if r["product"] == "SUPERAntiSpyware")
    assert len(mine) == 2
    assert any("jdoe" in p for p in mine) and any("asmith" in p for p in mine)


# --- McAfee --------------------------------------------------------------

_MC_CONFIRMED = (
    "10/12/2021\t11:03:27 AM\tDeleted\tEXAMPLE\\jdoe\t"
    "C:\\Users\\jdoe\\Downloads\\invented.exe\tInvented-Dropper\tTrojan\n")


def test_mcafee_layout_confirmed_names_the_threat(tmp_path):
    evidence = tmp_path / "evidence"
    _write(evidence, "ProgramData/McAfee/DesktopProtection/OnAccessScanLog.txt",
           _MC_CONFIRMED)
    det, prod = _run(tmp_path)
    assert len(det) == 1
    row = det[0]
    assert row["product"] == "McAfee"
    assert row["threat_name"] == "Invented-Dropper"
    assert row["path"] == "C:\\Users\\jdoe\\Downloads\\invented.exe"
    assert row["action"] == "Deleted" and row["user"] == "EXAMPLE\\jdoe"
    assert row["source_file"] == "OnAccessScanLog.txt"
    assert row["suspicious"] == ""
    assert [r for r in prod if r["product"] == "McAfee"][0]["raw_only"] == "0"


def test_mcafee_date_is_carried_verbatim(tmp_path):
    """10/12/2021 is October or December depending on the host's locale and the
    file does not say which. Normalising it would invent a day/month order."""
    evidence = tmp_path / "evidence"
    _write(evidence, "ProgramData/McAfee/DesktopProtection/OnAccessScanLog.txt",
           _MC_CONFIRMED)
    det, _ = _run(tmp_path)
    assert det[0]["time_local"] == "10/12/2021 11:03:27 AM"
    assert det[0]["time_kind"] == "event"


def test_an_unconfirmed_layout_guesses_nothing_and_keeps_the_line(tmp_path):
    """Two paths in a row: the field after the path is a path, so the layout
    check fails. The threat name must be EMPTY -- not the next field -- and the
    raw line must still be there."""
    evidence = tmp_path / "evidence"
    line = ("10/12/2021\t11:03:27 AM\tBlocked by rule\t"
            "C:\\Windows\\System32\\invented.exe\tC:\\Users\\jdoe\\target.doc\n")
    _write(evidence, "ProgramData/McAfee/Endpoint Security/Logs/tp_activity.log", line)
    det, prod = _run(tmp_path)
    assert len(det) == 1
    assert det[0]["threat_name"] == ""
    assert det[0]["path"] == "C:\\Windows\\System32\\invented.exe"
    assert "C:\\Users\\jdoe\\target.doc" in det[0]["detail"]
    assert [r for r in prod if r["product"] == "McAfee"][0]["raw_only"] == "1"


def test_a_space_padded_log_line_keeps_the_spaces_inside_its_fields(tmp_path):
    """Not every one of these logs is tab-separated: some pad their columns with
    spaces. Splitting on a single space then shreds `C:\\Program Files\\...` into
    three fields and the threat name becomes the middle of a path."""
    evidence = tmp_path / "evidence"
    _write(evidence, "ProgramData/McAfee/DesktopProtection/OnDemandScanLog.txt",
           "10/12/2021  11:03:27 AM  Deleted  EXAMPLE\\jdoe  "
           "C:\\Program Files\\Invented App\\run.exe  Invented-C  Trojan\n")
    det, _ = _run(tmp_path)
    assert len(det) == 1
    assert det[0]["path"] == "C:\\Program Files\\Invented App\\run.exe"
    assert det[0]["threat_name"] == "Invented-C"
    assert det[0]["user"] == "EXAMPLE\\jdoe" and det[0]["action"] == "Deleted"


def test_a_record_naming_no_file_is_not_a_detection_row(tmp_path):
    """This is a detections table, not a log dump."""
    evidence = tmp_path / "evidence"
    _write(evidence, "ProgramData/McAfee/DesktopProtection/OnAccessScanLog.txt",
           "10/12/2021\t11:00:00 AM\tScan started\tEXAMPLE\\jdoe\n" + _MC_CONFIRMED)
    det, _ = _run(tmp_path)
    assert len(det) == 1 and det[0]["threat_name"] == "Invented-Dropper"


def test_a_utf16_log_with_a_bom_is_read(tmp_path):
    evidence = tmp_path / "evidence"
    _write(evidence, "ProgramData/McAfee/DesktopProtection/OnAccessScanLog.txt",
           _MC_CONFIRMED, encoding="utf-16")
    det, _ = _run(tmp_path)
    assert len(det) == 1 and det[0]["threat_name"] == "Invented-Dropper"


def test_a_utf16_log_without_a_bom_is_read(tmp_path):
    """Read as UTF-8 it matches nothing, and nothing is a silent empty table."""
    evidence = tmp_path / "evidence"
    path = evidence / "ProgramData/McAfee/DesktopProtection/OnDemandScanLog.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_MC_CONFIRMED.encode("utf-16-le"))
    det, _ = _run(tmp_path)
    assert len(det) == 1 and det[0]["threat_name"] == "Invented-Dropper"


def test_the_flag_is_read_from_the_action_not_from_the_line(tmp_path):
    """`left alone` inside a file name is a file name. The flag is the product's
    own verdict or it is noise."""
    evidence = tmp_path / "evidence"
    body = ("10/12/2021\t11:03:27 AM\tDeleted\tEXAMPLE\\jdoe\t"
            "C:\\temp\\left alone notes\\invented.exe\tInvented-A\tTrojan\n"
            "10/12/2021\t11:04:00 AM\tAccess denied\tEXAMPLE\\jdoe\t"
            "C:\\temp\\invented2.exe\tInvented-B\tTrojan\n")
    _write(evidence, "ProgramData/McAfee/DesktopProtection/OnAccessScanLog.txt", body)
    det, _ = _run(tmp_path)
    by_threat = {r["threat_name"]: r["suspicious"] for r in det}
    assert by_threat == {"Invented-A": "", "Invented-B": "yes"}


# --- Symantec ------------------------------------------------------------

def _sep_line(hex12: str, *, path: str = "C:\\temp\\invented.exe",
              virus: str = "Invented.Worm", user: str = "jdoe",
              action: str = "4") -> str:
    parts = [hex12, "51", "2", "100", "HOST-01", user, virus, path, "3", "1", action]
    return ",".join(parts) + ",,,\n"


def _sep(tmp_path: Path, body: str):
    evidence = tmp_path / "evidence"
    _write(evidence,
           "ProgramData/Symantec/Symantec Endpoint Protection/14.3/Data/Logs/0125.log",
           body)
    return _run(tmp_path)


def test_symantec_hex_timestamp_is_decoded(tmp_path):
    # year 1970+56=2026, month 0x09+1=10, day 3, 14:05:06
    det, _ = _sep(tmp_path, _sep_line("3809030E0506"))
    assert len(det) == 1
    assert det[0]["time_local"] == "2026-10-03 14:05:06"
    assert det[0]["time_kind"] == "event"
    assert det[0]["threat_name"] == "Invented.Worm"
    assert det[0]["path"] == "C:\\temp\\invented.exe"
    assert det[0]["user"] == "jdoe"


def test_symantec_an_impossible_timestamp_drops_the_row(tmp_path):
    """The decode IS the layout check: month 14 means this is not the format
    this reader thinks it is, and the answer to that is no row, not a wrong
    timestamp on a real detection."""
    det, prod = _sep(tmp_path, _sep_line("380D030E0506"))
    assert det == []
    assert [r for r in prod if "Logs" in r["path"]][0]["files_read"] == "1"


def test_symantec_action_codes_are_never_translated(tmp_path):
    """The engine does not know this vocabulary. A guessed word would be read as
    the product's own, and `suspicious` must not be invented from it."""
    det, _ = _sep(tmp_path, _sep_line("3809030E0506", action="4"))
    assert det[0]["action"] == "code:4"
    assert det[0]["suspicious"] == ""


def test_symantec_file_column_elsewhere_degrades_without_guessing(tmp_path):
    """If the file column is not path-shaped the layout is not what this reader
    assumes, so the path is located by shape and the threat name is left empty
    rather than taken from a column that may be something else."""
    parts = ["3809030E0506", "51", "2", "100", "HOST-01", "jdoe",
             "Invented.Worm", "not-a-path", "3", "1", "4",
             "C:\\temp\\invented.exe"]
    det, prod = _sep(tmp_path, ",".join(parts) + "\n")
    assert len(det) == 1
    assert det[0]["path"] == "C:\\temp\\invented.exe"
    assert det[0]["threat_name"] == "" and det[0]["action"] == ""
    assert "Invented.Worm" in det[0]["detail"]
    assert [r for r in prod if "Logs" in r["path"]][0]["raw_only"] == "1"


# --- Microsoft Safety Scanner -------------------------------------------

_MSERT = """Microsoft Safety Scanner v1.0, (build 1.0.0.0)
Started On Fri Oct 03 10:00:00 2026

Threat detected: Trojan:Win32/Invented
    file://C:\\Users\\jdoe\\Downloads\\invented.exe

Results Summary:
----------------
Found Trojan:Win32/Invented and Removed!
Found Backdoor:Win32/Invented2 but could not remove it.
"""


def test_msert_time_is_the_scan_start_and_says_so(tmp_path):
    """The file logs one time for the whole scan. A scan start placed on a
    timeline as an event time is a wrong timeline, so the row names what the
    value is."""
    evidence = tmp_path / "evidence"
    _write(evidence, "Windows/Debug/msert.log", _MSERT)
    det, _ = _run(tmp_path)
    assert {r["time_kind"] for r in det} == {"scan_start"}
    assert {r["time_local"] for r in det} == {"Fri Oct 03 10:00:00 2026"}


def test_msert_pairs_a_threat_with_its_file_and_its_verdict(tmp_path):
    evidence = tmp_path / "evidence"
    _write(evidence, "Windows/Debug/msert.log", _MSERT)
    det, _ = _run(tmp_path)
    by_name = {r["threat_name"]: r for r in det}
    assert set(by_name) == {"Trojan:Win32/Invented", "Backdoor:Win32/Invented2"}
    first = by_name["Trojan:Win32/Invented"]
    assert first["path"] == "C:\\Users\\jdoe\\Downloads\\invented.exe"
    assert first["suspicious"] == ""


def test_msert_flags_what_the_scanner_said_it_could_not_remove(tmp_path):
    """The one row that matters here: the file is still on the disk, and the
    product said so."""
    evidence = tmp_path / "evidence"
    _write(evidence, "Windows/Debug/msert.log", _MSERT)
    det, _ = _run(tmp_path)
    flagged = [r for r in det if r["suspicious"] == "yes"]
    assert len(flagged) == 1
    assert flagged[0]["threat_name"] == "Backdoor:Win32/Invented2"


# --- the shipped list ----------------------------------------------------

def test_every_reader_named_in_the_shipped_asset_exists(tmp_path):
    """A typo in the asset would silently turn a product with a reader into one
    without, which is the one failure this parser cannot report on itself."""
    for raw in ASSET.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        reader = [p.strip() for p in s.split("|")][1]
        assert reader == "-" or reader in A._READERS, s.split("|")[0]


def test_the_shipped_asset_leaves_defender_to_its_own_parsers(tmp_path):
    """Defender has `defender_detections` and `evtx_defender`. Listing it here
    would report the same detections twice, from a worse source."""
    products = A.load_products(ASSET)
    assert products
    # Bitdefender is a different product and belongs here; what must not appear
    # is Microsoft's own, and any path under its ProgramData tree.
    assert not any("windows defender" in name.lower() or name.lower() == "defender"
                   for name, _, _ in products)
    assert not any("windows defender" in path.lower()
                   for _n, _r, paths in products for path in paths)


def test_shipped_asset_paths_are_relative_to_the_volume(tmp_path):
    """An absolute path would read the ANALYST's machine instead of the
    evidence."""
    for _name, _reader, paths in A.load_products(ASSET):
        for p in paths:
            assert not p.startswith(("/", "\\")) and ":" not in p, p


def test_the_block_reaches_report_txt(tmp_path):
    """The handler and the renderer can both be right while nothing calls them.
    This is the wiring: a machine's .db carrying `av_products` must produce the
    block in report.txt."""
    import sqlite3

    from artifact_engine.core import report
    from artifact_engine.core.detector import Machine, Volume

    home = tmp_path / "HOST-01"
    (home / "CSVs").mkdir(parents=True)
    db = home / "HOST-01.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE av_products (product TEXT, path TEXT, files INT, "
                 "bytes INT, first_modified_utc TEXT, last_modified_utc TEXT, "
                 "reader TEXT, files_read INT, rows INT, raw_only INT)")
    conn.execute("INSERT INTO av_products VALUES "
                 "('Emsisoft','ProgramData/Emsisoft/Reports',4,120,"
                 "'2026-07-01 00:00:00','2026-10-02 00:00:00','',0,0,0)")
    conn.commit()
    conn.close()
    m = Machine("HOST-01", "windows", "kape", "windows_kape", home, "src",
                [Volume("C", home, True)])

    assert report.build(m, [], out_dir=home, db_path=db) is None

    text = (home / "report.txt").read_text(encoding="utf-8")
    assert "Endpoint-security products on this machine:" in text
    assert "Emsisoft" in text and "no reader" in text
    assert "2026-07-01 00:00:00 .. 2026-10-02 00:00:00" in text


def test_the_detections_table_names_its_time_basis(tmp_path):
    """These products write a wall clock with no offset in it (ARCHITECTURE §5)."""
    assert "time_local" in A.DETECTION_HEADER
    assert "time_utc" not in A.DETECTION_HEADER
    assert "time" not in A.DETECTION_HEADER


# --- the three outcomes report.txt must keep apart -----------------------

def _inventory(**over) -> dict:
    row = {"product": "McAfee", "path": "ProgramData/McAfee/DesktopProtection",
           "files": 4, "bytes": 120, "first_modified_utc": "2026-07-01 00:00:00",
           "last_modified_utc": "2026-10-02 00:00:00", "reader": "mcafee",
           "files_read": 4, "rows": 9, "raw_only": 0}
    row.update(over)
    return row


def test_a_reader_that_ran_and_found_nothing_is_not_called_a_missing_reader():
    """The two are a lead and a gap. Printed as the same thing, the reader that
    may have met a layout it does not know is the one nobody looks at."""
    text = "\n".join(coverage.render_av([_inventory(rows=0)]))
    line = [ln for ln in text.splitlines() if "McAfee" in ln][0]
    assert line.lstrip().startswith("?")
    assert "a reader ran" in text and "no reader" not in text


def test_a_product_directory_with_no_files_is_not_described_as_files():
    """The directory is the product's footprint; the footer must not assert that
    files are sitting in the acquisition when none are."""
    text = "\n".join(coverage.render_av(
        [_inventory(reader="", files=0, files_read=0, rows=0,
                    first_modified_utc="", last_modified_utc="")]))
    assert "present, no files in it" in text
    assert "The files ARE in the" not in text


def test_the_marks_are_counted_over_products_not_over_paths():
    text = "\n".join(coverage.render_av([
        _inventory(product="Emsisoft", reader="", rows=0,
                   path="ProgramData/Emsisoft/Reports"),
        _inventory(product="Emsisoft", reader="", rows=0,
                   path="ProgramData/Emsisoft/Other"),
    ]))
    assert "1 of 1 found here" in text


# --- the readers, after the correctness review ---------------------------

def test_one_threat_across_three_files_is_three_detections(tmp_path):
    """Keying the scan by threat NAME kept the last path and dropped the rest,
    with nothing counting them: a complete-looking table missing two thirds of
    what the scanner found."""
    evidence = tmp_path / "evidence"
    _write(evidence, "Windows/Debug/msert.log",
           "Started On Fri Oct 03 10:00:00 2026\n"
           "Threat detected: Trojan:Win32/Invented\n"
           "    file://C:\\a\\one.exe\n"
           "    file://C:\\b\\two.exe\n"
           "    file://C:\\c\\three.exe\n"
           "Found Trojan:Win32/Invented and Removed!\n")
    det, prod = _run(tmp_path)
    assert sorted(r["path"] for r in det) == [
        "C:\\a\\one.exe", "C:\\b\\two.exe", "C:\\c\\three.exe"]
    assert {r["threat_name"] for r in det} == {"Trojan:Win32/Invented"}
    assert [r for r in prod if r["reader"] == "msert"][0]["rows"] == "3"


def test_a_summary_line_that_names_no_threat_invents_none(tmp_path):
    """`Found no infections` is not a threat called `no`, and `Found 2 threats.`
    is not one called `2`. The scanner names a threat in Microsoft's own
    nomenclature or it has not named one."""
    evidence = tmp_path / "evidence"
    _write(evidence, "Windows/Debug/msert.log",
           "Started On Fri Oct 03 10:00:00 2026\n"
           "Found no infections\n"
           "Found 2 threats.\n"
           "Found nothing of interest here\n")
    det, _ = _run(tmp_path)
    assert det == []


def test_a_threat_the_scanner_could_not_remove_is_a_row_with_no_file(tmp_path):
    """The on-demand scanners label their threat names, so a summary entry with
    no path still identifies something -- and `could not remove it` on a
    backdoor is the most useful sentence in the acquisition."""
    evidence = tmp_path / "evidence"
    _write(evidence, "Windows/Debug/msert.log",
           "Started On Fri Oct 03 10:00:00 2026\n"
           "Found Backdoor:Win32/Invented2 but could not remove it.\n")
    det, _ = _run(tmp_path)
    assert len(det) == 1
    assert det[0]["threat_name"] == "Backdoor:Win32/Invented2"
    assert det[0]["path"] == "" and det[0]["suspicious"] == "yes"


def test_raw_only_counts_the_layout_the_reader_failed_on_not_an_empty_cell(tmp_path):
    """A Symantec row whose virus column is blank in the log is not a row this
    reader could not read: its layout was confirmed by the file column. Counting
    it would dilute the one number that exposes an unknown layout."""
    parts = ["3809030E0506", "51", "2", "100", "HOST-01", "jdoe", "",
             "C:\\temp\\invented.exe", "3", "1", "4"]
    det, prod = _sep(tmp_path, ",".join(parts) + "\n")
    assert len(det) == 1 and det[0]["threat_name"] == ""
    assert [r for r in prod if "Logs" in r["path"]][0]["raw_only"] == "0"


# --- a product path stays inside the volume ------------------------------

def test_an_absolute_product_path_reads_nothing_and_is_named(tmp_path, caplog):
    """`C:/ProgramData/...` is the natural shape to paste in from a vendor's
    documentation. Left alone it reads the EXAMINER's own machine and files it
    under the subject's name -- and then crashes the parser on relative_to."""
    evidence = tmp_path / "evidence"
    _write(evidence, "ProgramData/Emsisoft/Reports/scan.txt", "x\n")
    with caplog.at_level("WARNING", logger="aeng.test"):
        det, prod = _run(tmp_path, asset_text=(
            "Invented | - | C:/ProgramData/Invented/Logs\n"
            "Emsisoft | - | ProgramData/Emsisoft/Reports\n"))
    assert [r["product"] for r in prod] == ["Emsisoft"]
    assert det == []
    assert any("leaves the volume" in r.message for r in caplog.records)


def test_a_product_path_cannot_walk_out_of_the_volume(tmp_path):
    """`..` would reach another machine's output tree in the same case."""
    assert not A.contained("../other/Logs")
    assert not A.contained("ProgramData/../../x")
    assert A.contained("ProgramData/Emsisoft/Reports")
    assert A.contained("Users/%user%/AppData/Roaming/Invented/Logs")
    det, prod = _run(tmp_path, asset_text="Invented | - | ../other/Logs\n")
    assert det == [] and prod == []


def test_an_absolute_glob_never_reaches_glob_at_all(tmp_path):
    """`Path.glob` raises NotImplementedError -- not an OSError -- on an absolute
    pattern, so the containment check has to come FIRST: catching the exception
    afterwards would mean the read had already been attempted."""
    assert A._expand(tmp_path, "C:/Program Files*/Invented/Logs") == []
    assert A._expand(tmp_path, "/etc/*") == []
