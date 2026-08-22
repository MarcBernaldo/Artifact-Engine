"""Rows for the incident event log, and the limits on what they may claim."""
import csv
import zipfile
from pathlib import Path

import pytest

from artifact_engine.core import bitacola as B
from artifact_engine.core import xlsx_inplace as xi

_CT = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
</Types>"""
_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""
_WORKBOOK = """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Bit&#224;cola" sheetId="1" r:id="rId1"/><sheet name="Llegenda" sheetId="2" r:id="rId2"/></sheets>
</workbook>"""
_WB_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
</Relationships>"""


def _cell(ref: str, text: str) -> str:
    return f'<c r="{ref}" t="inlineStr"><is><t>{text}</t></is></c>'


def _sheet(rows: dict[int, dict[str, str]], last: int) -> str:
    body = []
    for n in range(1, last + 1):
        cells = "".join(_cell(f"{c}{n}", v) for c, v in sorted(rows.get(n, {}).items()))
        body.append(f'<row r="{n}" spans="1:12">{cells}</row>' if cells
                    else f'<row r="{n}" spans="1:12"/>')
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f'<sheetData>{"".join(body)}</sheetData>'
            '<extLst><ext uri="{X}"><x14:dataValidation xmlns:x14="u"/></ext></extLst>'
            '</worksheet>')


HEADER = {"A": "Tipus", "B": "Data esdeveniment (UTC)", "C": "Data entrada fila",
          "D": "Host", "E": "Domini", "F": "Source", "G": "Destination",
          "H": "Usuari", "I": "Rellevància", "J": "Tàctica", "K": "Descripció",
          "L": "Font Evidència"}

# The vocabularies the template validates against, in their own sheet.
LEGEND = {1: {"A": "Esdeveniment", "C": "Confirmat", "K": "Reconeixement"},
          2: {"A": "Alerta", "C": "Potser", "K": "Accés Inicial"},
          3: {"A": "Contramesura", "C": "Descartat", "K": "Accés a Credencials"},
          4: {"C": "Clau", "K": "Descobriment"},
          5: {"K": "Moviment Lateral"}}


@pytest.fixture
def book(tmp_path) -> Path:
    """A template with a header, ten empty rows, and a legend to validate against."""
    p = tmp_path / "bitacola.xlsx"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CT)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("xl/workbook.xml", _WORKBOOK)
        z.writestr("xl/_rels/workbook.xml.rels", _WB_RELS)
        # every row pre-filled with `Esdeveniment` in A, exactly like the real one
        rows = {1: HEADER}
        for n in range(2, 12):
            rows[n] = {"A": "Esdeveniment"}
        z.writestr("xl/worksheets/sheet1.xml", _sheet(rows, 11))
        z.writestr("xl/worksheets/sheet2.xml", _sheet(LEGEND, 5))
    return p


def _lateral(tmp_path: Path, rows: list[dict]) -> Path:
    cols = ["src", "dst", "user", "logon_type", "event_id", "status", "count",
            "first_seen_utc", "last_seen_utc", "src_in_case", "suspicious",
            "reasons", "chainsaw"]
    p = tmp_path / "lateral_movement.csv"
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})
    return p


def _edge(**kw) -> dict:
    base = {"src": "HOST-01", "dst": "HOST-02", "user": "CORP\\jdoe",
            "logon_type": "network", "event_id": "4624", "status": "ok",
            "count": "1", "first_seen_utc": "2026-03-14T09:00:00Z",
            "suspicious": "yes", "reasons": "case_to_case"}
    base.update(kw)
    return base


def test_the_tool_never_marks_its_own_finding_as_confirmed(tmp_path):
    """`Rellevància` is a confirmation state in this template, not a severity:
    Confirmat / Potser / Descartat / Clau. A row derived from a CSV is a
    hypothesis, and writing it in as confirmed would put the tool's name behind a
    judgement only the analyst can make -- in the document the analyst will later
    defend."""
    entries = B.from_lateral(_lateral(tmp_path, [_edge(), _edge(src="10.0.0.5")]))
    assert entries
    assert {e.relevance for e in entries} == {"Potser"}
    assert B.RELEVANCE_UNCONFIRMED == "Potser"


def test_the_first_matching_reason_decides_the_tactic():
    """Order is the judgement: an edge from a routable source is initial access
    before it is movement, and a failure is about credentials whatever mechanism
    carried it. An edge carrying both must not depend on dict ordering."""
    assert B.tactic_for("rdp_public+case_to_case+chain") == B.T_INITIAL_ACCESS
    assert B.tactic_for("case_to_case+rdp_public") == B.T_INITIAL_ACCESS
    assert B.tactic_for("failed_logon+typed_unc") == B.T_CREDENTIAL_ACCESS
    assert B.tactic_for("anonymous_logon") == B.T_DISCOVERY
    assert B.tactic_for("case_to_case") == B.T_LATERAL
    assert B.tactic_for("") == "", "an edge with no reason must not be given a tactic"
    assert B.tactic_for("something_new") == "", "an unknown reason is not a guess"


def test_only_the_edges_the_graph_flagged_become_rows(tmp_path):
    """lateral_movement.csv is the COMPLETE edge list by design -- a routine estate
    puts thousands of ordinary logons in it. Copying those into the event log
    would bury the incident in the evidence of a working network."""
    p = _lateral(tmp_path, [_edge(), _edge(dst="HOST-09", suspicious="")])
    assert [e.destination for e in B.from_lateral(p)] == ["HOST-02"]
    assert len(B.from_lateral(p, only_suspicious=False)) == 2


def test_a_rule_that_fired_is_an_alert_not_an_event(tmp_path):
    rows = B.from_lateral(_lateral(tmp_path, [
        _edge(chainsaw="Account Brute Force"), _edge(dst="HOST-03")]))
    by_dst = {e.destination: e.tipus for e in rows}
    assert by_dst == {"HOST-02": B.TIPUS_ALERT, "HOST-03": B.TIPUS_EVENT}


def test_the_account_domain_is_split_out_for_its_own_column(tmp_path):
    rows = B.from_lateral(_lateral(tmp_path, [
        _edge(user="CORP\\jdoe"), _edge(dst="HOST-03", user="ANONYMOUS LOGON")]))
    assert (rows[0].domain, rows[0].user) == ("CORP", "CORP\\jdoe")
    assert rows[1].domain == "", "an account with no domain must not invent one"


def test_writing_twice_adds_nothing_the_second_time(book, tmp_path):
    """The tool writes directly into the analyst's working file, so a re-run after
    parsing more evidence has to be safe. Identity is the finding, not the wording:
    a row whose description was rewritten is still the same row."""
    entries = B.from_lateral(_lateral(tmp_path, [_edge(), _edge(dst="HOST-03")]))
    assert B.write(book, entries) == (2, 0, 0)
    assert B.write(book, entries) == (0, 2, 0)

    entries[0].description = "reworded by hand"
    assert B.write(book, entries) == (0, 2, 0), "rewording made it a new row"


def test_a_row_the_analyst_filled_is_never_written_over(book, tmp_path):
    """Rows are found by being empty, and the template pre-fills column A on every
    one of them. A writer that only looked for a blank row would find none; one
    that ignored column A alone would overwrite the analyst's first entry."""
    xi.write_cells(book, B.SHEET, {2: {"B": "2026-01-01T00:00:00Z", "K": "escrit a ma"}})
    B.write(book, B.from_lateral(_lateral(tmp_path, [_edge()])))
    rows = xi.read_rows(book, B.SHEET)
    assert rows[2]["K"] == "escrit a ma"
    assert rows[3]["K"], "the generated row did not land on the next free line"


def test_more_findings_than_rows_is_reported_not_silently_dropped(book, tmp_path, caplog):
    """The template ships with a fixed number of rows. Dropping the overflow would
    lose findings from an incident, and in a document meant to be complete that is
    the worst possible failure: it looks finished."""
    import logging
    many = [_edge(dst=f"HOST-{i:02d}", first_seen_utc=f"2026-03-14T09:{i:02d}:00Z")
            for i in range(20)]
    with caplog.at_level(logging.WARNING, logger="aeng"):
        written, _, unplaced = B.write(book, B.from_lateral(_lateral(tmp_path, many)))
    assert written == 10 and unplaced == 10
    assert any("nowhere to go" in r.message for r in caplog.records)


def test_it_refuses_to_write_a_value_the_workbook_no_longer_offers(book, tmp_path):
    """Excel does not reject an out-of-list value in a validated cell -- it accepts
    it and the dropdown for that cell stops working. So a legend that was edited or
    translated has to stop the write, not produce a workbook that looks fine and
    has one broken cell per row."""
    assert B.check_vocabulary(book) == []

    broken = tmp_path / "broken.xlsx"
    broken.write_bytes(book.read_bytes())
    xi.write_cells(broken, "Llegenda", {3: {"K": "Credential Access"}})   # translated
    assert B.check_vocabulary(broken) == [B.T_CREDENTIAL_ACCESS]
    with pytest.raises(ValueError, match="break the dropdown"):
        B.write(broken, B.from_lateral(_lateral(tmp_path, [_edge()])))


def test_the_description_only_repeats_what_the_row_already_says(tmp_path):
    """The prose is a reading aid, not a finding. Every clause has to be checkable
    against the CSV, because a sentence that adds a fact is a sentence nobody can
    trace back to evidence."""
    row = {"src": "10.0.0.5", "dst": "HOST-02", "user": "CORP\\jdoe",
           "logon_type": "rdp", "status": "failed", "count": "41",
           "reasons": "failed_logon", "chainsaw": "Account Brute Force"}
    text = B.describe(row, B.T_CREDENTIAL_ACCESS)
    for value in ("10.0.0.5", "HOST-02", "CORP\\jdoe", "rdp", "41", "Account Brute Force"):
        assert value in text, f"{value!r} was dropped from the description"
    assert "fallit" in text, "a failed logon must not read as a successful one"


def test_no_case_data_reaches_the_row_without_naming_its_source(tmp_path):
    """Every row has to say which file it came from. A timeline entry nobody can
    trace back to an artifact cannot be defended, and this tool produces rows for a
    document that may be read by people who were not in the room."""
    entries = B.from_lateral(_lateral(tmp_path, [_edge(), _edge(dst="HOST-03")]))
    assert {e.evidence for e in entries} == {"lateral_movement.csv"}


def test_a_missing_graph_is_not_an_error(tmp_path):
    """`aeng lateral` may not have run, or the case may have no Windows logons at
    all. That is a case with no rows, not a failure."""
    assert B.from_lateral(tmp_path / "nope.csv") == []


def test_the_command_refuses_rather_than_guessing_where_to_write(book, tmp_path):
    """Both paths are required and both are checked: this writes into a file the
    analyst is working in, so a typo must stop it rather than create a workbook
    somewhere or fill the wrong one."""
    import argparse

    from artifact_engine import cli

    def run(**kw):
        args = argparse.Namespace(path=str(tmp_path), xlsx=str(book), all_edges=False,
                                  dry_run=False, verbose=False)
        for k, v in kw.items():
            setattr(args, k, v)
        return cli.cmd_bitacola(args)

    assert run(path=str(tmp_path / "nope")) == 1
    assert run(xlsx=str(tmp_path / "nope.xlsx")) == 1


def test_a_dry_run_leaves_the_workbook_byte_identical(book, tmp_path):
    """The point of --dry-run on a file someone else is editing."""
    import argparse

    from artifact_engine import cli

    _lateral(tmp_path, [_edge()])
    before = book.read_bytes()
    rc = cli.cmd_bitacola(argparse.Namespace(
        path=str(tmp_path), xlsx=str(book), all_edges=False, dry_run=True, verbose=False))
    assert rc == 0
    assert book.read_bytes() == before


def test_a_case_with_no_graph_is_reported_and_not_a_failure(book, tmp_path, caplog):
    """`aeng lateral` may not have run, or the case may carry no Windows logons.
    Exiting non-zero would make a wrapper treat an ordinary case as broken."""
    import argparse
    import logging

    from artifact_engine import cli

    with caplog.at_level(logging.WARNING, logger="aeng"):
        rc = cli.cmd_bitacola(argparse.Namespace(
            path=str(tmp_path), xlsx=str(book), all_edges=False,
            dry_run=False, verbose=False))
    assert rc == 0
    assert any("nothing to add" in r.message for r in caplog.records)
