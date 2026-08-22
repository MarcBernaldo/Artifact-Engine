"""The in-place .xlsx writer, and the reason it exists.

The fixture is built by hand rather than with a library because the whole point
is what a library throws away: openpyxl cannot represent an `x14` data validation
and silently drops it on save. Measured on the real event-log template this writes
into, a load-and-save round trip removed all 9 of them, spread across five sheets,
taking every dropdown with them. So the fixture carries one, and the tests check it is
still there afterwards.
"""
import re
import zipfile
from pathlib import Path

import pytest

from artifact_engine.core import xlsx_inplace as xi

_CT = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
</Types>"""

_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

# Deliberately out of order: the second TAB is the first sheetN.xml file. A writer
# that assumes tab order matches file numbering silently edits the wrong sheet.
_WORKBOOK = """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Llegenda" sheetId="1" r:id="rId2"/><sheet name="Bit&#224;cola" sheetId="2" r:id="rId1"/></sheets>
</workbook>"""

_WB_RELS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
</Relationships>"""

_SHARED = """<?xml version="1.0" encoding="UTF-8"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="3" uniqueCount="3">
<si><t>Tipus</t></si><si><t>Esdeveniment</t></si><si><t>Host</t></si></sst>"""

# Row 2 is a pre-formatted template row: a shared string in A, a styled empty B,
# and nothing else. Row 3 is the self-closing form. The extLst at the end is the
# part every library-based approach loses.
_SHEET1 = """<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>
<row r="1" spans="1:4"><c r="A1" t="s"><v>0</v></c><c r="D1" t="s"><v>2</v></c></row>
<row r="2" spans="1:4" ht="15" customHeight="1"><c r="A2" s="3" t="s"><v>1</v></c><c r="B2" s="14"/></row>
<row r="3" spans="1:4" ht="15" customHeight="1"/>
</sheetData>
<autoFilter ref="A1:L110"/>
<extLst><ext uri="{CCE6A557-97BC-4b89-ADB6-D9C93CAAB3DF}"><x14:dataValidations xmlns:x14="http://schemas.microsoft.com/office/spreadsheetml/2009/9/main" count="1"><x14:dataValidation type="list" allowBlank="1"><x14:formula1><xm:f xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">Llegenda!$A$2:$A$4</xm:f></x14:formula1><xm:sqref xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">A2:A140</xm:sqref></x14:dataValidation></x14:dataValidations></ext></extLst>
</worksheet>"""

_SHEET2 = """<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row r="1" spans="1:1"><c r="A1" t="inlineStr"><is><t>Esdeveniment</t></is></c></row></sheetData>
</worksheet>"""


@pytest.fixture
def book(tmp_path) -> Path:
    p = tmp_path / "bitacola.xlsx"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CT)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("xl/workbook.xml", _WORKBOOK)
        z.writestr("xl/_rels/workbook.xml.rels", _WB_RELS)
        z.writestr("xl/sharedStrings.xml", _SHARED)
        z.writestr("xl/worksheets/sheet1.xml", _SHEET1)
        z.writestr("xl/worksheets/sheet2.xml", _SHEET2)
    return p


def _x14_count(p: Path) -> int:
    # the opening tag of a validation, not every mention of the word: the plural
    # `<x14:dataValidations>` container and both closing tags share the substring
    with zipfile.ZipFile(p) as z:
        return sum(len(re.findall(r"<x14:dataValidation\s", z.read(n).decode("utf-8")))
                   for n in z.namelist() if "worksheets/sheet" in n)


def test_the_dropdowns_survive_being_written_into(book):
    """The reason this module exists instead of three lines of openpyxl. A load
    and save through a library that cannot represent the x14 extension removes it,
    and the analyst finds out when a dropdown they rely on is an empty cell."""
    assert _x14_count(book) == 1
    xi.write_cells(book, "Bitàcola", {2: {"C": "10.0.0.5"}})
    assert _x14_count(book) == 1, "the validation was dropped by the write"


def test_everything_not_being_written_is_copied_byte_for_byte(book):
    """Only the target sheet is rewritten. Anything else -- styles, the other
    sheets, shared strings, the parts this code never parses -- must come out of
    the zip identical, because what is not touched cannot be corrupted."""
    with zipfile.ZipFile(book) as z:
        before = {n: z.read(n) for n in z.namelist()}
    xi.write_cells(book, "Bitàcola", {2: {"C": "x"}})
    with zipfile.ZipFile(book) as z:
        after = {n: z.read(n) for n in z.namelist()}

    assert set(before) == set(after), "an entry appeared or vanished"
    changed = [n for n in before if before[n] != after[n]]
    assert changed == ["xl/worksheets/sheet1.xml"], f"also rewrote {changed}"


def test_the_sheet_is_found_by_name_not_by_file_number(book):
    """Tab order is not file order: this workbook's FIRST tab is sheet2.xml. A
    writer that guessed would fill the legend and report success."""
    assert xi.sheet_part_for(book, "Bitàcola") == "xl/worksheets/sheet1.xml"
    assert xi.sheet_part_for(book, "Llegenda") == "xl/worksheets/sheet2.xml"
    with pytest.raises(KeyError):
        xi.sheet_part_for(book, "Nope")


def test_a_filled_cell_keeps_the_style_the_template_gave_it(book):
    """Template rows are pre-formatted -- a date column, borders, the fill that
    marks a block. A cell rewritten without its `s=` renders as raw text in the
    middle of a styled sheet, which looks like corruption to whoever opens it."""
    xi.write_cells(book, "Bitàcola", {2: {"B": "2026-03-14T08:21:00Z"}})
    with zipfile.ZipFile(book) as z:
        xml = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
    cell = re.search(r'<c r="B2"[^>]*', xml).group(0)
    assert 's="14"' in cell, f"style lost: {cell}"
    assert 's="3"' in re.search(r'<c r="A2"[^>]*', xml).group(0), "untouched cell changed"


def test_a_value_already_in_the_row_is_left_alone(book):
    """Column A carries `Esdeveniment` from the template. Filling the rest of the
    row must not disturb it -- and it is a SHARED string, so a writer that
    rewrote every cell as inline text would have to renumber the shared table."""
    xi.write_cells(book, "Bitàcola", {2: {"C": "10.0.0.5"}})
    rows = xi.read_rows(book, "Bitàcola")
    assert rows[2]["A"] == "Esdeveniment"
    assert rows[2]["C"] == "10.0.0.5"


def test_an_empty_self_closing_row_can_still_be_filled(book):
    """`<row r="3" .../>` is how Excel writes a formatted but empty row, and it is
    most of a fresh template. Treating it as absent would make the writer refuse
    to fill exactly the rows it is meant to fill."""
    xi.write_cells(book, "Bitàcola", {3: {"A": "Alerta", "D": "HOST-01"}})
    rows = xi.read_rows(book, "Bitàcola")
    assert rows[3] == {"A": "Alerta", "D": "HOST-01"}


def test_text_that_would_break_the_xml_is_escaped(book):
    """Evidence text is attacker-influenced: a username or a path can carry `<`,
    `&` or a quote. Written raw it does not corrupt a cell, it corrupts the sheet,
    and the workbook stops opening at all."""
    nasty = 'CORP\\a<b>&"c" \'d\''
    xi.write_cells(book, "Bitàcola", {2: {"C": nasty}})
    from xml.dom.minidom import parseString
    with zipfile.ZipFile(book) as z:
        parseString(z.read("xl/worksheets/sheet1.xml"))      # raises if malformed
    assert xi.read_rows(book, "Bitàcola")[2]["C"] == nasty


def test_refusing_to_write_past_the_end_of_the_template(book):
    """The sheet has three rows. Silently ignoring row 900 would drop findings;
    inventing it would need the dimension, spans and validation ranges extended
    too, which is how a file stops being the template it was."""
    with pytest.raises(KeyError, match="not in the sheet"):
        xi.write_cells(book, "Bitàcola", {900: {"A": "Esdeveniment"}})


def test_column_letters_go_past_z():
    assert [xi.column_letter(i) for i in (1, 12, 26, 27, 28)] == ["A", "L", "Z", "AA", "AB"]
    with pytest.raises(ValueError):
        xi.column_letter(0)
