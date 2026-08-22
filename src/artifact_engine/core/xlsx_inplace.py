r"""Fill cells in an existing .xlsx without disturbing anything else in it.

The obvious way to do this is to load the workbook with openpyxl and save it
back. Measured on the event-log template this engine writes into, that round trip
**destroys all 9 data validations, across five sheets**: openpyxl does not support
the `x14` validation extension and drops it on save, taking every dropdown the
analyst picks values from with it. The standard-namespace validations survive; the ones
that matter here do not. Nothing warns the analyst -- the file opens, the sheet
looks right, and the lists are simply gone.

So this writes the file the way a patch writes a file. The workbook is a zip of
XML parts; only the one sheet being filled is rewritten, every other entry is
copied across byte for byte, and inside that sheet only `<c>` elements change.
Styles, column widths, the autofilter, conditional formatting and the `<extLst>`
holding those validations are never parsed, so they cannot be lost.

Values are written as INLINE strings. Shared strings would mean editing a second
part and renumbering indices that other sheets point into; inline text costs a few
bytes and touches nothing outside the cell.
"""
from __future__ import annotations

import html
import re
import shutil
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

# `<c r="B7" s="14" t="s"><v>12</v></c>` or the self-closing `<c r="B7" s="14"/>`
_CELL = re.compile(r'<c\s+r="(?P<ref>[A-Z]+\d+)"(?P<attrs>[^>]*?)(?:/>|>(?P<body>.*?)</c>)',
                   re.DOTALL)
_ROW = re.compile(r'<row\s[^>]*?r="(?P<n>\d+)"[^>]*?(?:/>|>(?P<body>.*?)</row>)', re.DOTALL)
_STYLE = re.compile(r'\ss="(\d+)"')


def column_letter(index: int) -> str:
    """1 -> A, 26 -> Z, 27 -> AA."""
    if index < 1:
        raise ValueError(f"column index starts at 1, got {index}")
    out = ""
    while index:
        index, rem = divmod(index - 1, 26)
        out = chr(65 + rem) + out
    return out


def sheet_part_for(xlsx: Path, sheet_name: str) -> str:
    """The zip entry holding `sheet_name`, resolved the way Excel resolves it.

    Sheet order in workbook.xml is NOT the order of the sheetN.xml files, and the
    numbers do not line up either: a workbook whose first tab is `sheet1.xml` is a
    coincidence, not a rule. Follow the relationship id, like a reader would.
    """
    with zipfile.ZipFile(xlsx) as z:
        book = z.read("xl/workbook.xml").decode("utf-8")
        rels = z.read("xl/_rels/workbook.xml.rels").decode("utf-8")
    rid = None
    for m in re.finditer(r'<sheet[^>]*?name="([^"]*)"[^>]*?r:id="(rId\d+)"', book):
        if _unescape(m.group(1)) == sheet_name:
            rid = m.group(2)
            break
    if rid is None:
        raise KeyError(f"no sheet named {sheet_name!r} in {xlsx.name}")
    for m in re.finditer(r'Id="(rId\d+)"[^>]*?Target="([^"]+)"', rels):
        if m.group(1) == rid:
            target = m.group(2).lstrip("/")
            return target if target.startswith("xl/") else f"xl/{target}"
    raise KeyError(f"{sheet_name!r} resolves to {rid}, which has no target")


def _unescape(s: str) -> str:
    """XML text back to characters, NUMERIC references included.

    The five named entities are not the whole story: a sheet named `Bitàcola` can
    reach the file as `Bit&#224;cola`, and a writer that only knew `&amp;` and
    friends would look for a sheet by that literal name, fail to find it, and
    report the workbook as having no such tab.
    """
    return html.unescape(s)


def read_rows(xlsx: Path, sheet_name: str, shared: list[str] | None = None) -> dict[int, dict[str, str]]:
    """{row number: {column letter: text}} for the cells that carry a value.

    Enough to tell an empty template row from a filled one, which is all the
    caller needs to know to avoid overwriting an analyst's work.
    """
    part = sheet_part_for(xlsx, sheet_name)
    with zipfile.ZipFile(xlsx) as z:
        xml = z.read(part).decode("utf-8")
        if shared is None:
            shared = _shared_strings(z)
    out: dict[int, dict[str, str]] = {}
    for row in _ROW.finditer(xml):
        body = row.group("body")
        if not body:
            continue
        cells: dict[str, str] = {}
        for c in _CELL.finditer(body):
            text = _cell_text(c.group("attrs") or "", c.group("body") or "", shared)
            if text:
                cells[_col_of(c.group("ref"))] = text
        if cells:
            out[int(row.group("n"))] = cells
    return out


def _shared_strings(z: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in z.namelist():
        return []
    xml = z.read("xl/sharedStrings.xml").decode("utf-8")
    # a shared string can be split across several <t> runs; join them
    return ["".join(re.findall(r"<t[^>]*>(.*?)</t>", si, re.DOTALL))
            for si in re.findall(r"<si>(.*?)</si>", xml, re.DOTALL)]


def _cell_text(attrs: str, body: str, shared: list[str]) -> str:
    if 't="inlineStr"' in attrs:
        return _unescape("".join(re.findall(r"<t[^>]*>(.*?)</t>", body, re.DOTALL)))
    v = re.search(r"<v>(.*?)</v>", body, re.DOTALL)
    if not v:
        return ""
    if 't="s"' in attrs:
        try:
            return _unescape(shared[int(v.group(1))])
        except (ValueError, IndexError):
            return ""
    return _unescape(v.group(1))


def _col_of(ref: str) -> str:
    return re.match(r"([A-Z]+)", ref).group(1)


def _render_cell(ref: str, style: str, value: str) -> str:
    if value == "":
        return f'<c r="{ref}"{style}/>'
    return (f'<c r="{ref}"{style} t="inlineStr"><is><t xml:space="preserve">'
            f'{escape(value)}</t></is></c>')


def write_cells(xlsx: Path, sheet_name: str, cells: dict[int, dict[str, str]]) -> int:
    """Set `{row: {column letter: text}}` in place. Returns the rows touched.

    A cell that already exists keeps its style: the template's rows are
    pre-formatted (dates, borders, the fill that marks a section) and a cell
    rewritten without its `s=` would render as raw text in the middle of a styled
    sheet. A cell that does not exist yet is created without a style, which is
    what an empty column in that row looked like anyway.
    """
    part = sheet_part_for(xlsx, sheet_name)
    with zipfile.ZipFile(xlsx) as z:
        entries = [(i, z.read(i.filename)) for i in z.infolist()]
    xml = next(data for info, data in entries if info.filename == part).decode("utf-8")

    touched = 0
    for row_no in sorted(cells):
        wanted = {c.upper(): v for c, v in cells[row_no].items()}
        m = re.search(rf'<row\s[^>]*?r="{row_no}"[^>]*?(?:/>|>.*?</row>)', xml, re.DOTALL)
        if not m:
            raise KeyError(f"row {row_no} is not in the sheet; this writer fills "
                           f"existing template rows, it does not extend the sheet")
        block = m.group(0)
        # `<row r="7" .../>` is how Excel writes a formatted but EMPTY row, and it
        # is most of a fresh template. It cannot be told apart by matching up to
        # the first `>` -- that matches the self-closing one too, and slicing on
        # its length then eats into the attributes. The closing tells them apart.
        if block.endswith("/>"):
            open_tag_text = block[:-2].rstrip() + ">"
            body = ""
        else:
            open_tag_text = re.match(r"<row\s[^>]*?>", block, re.DOTALL).group(0)
            body = block[len(open_tag_text):-len("</row>")]

        existing = {_col_of(c.group("ref")): c for c in _CELL.finditer(body)}
        rendered: dict[str, str] = {}
        for col, cell in existing.items():
            keep = _STYLE.search(cell.group("attrs") or "")
            rendered[col] = (_render_cell(f"{col}{row_no}",
                                          f' s="{keep.group(1)}"' if keep else "",
                                          wanted[col])
                             if col in wanted else cell.group(0))
        for col, value in wanted.items():
            if col not in rendered:
                rendered[col] = _render_cell(f"{col}{row_no}", "", value)

        ordered = "".join(rendered[c] for c in sorted(rendered, key=_col_sort))
        xml = xml[:m.start()] + open_tag_text + ordered + "</row>" + xml[m.end():]
        touched += 1

    tmp = xlsx.with_suffix(".xlsx.tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as out:
        for info, data in entries:
            out.writestr(info, xml.encode("utf-8") if info.filename == part else data)
    shutil.move(str(tmp), str(xlsx))
    return touched


def _col_sort(col: str) -> tuple[int, str]:
    return (len(col), col)
