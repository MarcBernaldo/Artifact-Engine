r"""Ransomware traces, and not reporting every developer workstation.

The extension list this reads is a list of REAL FILE TYPES -- `.frag` is a GLSL
shader, `.razor` a Blazor component, `.enc` and `.lock` are what ordinary
software writes -- so the whole difficulty is that a match cannot be a verdict.
These tests pin what is allowed to turn a count into a finding (a ransom note, or
the double-extension rename shape at volume), the three shapes that look like a
rename and are not, and the list-free kind that exists so the detector is not
limited to families somebody has already published.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _awesome, _ransom
from artifact_engine.handlers import lin_ransomware as L
from artifact_engine.handlers import win_ransomware as W


class _Ctx:
    def __init__(self, evidence: Path, out: Path):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "C"
        self.log = None


_MFT_COLS = ["ParentPath", "FileName", "Extension", "IsDirectory",
             "LastModified0x10", "Created0x10", "FileSize"]

_WHEN = "2026-05-19 11:22:33.0000000"


def _write_mft(tmp_path: Path, files: list[tuple[str, str, str]]) -> None:
    """(parent, filename, modified) rows, plus a DIRECTORY carrying a ransom-note
    name -- every test then proves directories are never traces."""
    d = tmp_path / "CSVs" / "Filesystem"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "MFT.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_MFT_COLS)
        w.writeheader()
        w.writerow({c: "" for c in _MFT_COLS} |
                   {"ParentPath": ".\\Users", "FileName": "HOW_TO_DECRYPT.txt",
                    "IsDirectory": "True"})
        for parent, name, when in files:
            w.writerow({c: "" for c in _MFT_COLS} |
                       {"ParentPath": parent, "FileName": name,
                        "LastModified0x10": when})


def _write_bodyfile(tmp_path: Path, files: list[tuple[str, str]]) -> None:
    d = tmp_path / "CSVs" / "Filesystem"
    d.mkdir(parents=True, exist_ok=True)
    cols = ["name", "mode", "uid", "size", "atime_utc", "mtime_utc", "ctime_utc",
            "crtime_utc"]
    with (d / "bodyfile.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerow({c: "" for c in cols} |
                   {"name": "/srv/share/HOW_TO_DECRYPT.txt",
                    "mode": "d/drwxr-xr-x"})
        for path, when in files:
            w.writerow({c: "" for c in cols} |
                       {"name": path, "mode": "-/-rw-r--r--", "mtime_utc": when})


def _write_lists(tmp_path: Path, notes: list[dict] | None = None,
                 exts: list[dict] | None = None) -> None:
    d = tmp_path / _awesome.DIR
    d.mkdir(parents=True, exist_ok=True)
    ncols = ["file_name", "metadata_description", "metadata_link"]
    with (d / _ransom.NOTES_LIST).open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=ncols)
        w.writeheader()
        for r in notes or []:
            w.writerow({c: r.get(c, "") for c in ncols})
    ecols = ["file_path", "metadata_comment"]
    with (d / _ransom.EXTENSIONS_LIST).open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=ecols)
        w.writeheader()
        for r in exts or []:
            w.writerow({c: r.get(c, "") for c in ecols})


_NOTE = [{"file_name": "HOW_TO_DECRYPT.txt",
          "metadata_description": "Example ransomware",
          "metadata_link": "https://example.invalid/report"}]
_EXT = [{"file_path": "*.razor", "metadata_comment": "Example ransomware"},
        {"file_path": "*.jackpot*", "metadata_comment": "MedusaLocker variant"}]


def _read(tmp_path: Path) -> list[dict]:
    p = tmp_path / "out" / "ransomware_traces.csv"
    if not p.is_file():
        return []
    with p.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _run_win(tmp_path: Path, files, notes=None, exts=None) -> list[dict]:
    _write_mft(tmp_path, files)
    _write_lists(tmp_path, notes, exts)
    W.run(_Ctx(tmp_path, tmp_path / "out"))
    return _read(tmp_path)


def _run_lin(tmp_path: Path, files, notes=None, exts=None) -> list[dict]:
    _write_bodyfile(tmp_path, files)
    _write_lists(tmp_path, notes, exts)
    L.run(_Ctx(tmp_path, tmp_path / "out"))
    return _read(tmp_path)


def _by_kind(rows: list[dict], kind: str) -> list[dict]:
    return [r for r in rows if r["kind"] == kind]


# --------------------------------------------------------------------------- #
# The note
# --------------------------------------------------------------------------- #
def test_one_ransom_note_is_a_finding_on_its_own(tmp_path):
    """That filename occurs for one reason."""
    rows = _run_win(tmp_path, [(r".\Users\jdoe", "HOW_TO_DECRYPT.txt", _WHEN)],
                    notes=_NOTE, exts=_EXT)
    note = _by_kind(rows, "note")[0]
    assert note["suspicious"] == "yes"
    assert note["family"] == "Example ransomware"
    assert note["reference"].startswith("https://")


def test_a_note_counts_the_directories_it_was_dropped_in(tmp_path):
    """A note in every directory is the footprint of the run, not one file."""
    rows = _run_win(tmp_path, [
        (rf".\Share\dir{i}", "HOW_TO_DECRYPT.txt", _WHEN) for i in range(40)
    ], notes=_NOTE, exts=_EXT)
    note = _by_kind(rows, "note")[0]
    assert note["files"] == "40" and note["directories"] == "40"


def test_a_note_corroborates_an_extension_group_that_could_not_stand_alone(tmp_path):
    """Six `.razor` files are a project. Six `.razor` files next to a ransom note
    are the same six files with an answer beside them."""
    files = [(r".\App\Pages", f"Page{i}.razor", _WHEN) for i in range(6)]
    quiet = _run_win(tmp_path, files, notes=_NOTE, exts=_EXT)
    assert _by_kind(quiet, "renamed")[0]["suspicious"] == ""

    loud = _run_win(tmp_path, files + [(r".\App", "HOW_TO_DECRYPT.txt", _WHEN)],
                    notes=_NOTE, exts=_EXT)
    assert _by_kind(loud, "renamed")[0]["suspicious"] == "yes"
    assert "ransom note" in _by_kind(loud, "renamed")[0]["note"]


# --------------------------------------------------------------------------- #
# A match is a count, never a verdict
# --------------------------------------------------------------------------- #
def test_a_project_full_of_a_listed_extension_is_reported_unflagged(tmp_path):
    """`.razor` is on the list and is also a Blazor component. Six hundred of them
    checked out in one second is a git clone."""
    rows = _run_win(tmp_path, [
        (rf".\repo\Pages\d{i % 30}", f"Component{i}.razor", _WHEN)
        for i in range(600)
    ], notes=_NOTE, exts=_EXT)
    grp = _by_kind(rows, "renamed")[0]
    assert grp["files"] == "600" and grp["suspicious"] == ""
    assert "real file type" in grp["note"]


def test_the_rename_shape_at_volume_is_the_finding(tmp_path):
    """`report.docx.razor` is not a component. Fifty of them are a run."""
    rows = _run_win(tmp_path, [
        (rf".\Share\d{i % 20}", f"report{i}.docx.razor", _WHEN) for i in range(60)
    ], notes=_NOTE, exts=_EXT)
    grp = _by_kind(rows, "renamed")[0]
    assert grp["suspicious"] == "yes"
    assert grp["double_extension"] == "60"


def test_the_rename_shape_below_the_burst_says_what_it_is_short_of(tmp_path):
    rows = _run_win(tmp_path, [
        (r".\Share", f"report{i}.docx.razor", _WHEN) for i in range(6)
    ], notes=_NOTE, exts=_EXT)
    grp = _by_kind(rows, "renamed")[0]
    assert grp["suspicious"] == ""
    assert "fewer than the 50" in grp["note"]


def test_a_single_listed_extension_is_counted_not_listed(tmp_path):
    """One `.razor` on a machine is not worth a row, and the row that says so
    is how the table stays honest about what it dropped."""
    rows = _run_win(tmp_path, [(r".\App", "One.razor", _WHEN)],
                    notes=_NOTE, exts=_EXT)
    assert _by_kind(rows, "renamed") == []
    assert rows[-1]["kind"] == "(not listed)"
    assert "1 extension group(s) below the reporting threshold" in rows[-1]["note"]


# --------------------------------------------------------------------------- #
# The family nobody has published yet
# --------------------------------------------------------------------------- #
def test_an_unlisted_extension_after_a_document_extension_is_a_mass_rename(tmp_path):
    """A detector that can only find what the list names finds last year's
    ransomware."""
    rows = _run_win(tmp_path, [
        (rf".\Share\d{i % 10}", f"invoice{i}.xlsx.a7fk2", _WHEN) for i in range(30)
    ], notes=_NOTE, exts=_EXT)
    grp = _by_kind(rows, "mass_rename")[0]
    assert grp["marker"] == ".a7fk2" and grp["suspicious"] == "yes"


def test_a_compressed_backup_is_not_a_mass_rename(tmp_path):
    """`dump.sql.gz` is a document extension followed by another extension on
    every backup server in existence."""
    rows = _run_win(tmp_path, [
        (r".\Backups", f"dump{i}.sql.gz", _WHEN) for i in range(200)
    ], notes=_NOTE, exts=_EXT)
    assert _by_kind(rows, "mass_rename") == []


def test_a_converted_document_is_not_a_mass_rename(tmp_path):
    rows = _run_win(tmp_path, [
        (r".\Docs", f"report{i}.docx.pdf", _WHEN) for i in range(200)
    ], notes=_NOTE, exts=_EXT)
    assert _by_kind(rows, "mass_rename") == []


def test_a_rotated_or_split_file_is_not_a_mass_rename(tmp_path):
    rows = _run_win(tmp_path, [
        (r".\Archive", f"volume{i}.zip.001", _WHEN) for i in range(200)
    ], notes=_NOTE, exts=_EXT)
    assert _by_kind(rows, "mass_rename") == []


def test_a_handful_of_the_shape_is_not_a_run(tmp_path):
    rows = _run_win(tmp_path, [
        (r".\Share", f"x{i}.docx.a7fk2", _WHEN) for i in range(5)
    ], notes=_NOTE, exts=_EXT)
    assert _by_kind(rows, "mass_rename") == []


def test_the_shape_test_reads_the_last_two_components(tmp_path):
    assert _ransom.extensions("report.docx.locked") == ("docx", "locked")
    assert _ransom.extensions("Counter.razor") == ("", "razor")
    assert _ransom.extensions("noextension") == ("", "")
    assert _ransom.unpublished_rename("docx", "a7fk2")
    assert not _ransom.unpublished_rename("", "a7fk2")
    assert not _ransom.unpublished_rename("sql", "gz")
    assert not _ransom.unpublished_rename("docx", "pdf")
    assert not _ransom.unpublished_rename("docx", "0123")
    assert not _ransom.unpublished_rename("docx", "a" * 20)


# --------------------------------------------------------------------------- #
# The window, and the two listings
# --------------------------------------------------------------------------- #
def test_the_window_is_the_write_not_the_creation(tmp_path):
    """A rename in place carries the original creation time forward, so a run that
    renames rather than rewrites would look years old measured that way."""
    rows = _run_win(tmp_path, [
        (r".\Share", "a.docx.a7fk2", "2026-05-19 11:00:00.0000000"),
        (r".\Share", "b.docx.a7fk2", "2026-05-19 12:00:00.0000000"),
    ] + [(r".\Share", f"c{i}.docx.a7fk2", "2026-05-19 11:30:00.0000000")
         for i in range(25)], notes=_NOTE, exts=_EXT)
    grp = _by_kind(rows, "mass_rename")[0]
    assert grp["first_modified_utc"].startswith("2026-05-19 11:00")
    assert grp["last_modified_utc"].startswith("2026-05-19 12:00")
    assert grp["span_hours"] == "1"


def test_the_bodyfile_reaches_the_share(tmp_path):
    """Linux ransomware is where the shares are: a datastore or an export is an
    ordinary directory here."""
    rows = _run_lin(tmp_path, [
        (f"/srv/share/dept{i % 12}/invoice{i}.xlsx.a7fk2", _WHEN) for i in range(40)
    ] + [("/srv/share/HOW_TO_DECRYPT.txt", _WHEN)], notes=_NOTE, exts=_EXT)
    assert _by_kind(rows, "note")[0]["suspicious"] == "yes"
    mass = _by_kind(rows, "mass_rename")[0]
    assert mass["files"] == "40" and mass["directories"] == "12"


def test_a_directory_is_never_a_trace(tmp_path):
    """Both listings carry a DIRECTORY named `HOW_TO_DECRYPT.txt` in every test
    above. A handler that reads the name without the directory bit reports a
    ransom note on every volume in the case."""
    assert _run_lin(tmp_path, [], notes=_NOTE, exts=_EXT) == []
    assert _run_win(tmp_path, [], notes=_NOTE, exts=_EXT) == []


def test_the_list_free_kind_survives_a_missing_list(tmp_path):
    """The lists arrive with `aeng update`; a fresh install has none, and the
    shape test needs neither of them."""
    _write_mft(tmp_path, [(r".\Share", f"x{i}.docx.a7fk2", _WHEN)
                          for i in range(30)])
    W.run(_Ctx(tmp_path, tmp_path / "out"))
    rows = _read(tmp_path)
    assert _by_kind(rows, "mass_rename")[0]["suspicious"] == "yes"


def test_no_listing_skips(tmp_path):
    with pytest.raises(HandlerSkip):
        W.run(_Ctx(tmp_path, tmp_path / "out"))
    with pytest.raises(HandlerSkip):
        L.run(_Ctx(tmp_path, tmp_path / "out"))
