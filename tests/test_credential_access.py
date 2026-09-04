r"""Credential material staged for collection, and the line between the two.

Every file this looks for is ordinary in its own directory -- `SAM` under
System32\config is the operating system, `Login Data` in a Chrome profile is
Chrome -- so the rule is the LOCATION and the whole difficulty is not reporting
the healthy machine. These tests pin the homes each family is allowed to live in
(WinSxS carries hives literally named SAM on every host), the staging heuristic
that turns scattered files into one row, and the two things the detector must not
lose: the deleted files, and the archive written beside them.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import win_credential_access as C


class _Ctx:
    def __init__(self, evidence: Path, out: Path):
        self.evidence, self.out = evidence, out
        self.tools = self.assets = evidence
        self.machine_name, self.volume = "HOST-01", "C"
        self.log = None


_COLS = ["ParentPath", "FileName", "Extension", "IsDirectory", "InUse",
         "Created0x10", "LastModified0x10", "FileSize"]

_WHEN = "2026-05-19 11:22:33.0000000"


def _f(parent: str, name: str, when: str = _WHEN, in_use: str = "True",
       size: str = "4096") -> dict:
    ext = name[name.rindex("."):] if "." in name else ""
    return {"ParentPath": parent, "FileName": name, "Extension": ext,
            "IsDirectory": "False", "InUse": in_use, "Created0x10": when,
            "LastModified0x10": when, "FileSize": size}


def _run(tmp_path: Path, files: list[dict]) -> list[dict]:
    d = tmp_path / "CSVs" / "Filesystem"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "MFT.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_COLS)
        w.writeheader()
        w.writerow({c: "" for c in _COLS} |
                   {"ParentPath": r".\Windows", "FileName": "Temp",
                    "IsDirectory": "True"})
        for row in files:
            w.writerow({c: row.get(c, "") for c in _COLS})
    C.run(_Ctx(tmp_path, tmp_path / "out"))
    p = tmp_path / "out" / "credential_access.csv"
    if not p.is_file():
        return []
    with p.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _kind(rows: list[dict], kind: str) -> list[dict]:
    return [r for r in rows if r["kind"] == kind]


# --------------------------------------------------------------------------- #
# The rule is the location
# --------------------------------------------------------------------------- #
def test_the_hives_where_they_belong_are_the_operating_system(tmp_path):
    assert _run(tmp_path, [
        _f(r".\Windows\System32\config", "SAM"),
        _f(r".\Windows\System32\config", "SYSTEM"),
        _f(r".\Windows\System32\config", "SECURITY"),
        _f(r".\Windows\System32\config\RegBack", "SAM"),
        _f(r".\Windows\NTDS", "ntds.dit"),
        _f(r".\Windows\repair", "SAM"),
    ]) == []


def test_winsxs_carries_hives_named_sam_on_every_healthy_machine(tmp_path):
    """Servicing keeps the pristine templates there. A detector that reports them
    reports every Windows install in the case."""
    assert _run(tmp_path, [
        _f(r".\Windows\WinSxS\amd64_microsoft-windows-s..ry-hives_31bf_10.0", "SAM"),
        _f(r".\Windows\WinSxS\amd64_microsoft-windows-s..ry-hives_31bf_10.0", "SYSTEM"),
    ]) == []


def test_a_hive_outside_its_path_is_a_finding_on_its_own(tmp_path):
    rows = _run(tmp_path, [_f(r".\Windows\Temp", "SAM.hiv")])
    assert len(rows) == 1
    assert rows[0]["kind"] == "misplaced"
    assert rows[0]["families"] == "registry_hive"
    assert rows[0]["suspicious"] == "yes"


def test_the_browser_stores_inside_a_profile_are_the_browser(tmp_path):
    assert _run(tmp_path, [
        _f(r".\Users\jdoe\AppData\Local\Google\Chrome\User Data\Default",
           "Login Data"),
        _f(r".\Users\jdoe\AppData\Local\Google\Chrome\User Data\Default", "Web Data"),
        _f(r".\Users\jdoe\AppData\Roaming\Mozilla\Firefox\Profiles\ab.default",
           "key4.db"),
        _f(r".\Users\jdoe\AppData\Roaming\Mozilla\Firefox\Profiles\ab.default",
           "logins.json"),
    ]) == []


def test_dpapi_material_inside_its_own_profile_is_not_a_finding(tmp_path):
    assert _run(tmp_path, [
        _f(r".\Users\jdoe\AppData\Roaming\Microsoft\Protect\S-1-5-21-1-2-3",
           "a1b2c3d4-0000-0000-0000-000000000001"),
        _f(r".\Users\jdoe\AppData\Roaming\Microsoft\Protect", "CREDHIST"),
        _f(r".\Users\jdoe\AppData\Local\Microsoft\Vault\4BF4C442", "Policy.vpol"),
    ]) == []


def test_a_key_in_dot_ssh_is_somebody_using_ssh(tmp_path):
    assert _run(tmp_path, [
        _f(r".\Users\jdoe\.ssh", "id_rsa"),
        _f(r".\Users\jdoe\.ssh", "known_hosts"),
        _f(r".\ProgramData\ssh", "authorized_keys"),
    ]) == []


def test_a_stray_key_alone_is_reported_and_not_flagged(tmp_path):
    """People copy their own key material around. A detector that flags this is a
    detector that gets turned off."""
    rows = _run(tmp_path, [_f(r".\Users\jdoe\Documents", "known_hosts")])
    assert rows[0]["kind"] == "misplaced" and rows[0]["suspicious"] == ""
    assert "something else joins it" in rows[0]["note"]


def test_an_lsass_dump_has_no_home_at_all(tmp_path):
    rows = _run(tmp_path, [_f(r".\Users\Public", "lsass.DMP")])
    assert rows[0]["families"] == "credential_dump"
    assert rows[0]["suspicious"] == "yes"


# --------------------------------------------------------------------------- #
# The staging heuristic
# --------------------------------------------------------------------------- #
def test_two_families_in_one_directory_is_one_row_not_two(tmp_path):
    """Nothing legitimate puts a registry hive next to a browser credential
    database, and the incident lead needs the sentence, not the file list."""
    rows = _run(tmp_path, [
        _f(r".\Windows\Temp\stage", "SAM"),
        _f(r".\Windows\Temp\stage", "SYSTEM"),
        _f(r".\Windows\Temp\stage", "Login Data"),
        _f(r".\Windows\Temp\stage", "known_hosts"),
    ])
    staging = _kind(rows, "staging")
    assert len(staging) == 1 and _kind(rows, "misplaced") == []
    assert staging[0]["path"] == "\\windows\\temp\\stage\\"
    assert staging[0]["files"] == "4"
    assert set(staging[0]["families"].split()) == {
        "registry_hive", "browser_credentials", "ssh_material"}
    assert staging[0]["suspicious"] == "yes"


def test_a_harvest_sorted_into_subdirectories_is_still_one_tree(tmp_path):
    rows = _run(tmp_path, [
        _f(r".\Windows\Temp\stage\hives", "SAM"),
        _f(r".\Windows\Temp\stage\browsers", "Login Data"),
        _f(r".\Windows\Temp\stage\ssh", "id_rsa"),
    ])
    staging = _kind(rows, "staging")
    assert len(staging) == 1
    assert staging[0]["path"] == "\\windows\\temp\\stage\\"
    assert staging[0]["files"] == "3"
    assert _kind(rows, "misplaced") == []


def test_a_nested_tree_is_reported_once_at_its_top(tmp_path):
    """Both directories qualify on their own. The row has to be the one that
    covers the whole harvest, not the deepest corner of it."""
    rows = _run(tmp_path, [
        _f(r".\Windows\Temp\stage", "SAM"),
        _f(r".\Windows\Temp\stage", "Login Data"),
        _f(r".\Windows\Temp\stage\more", "SYSTEM"),
        _f(r".\Windows\Temp\stage\more", "key4.db"),
    ])
    staging = _kind(rows, "staging")
    assert len(staging) == 1
    assert staging[0]["path"] == "\\windows\\temp\\stage\\"
    assert staging[0]["files"] == "4"


def test_two_unrelated_directories_each_get_their_own_row(tmp_path):
    rows = _run(tmp_path, [
        _f(r".\Windows\Temp", "SAM"),
        _f(r".\Users\jdoe\Documents", "known_hosts"),
    ])
    assert _kind(rows, "staging") == []
    assert len(_kind(rows, "misplaced")) == 2


# --------------------------------------------------------------------------- #
# The two things it must not lose
# --------------------------------------------------------------------------- #
def test_a_tree_that_was_deleted_is_the_stronger_finding(tmp_path):
    """The staged directory is normally removed after it is archived. A handler
    that filters on InUse loses exactly the case this exists for."""
    rows = _run(tmp_path, [
        _f(r".\Windows\Temp\stage", "SAM", in_use="False"),
        _f(r".\Windows\Temp\stage", "Login Data", in_use="False"),
    ])
    staging = _kind(rows, "staging")[0]
    assert staging["deleted_files"] == "2"
    assert "DELETED" in staging["note"]


def test_the_archive_beside_the_tree_is_the_package(tmp_path):
    rows = _run(tmp_path, [
        _f(r".\Windows\Temp\stage", "SAM", "2026-05-19 11:00:00.0000000"),
        _f(r".\Windows\Temp\stage", "Login Data", "2026-05-19 11:01:00.0000000"),
        _f(r".\Windows\Temp", "out.7z", "2026-05-19 11:05:00.0000000",
           in_use="False", size="90210"),
    ])
    archive = _kind(rows, "archive")
    assert len(archive) == 1
    assert archive[0]["path"] == "\\windows\\temp\\out.7z"
    assert archive[0]["deleted_files"] == "1"
    assert "DELETED" in archive[0]["note"]
    assert archive[0]["suspicious"] == "yes"


def test_an_archive_written_days_later_is_not_the_package(tmp_path):
    rows = _run(tmp_path, [
        _f(r".\Windows\Temp\stage", "SAM", "2026-05-19 11:00:00.0000000"),
        _f(r".\Windows\Temp\stage", "Login Data", "2026-05-19 11:00:00.0000000"),
        _f(r".\Windows\Temp", "setup.zip", "2026-05-01 09:00:00.0000000"),
    ])
    assert _kind(rows, "archive") == []


def test_an_archive_beside_a_lone_stray_key_is_not_a_package(tmp_path):
    """Nothing qualified, so there is nothing for the archive to be the package
    of -- and a zip next to somebody's own key material is a zip."""
    rows = _run(tmp_path, [
        _f(r".\Users\jdoe\Documents", "known_hosts"),
        _f(r".\Users\jdoe\Documents", "backup.zip"),
    ])
    assert _kind(rows, "archive") == []


# --------------------------------------------------------------------------- #
# The path arithmetic everything above rests on
# --------------------------------------------------------------------------- #
def test_the_mft_root_dot_is_not_a_directory(tmp_path):
    assert C.norm(r".\Windows\Temp") == "\\windows\\temp\\"
    assert C.norm(".") == "\\"
    assert C.norm("") == "\\"
    assert C.norm(r".\Windows\Temp\\") == "\\windows\\temp\\"


def test_the_parent_of_the_root_is_the_root(tmp_path):
    assert C.parent_of("\\windows\\temp\\stage\\") == "\\windows\\temp\\"
    assert C.parent_of("\\windows\\") == "\\"
    assert C.parent_of("\\") == "\\"


def test_the_family_test_is_case_and_extension_aware(tmp_path):
    assert C.family_of("\\windows\\temp\\", "sam", "") == "registry_hive"
    assert C.family_of("\\windows\\system32\\config\\", "sam", "") == ""
    assert C.family_of("\\windows\\temp\\", "sample.txt", ".txt") == ""
    assert C.family_of("\\users\\jdoe\\desktop\\", "key.ppk", ".ppk") == "ssh_material"
    assert C.family_of("\\x\\", "lsass_dump.bin", ".bin") == "credential_dump"


def test_no_mft_skips(tmp_path):
    with pytest.raises(HandlerSkip):
        C.run(_Ctx(tmp_path, tmp_path / "out"))
