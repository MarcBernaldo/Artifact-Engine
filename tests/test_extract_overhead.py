"""AE-113: the per-member costs of extraction -- a mkdir per member, the collision
key built a character at a time, tarfile keeping every member's record, and a
stat before the suffix is looked at."""
from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

from artifact_engine.core import extractor


def _tar(path: Path, n: int) -> None:
    with tarfile.open(path, "w") as tf:
        for i in range(n):
            ti = tarfile.TarInfo(f"root/sub/file{i}.txt")
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))


def test_a_tarball_does_not_keep_every_member_record(tmp_path, monkeypatch):
    _tar(tmp_path / "a.tar", 50)
    seen: list[int] = []
    real = tarfile.TarFile.next

    def spy(self):
        m = real(self)
        seen.append(len(self.members))
        return m

    monkeypatch.setattr(tarfile.TarFile, "next", spy)
    extractor._extract_tar(tmp_path / "a.tar", tmp_path / "out")
    assert len(list((tmp_path / "out" / "root" / "sub").iterdir())) == 50
    assert max(seen) <= 2


def test_a_folder_is_made_once_not_once_per_member(tmp_path, monkeypatch):
    with zipfile.ZipFile(tmp_path / "a.zip", "w") as zf:
        for i in range(50):
            zf.writestr(f"root/sub/file{i}.txt", b"x")
    _tar(tmp_path / "a.tar", 50)
    made: list[Path] = []
    real = Path.mkdir

    def spy(self, *a, **k):
        made.append(self)
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "mkdir", spy)
    extractor._extract_zip(tmp_path / "a.zip", tmp_path / "z")
    extractor._extract_tar(tmp_path / "a.tar", tmp_path / "t")
    assert len(list((tmp_path / "z" / "root" / "sub").iterdir())) == 50
    assert len(list((tmp_path / "t" / "root" / "sub").iterdir())) == 50
    assert len(made) < 20                  # 100 members; their parents and probes


def test_an_ascii_name_is_keyed_at_once_and_the_same(tmp_path, monkeypatch):
    claims = extractor._Claims(tmp_path)
    claims._fold = True                    # a folding destination, wherever this runs
    calls: list[str] = []
    real = extractor._Claims._char_key
    monkeypatch.setattr(extractor._Claims, "_char_key",
                        lambda self, c: (calls.append(c), real(self, c))[1])
    name = "etc/Config/a-b_c.TXT"
    assert claims._key(name) == "".join(real(claims, c) for c in name)
    assert calls == []
    other = "etc/ß"                   # not ASCII: per character
    assert claims._key(other) == "".join(real(claims, c) for c in other)
    assert calls


def test_a_name_that_cannot_be_a_container_is_not_stat_ed(monkeypatch):
    asked: list[Path] = []
    monkeypatch.setattr(Path, "is_file", lambda self: (asked.append(self), True)[1])
    assert not extractor.is_container(Path("notes.txt"))
    assert asked == []
    assert extractor.is_container(Path("a.zip"))


def test_folders_a_path_compares_as_one_but_the_disk_keeps_apart(tmp_path):
    """Found by review: a Windows Path compares lower-cased, NTFS does not -- `k`
    and the Kelvin sign are two folders there, and the second was never made."""
    kelvin = "\u212a"
    with zipfile.ZipFile(tmp_path / "a.zip", "w") as zf:
        zf.writestr("k/a.txt", b"1")
        zf.writestr(f"{kelvin}/b.txt", b"2")
    probe = tmp_path / "probe"
    probe.mkdir()
    (probe / "k").mkdir()
    try:
        (probe / kelvin).mkdir()
    except FileExistsError:
        import pytest
        pytest.skip("this filesystem folds the Kelvin sign onto k")
    extractor._extract_zip(tmp_path / "a.zip", tmp_path / "out")
    assert (tmp_path / "out" / "k" / "a.txt").read_bytes() == b"1"
    assert (tmp_path / "out" / kelvin / "b.txt").read_bytes() == b"2"
