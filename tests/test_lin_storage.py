"""v0.7.134: art_storage.csv -- every real filesystem of a UAC host and whether the
bodyfile covers it. Synthetic acquisition: invented devices and paths."""
from __future__ import annotations

import csv
from pathlib import Path
from types import SimpleNamespace

from artifact_engine.handlers import lin_storage

MOUNT = """\
/dev/sda2 on / type ext4 (rw,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run/credentials/systemd-sysctl.service type tmpfs (ro,nosuid)
/dev/mapper/vg_data-lv_data on /srv/data type xfs (rw,noatime)
fileserver.example.local:/export on /mnt/share type nfs4 (rw,relatime,vers=4.2)
overlay on /var/lib/docker/overlay2/abc/merged type overlay (rw,relatime)
nas.example.local:/pv on /var/lib/kubelet/pods/0000/volumes/kubernetes.io~nfs/pv1 type nfs4 (rw)
/dev/sdb1 on /mnt/with\\040space type ext4 (rw,relatime)
"""
DF = """\
Filesystem                  1K-blocks    Used Available Use% Mounted on
/dev/sda2                    10000000 4000000   6000000  40% /
tmpfs                          100000       0    100000   0% /dev/shm
/dev/mapper/vg_data-lv_data  50000000 1000000  49000000   2% /srv/data
/dev/sdb1                      200000    1000    199000   1% /mnt/with space
"""
BLKID = """\
/dev/sda2: UUID="11111111-2222-3333-4444-555555555555" TYPE="ext4"
/dev/sdc1: UUID="66666666-7777-8888-9999-000000000000" TYPE="xfs"
/dev/sdd: UUID="aaaa" TYPE="LVM2_member"
/dev/sde1: UUID="bbbb" TYPE="swap"
/dev/mapper/vg_data-lv_data: UUID="cccc" TYPE="xfs"
"""
BODYFILE = """\
0|/etc/hostname|1|-rw-r--r--|0|0|10|1|1|1|1
0|/mnt/with space/notes.txt|2|-rw-r--r--|0|0|10|1|1|1|1
0|/srv|3|drwxr-xr-x|0|0|10|1|1|1|1
0|/srv/database/old.sql|4|-rw-r--r--|0|0|10|1|1|1|1
"""


def _host(tmp_path: Path, bodyfile: str | None = BODYFILE) -> Path:
    st = tmp_path / "live_response" / "storage"
    st.mkdir(parents=True)
    (st / "mount.txt").write_text(MOUNT, encoding="utf-8")
    (st / "df.txt").write_text(DF, encoding="utf-8")
    (st / "blkid.txt").write_text(BLKID, encoding="utf-8")
    if bodyfile is not None:
        (tmp_path / "bodyfile").mkdir()
        (tmp_path / "bodyfile" / "bodyfile.txt").write_text(bodyfile, encoding="utf-8")
    return tmp_path


def _rows(tmp_path: Path, **kw) -> dict[str, dict]:
    ev = _host(tmp_path, **kw)
    lin_storage.run(SimpleNamespace(evidence=ev, out=tmp_path / "out"))
    with open(tmp_path / "out" / "art_storage.csv", encoding="utf-8", newline="") as fh:
        return {r["mountpoint"] or r["device"]: r for r in csv.DictReader(fh)}


def test_real_filesystems_are_rows_and_kernel_ones_are_not(tmp_path):
    rows = _rows(tmp_path)
    assert {"/", "/dev/shm", "/srv/data", "/mnt/share", "/mnt/with space"} <= set(rows)
    assert "/proc" not in rows and "/sys" not in rows
    assert not any(k.startswith("/run/credentials/") for k in rows)


def test_kind_size_and_options(tmp_path):
    rows = _rows(tmp_path)
    assert rows["/mnt/share"]["kind"] == "network"
    assert rows["/dev/shm"]["kind"] == "memory"
    assert rows["/var/lib/docker/overlay2/abc/merged"]["kind"] == "container"
    assert (rows["/srv/data"]["size_kb"], rows["/srv/data"]["used_kb"]) == ("50000000", "1000000")
    assert rows["/mnt/with space"]["size_kb"] == "200000"       # \040 unescaped


def test_what_the_bodyfile_does_not_cover_is_said(tmp_path):
    rows = _rows(tmp_path)
    assert rows["/"]["in_bodyfile"] == "yes"
    assert rows["/mnt/with space"]["in_bodyfile"] == "yes"
    # /srv itself is listed and /srv/database is a sibling: nothing BELOW /srv/data
    assert rows["/srv/data"]["in_bodyfile"] == "no"
    assert "NOT in the bodyfile" in rows["/srv/data"]["note"]
    assert rows["/mnt/share"]["in_bodyfile"] == "no"
    assert "network filesystem" in rows["/mnt/share"]["note"]


def test_an_empty_mount_is_not_reported_as_missing(tmp_path):
    rows = _rows(tmp_path)
    assert rows["/dev/shm"]["in_bodyfile"] == "no"
    assert "empty when collected" in rows["/dev/shm"]["note"]
    assert "NOT in the bodyfile" not in rows["/dev/shm"]["note"]


def test_noatime_is_said(tmp_path):
    assert "noatime" in _rows(tmp_path)["/srv/data"]["note"]
    assert "noatime" not in _rows(tmp_path / "b")["/"]["note"]          # relatime


def test_an_unmounted_filesystem_is_a_row(tmp_path):
    rows = _rows(tmp_path)
    assert rows["/dev/sdc1"]["mountpoint"] == "" and "not mounted" in rows["/dev/sdc1"]["note"]
    assert "/dev/sdd" not in rows and "/dev/sde1" not in rows        # LVM PV, swap


def test_container_plumbing_is_not_asked_of_the_bodyfile(tmp_path):
    row = _rows(tmp_path)["/var/lib/docker/overlay2/abc/merged"]
    assert row["in_bodyfile"] == "" and "containers table" in row["note"]


def test_without_a_bodyfile_coverage_is_left_blank(tmp_path):
    rows = _rows(tmp_path, bodyfile=None)
    assert {r["in_bodyfile"] for r in rows.values()} == {""}


def test_a_match_split_across_read_chunks_is_found(tmp_path, monkeypatch):
    monkeypatch.setattr(lin_storage, "_CHUNK", 7)
    assert _rows(tmp_path)["/mnt/with space"]["in_bodyfile"] == "yes"


def test_a_pods_network_volume_is_kept_but_not_asked(tmp_path):
    row = _rows(tmp_path)["/var/lib/kubelet/pods/0000/volumes/kubernetes.io~nfs/pv1"]
    assert row["kind"] == "network"
    assert row["in_bodyfile"] == "" and "containers table" in row["note"]
