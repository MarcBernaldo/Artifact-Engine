"""container_logs.csv -- Kubernetes pod logs (CRI) and Docker json-file logs.
Synthetic files; namespaces, pods and ids are invented."""
from __future__ import annotations

import csv
import gzip
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import lin_container_logs


def _write(f: Path, text: str) -> None:
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")


def _rows(tmp_path: Path) -> list[dict]:
    ev = tmp_path / "ev"
    r = ev / "[root]"
    c = r / "var/log/pods/shop_web-7d9f-abcde_1111-2222/nginx"
    _write(c / "0.log", "2026-10-11T14:00:03.000000001+02:00 stdout F live line\n")
    with gzip.open(c / "0.log.20261011-130000.gz", "wt", encoding="utf-8") as fh:
        fh.write("2026-10-11T13:00:00.123456789+02:00 stderr P first half \n"
                 "2026-10-11T13:00:00.123456789+02:00 stderr F second half\n")
    _write(c / "0.log.20261011-140000", "2026-10-11T14:00:00Z stdout F rotated later\n")
    _write(c / "1.log", "2026-10-11T15:00:00Z stdout F after a restart\n\nnot a cri line\n")
    try:                                         # the kubelet's link to a pod file
        link = r / "var/log/containers/web-7d9f-abcde_shop_nginx-0123.log"
        link.parent.mkdir(parents=True)
        link.symlink_to(c / "1.log")
    except OSError:
        pass                                     # no symlink privilege: one case fewer
    d = r / "var/lib/docker/containers/abc123"
    _write(d / "abc123-json.log.1", json.dumps({"log": "older\n", "stream": "stdout",
                                                "time": "2026-10-11T10:00:00.5Z"}) + "\n")
    _write(d / "abc123-json.log", json.dumps({"log": "no newline", "stream": "stderr",
                                              "time": "2026-10-11T11:00:00Z"}) + "\n{broken\n")
    lin_container_logs.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
    with open(tmp_path / "out" / "container_logs.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_pod_files_in_restart_and_rotation_order(tmp_path):
    msgs = [r["message"] for r in _rows(tmp_path) if r["namespace"] == "shop"]
    assert msgs == ["first half ", "second half", "rotated later", "live line", "after a restart",
                    "not a cri line"]


def test_cri_fields(tmp_path):
    r = _rows(tmp_path)[0]
    assert (r["time_utc"], r["stream"], r["partial"], r["namespace"], r["pod"], r["container"]) == (
        "2026-10-11 11:00:00.123456", "stderr", "yes", "shop", "web-7d9f-abcde", "nginx")


def test_a_line_in_neither_format_keeps_only_the_message(tmp_path):
    rows = _rows(tmp_path)
    odd = [r for r in rows if r["message"] in ("not a cri line", "{broken")]
    assert len(odd) == 2 and not any(r["time_utc"] or r["stream"] for r in odd)


def test_docker_json_file_numbered_rotations_first(tmp_path):
    rows = [r for r in _rows(tmp_path) if r["container"] == "abc123"]
    assert [(r["time_utc"], r["stream"], r["partial"], r["message"]) for r in rows] == [
        ("2026-10-11 10:00:00.500000", "stdout", "", "older"),
        ("2026-10-11 11:00:00.000000", "stderr", "yes", "no newline"),
        ("", "", "", "{broken"),
    ]


def test_a_link_to_a_pod_file_is_not_read_twice(tmp_path):
    msgs = [r["message"] for r in _rows(tmp_path)]
    assert msgs.count("after a restart") == 1


def test_restarts_in_number_order_not_name_order(tmp_path):
    ev = tmp_path / "ev"
    c = ev / "[root]/var/log/pods/ns_p_u/c"
    _write(c / "10.log", "2026-10-11T15:00:00Z stdout F ten\n")
    _write(c / "9.log", "2026-10-11T14:00:00Z stdout F nine\n")
    lin_container_logs.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
    with open(tmp_path / "out" / "container_logs.csv", encoding="utf-8", newline="") as fh:
        assert [r["message"] for r in csv.DictReader(fh)] == ["nine", "ten"]


def test_only_blank_lines_write_nothing(tmp_path):
    ev = tmp_path / "ev"
    _write(ev / "[root]/var/log/pods/ns_p_u/c/0.log", "\n\n")
    lin_container_logs.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
    assert not (tmp_path / "out" / "container_logs.csv").exists()


def test_no_container_logs_skips(tmp_path):
    (tmp_path / "ev" / "[root]" / "var" / "log").mkdir(parents=True)
    with pytest.raises(HandlerSkip):
        lin_container_logs.run(SimpleNamespace(evidence=tmp_path / "ev", out=tmp_path / "out", log=None))
