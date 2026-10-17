"""web_ssl_requests.csv -- mod_ssl's ssl_request_log. Synthetic lines; hosts and
addresses are invented."""
from __future__ import annotations

import csv
import gzip
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import lin_web_ssl_requests

LOG = (
    '[11/Oct/2026:14:32:52 +0200] 10.0.0.5 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 "GET /a/b?x=1&y=2 HTTP/1.1" 5120\n'
    '[11/Oct/2026:14:32:53 +0200] 10.0.0.6 TLSv1.3 TLS_AES_256_GCM_SHA384 "\\x16\\x03\\x01" -\n'
    "garbage line\n"
    '[11/Oct/2026:14:32:54 +0200] 10.0.0.8 TLSv1.2 AES128-SHA "GET /q\\"x HTTP/1.1" 7\n'
)


def _rows(tmp_path: Path) -> list[dict]:
    ev = tmp_path / "ev"
    d = ev / "[root]" / "var" / "log" / "httpd"
    (d / "vh").mkdir(parents=True)
    (d / "vh" / "site-ssl_request_log").write_text(LOG, encoding="utf-8")
    with gzip.open(d / "ssl_request_log-20261011.gz", "wt", encoding="utf-8") as fh:
        fh.write('[10/Oct/2026:01:00:00 +0200] 10.0.0.7 TLSv1.2 AES128-SHA "POST /login HTTP/1.0" 12\n')
    (d / "ssl_access_log").write_text(               # same shape, other file: not read here
        '[10/Oct/2026:01:00:00 +0200] 10.0.0.9 TLSv1.2 AES128-SHA "GET / HTTP/1.1" 1\n', encoding="utf-8")
    lin_web_ssl_requests.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
    with open(tmp_path / "out" / "web_ssl_requests.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_rows_fields_and_files(tmp_path):
    rows = _rows(tmp_path)
    assert [r["source"].replace("\\", "/").rsplit("/", 1)[-1] for r in rows] == [
        "ssl_request_log-20261011.gz"] + ["site-ssl_request_log"] * 3
    assert (rows[3]["path"], rows[3]["size"]) == ('/q\\"x', "7")
    r = rows[1]
    assert {k: r[k] for k in _HEADER_NO_SOURCE} == {
        "time": "2026-10-11 14:32:52 +0200", "ip": "10.0.0.5", "protocol": "TLSv1.2",
        "cipher": "ECDHE-RSA-AES128-GCM-SHA256", "method": "GET", "path": "/a/b",
        "query": "x=1&y=2", "http_version": "HTTP/1.1", "size": "5120"}


def test_a_malformed_request_stays_whole(tmp_path):
    r = _rows(tmp_path)[2]
    assert (r["method"], r["path"], r["query"], r["size"]) == ("", "\\x16\\x03\\x01", "", "-")


def test_no_request_log_skips(tmp_path):
    (tmp_path / "ev" / "[root]" / "var" / "log" / "httpd").mkdir(parents=True)
    with pytest.raises(HandlerSkip):
        lin_web_ssl_requests.run(SimpleNamespace(evidence=tmp_path / "ev", out=tmp_path / "out", log=None))


_HEADER_NO_SOURCE = ["time", "ip", "protocol", "cipher", "method", "path", "query", "http_version", "size"]
