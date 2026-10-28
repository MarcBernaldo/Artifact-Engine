"""v0.7.156: mod_ssl's ssl_request_log goes into art_web_access.csv, and the web
detections skip those rows (the access log holds the same requests). Synthetic
lines; hosts and addresses are invented."""
from __future__ import annotations

import csv
import gzip
import logging
from pathlib import Path
from types import SimpleNamespace

from artifact_engine.core.runner import ParserContext, marker_path
from artifact_engine.handlers import _webshard as S
from artifact_engine.handlers import lin_web_access
from artifact_engine.handlers._webcommon import iter_records, parse_ssl_request

ACCESS = '10.0.0.5 - - [11/Oct/2026:14:32:52 +0200] "GET /a HTTP/1.1" 200 5 "-" "curl/8"\n'
SSL = (
    '[11/Oct/2026:14:32:52 +0200] 10.0.0.5 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 "GET /a/b?x=1&y=2 HTTP/1.1" 5120\n'
    '[11/Oct/2026:14:32:53 +0200] 10.0.0.6 - - "\\x16\\x03\\x01" -\n'
    "garbage line\n"
    '[11/Oct/2026:14:32:54 +0200] 10.0.0.8 TLSv1.3 TLS_AES_256_GCM_SHA384 "GET /q\\"x HTTP/1.1" 7\n'
)


def _volume(tmp_path: Path, access: bool = True) -> Path:
    d = tmp_path / "[root]" / "var" / "log" / "httpd"
    (d / "vh").mkdir(parents=True)
    if access:
        (d / "ssl_access_log").write_text(ACCESS, encoding="utf-8")
    (d / "vh" / "site-ssl_request_log").write_text(SSL, encoding="utf-8")
    with gzip.open(d / "ssl_request_log-20261010.gz", "wt", encoding="utf-8") as fh:
        fh.write('[10/Oct/2026:01:00:00 +0200] 10.0.0.7 TLSv1.2 AES128-SHA "POST /login HTTP/1.0" 12\n')
    return tmp_path


def _timeline(ev: Path) -> list[dict]:
    out = ev / "CSVs" / "Web"
    lin_web_access.run(SimpleNamespace(evidence=ev, out=out, log=logging.getLogger("t")))
    marker_path(out, "art_web_access").write_text("x", encoding="utf-8")
    with open(out / "art_web_access.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_request_log_rows_follow_the_access_rows_with_their_tls_fields(tmp_path):
    rows = _timeline(_volume(tmp_path))
    assert [(r["path"], r["tls_protocol"], r["tls_cipher"]) for r in rows] == [
        ("/a", "", ""),
        ("/login", "TLSv1.2", "AES128-SHA"),
        ("/a/b", "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256"),
        ("\\x16\\x03\\x01", "-", "-"),
        ('/q\\"x', "TLSv1.3", "TLS_AES_256_GCM_SHA384"),
    ]
    r = rows[2]
    assert (r["time"], r["ip"], r["method"], r["query"], r["size"], r["status"], r["ua"]) == (
        "2026-10-11 14:32:52 +0200", "10.0.0.5", "GET", "x=1&y=2", "5120", "", "")


def test_the_detections_read_only_the_access_rows(tmp_path):
    ev = _volume(tmp_path)
    _timeline(ev)
    ctx = ParserContext(evidence=ev, out=ev / "CSVs", tools=ev, assets=ev, machine_name="HOST-01",
                        volume="live", log=logging.getLogger("t"))
    assert [r.path for r, _ in iter_records(ctx)] == ["/a"]
    pre = ev / "CSVs" / "Web" / "art_web_access.csv"
    assert [r.path for lo, hi in S.ranges(pre, 10) for r, _ in S.read(pre, lo, hi)] == ["/a"]


def test_a_host_with_only_request_logs_still_gets_a_timeline(tmp_path):
    rows = _timeline(_volume(tmp_path, access=False))
    assert len(rows) == 4 and all(r["tls_cipher"] for r in rows)


def test_parse_ssl_request():
    assert parse_ssl_request("garbage") is None
    assert parse_ssl_request('[11/Oct/2026:14:32:52 +0200] 10.0.0.5 TLSv1.2 C "GET / HTTP/1.1" 1\r') == (
        "2026-10-11 14:32:52 +0200", "10.0.0.5", "GET", "/", "", "1", "TLSv1.2", "C")
