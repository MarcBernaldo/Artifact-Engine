"""v0.7.150: art_web_errors.csv -- every Apache/nginx error-log line, parsed, not
filtered. Synthetic logs; hosts, addresses and paths are invented."""
from __future__ import annotations

import csv
import gzip
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import lin_web_errors

APACHE = (
    "[Wed Oct 11 14:32:52.123456 2026] [php:warn] [pid 1234:tid 99] [client 10.0.0.5:51234] "
    "PHP Warning:  include(/var/www/x.php): Failed to open stream in /var/www/index.php on "
    "line 3, referer: http://example.local/a?b=c, d\n"
    "sh: 1: wget: not found\n"
    "\n"
    "[Wed Oct 11 14:33:00.000001 2026] [mpm_prefork:notice] [pid 1] AH00163: Apache configured\n"
    "[Wed Oct 11 14:34:00.5 2026] [:error] [pid 7] [client ::1:4443] ModSecurity: Access denied\n"
)
APACHE22 = "[Tue Jan  6 09:01:02 2026] [error] [client 10.0.0.9] File does not exist: /var/www/x\n"
NGINX = (
    '2026/10/11 15:00:01 [error] 812#812: *45 open() "/srv/www/x" failed (2: No such file), '
    'client: 10.0.0.7, server: example.local, request: "GET /x?a=1, 2 HTTP/1.1", '
    'host: "example.local", referrer: "http://example.local/"\n'
    "2026/10/11 15:00:02 [notice] 1#1: signal process started\n"
)


def _rows(tmp_path: Path, zone: str = "Europe/Madrid") -> list[dict]:
    ev = tmp_path / "ev"
    root = ev / "[root]"
    (root / "etc").mkdir(parents=True)
    if zone:
        (root / "etc" / "timezone").write_text(zone + "\n", encoding="utf-8")
    a = root / "var/log/httpd"
    (a / "sites").mkdir(parents=True)
    (a / "sites" / "vhost-error_log-20261012").write_text(APACHE, encoding="utf-8")
    (a / "access_log").write_text("not read\n", encoding="utf-8")
    (a / "error_log.conf").write_text("not read\n", encoding="utf-8")
    with gzip.open(a / "error_log.1.gz", "wt", encoding="utf-8") as fh:
        fh.write(APACHE22)
    n = root / "var/log/nginx"
    n.mkdir(parents=True)
    (n / "error.log").write_text(NGINX, encoding="utf-8")
    lin_web_errors.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=logging.getLogger("t")))
    with open(tmp_path / "out" / "art_web_errors.csv", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_every_line_of_every_error_log_and_nothing_else(tmp_path):
    rows = _rows(tmp_path)
    assert [r["source"].replace("\\", "/") for r in rows] == (
        ["[root]/var/log/httpd/error_log.1.gz"] + ["[root]/var/log/httpd/sites/vhost-error_log-20261012"] * 4
        + ["[root]/var/log/nginx/error.log"] * 2)


def test_apache_24_fields_and_the_referer(tmp_path):
    r = _rows(tmp_path)[1]
    assert (r["time_local"], r["time_utc"], r["level"], r["module"], r["pid"], r["client"]) == (
        "2026-10-11 14:32:52.123456", "2026-10-11 12:32:52", "warn", "php", "1234:tid 99", "10.0.0.5")
    assert r["message"].startswith("PHP Warning:  include(") and r["message"].endswith("line 3")
    assert r["referer"] == "http://example.local/a?b=c, d"


def test_a_line_without_a_prefix_is_kept_as_message_only(tmp_path):
    r = _rows(tmp_path)[2]
    assert r["message"] == "sh: 1: wget: not found"
    assert not any(r[k] for k in ("time_local", "time_utc", "level", "client", "referer"))


def test_module_without_client_ipv6_client_and_apache_22(tmp_path):
    rows = _rows(tmp_path)
    assert (rows[3]["module"], rows[3]["level"], rows[3]["client"]) == ("mpm_prefork", "notice", "")
    assert (rows[4]["module"], rows[4]["level"], rows[4]["client"]) == ("", "error", "::1:4443")
    assert rows[4]["message"] == "ModSecurity: Access denied"
    r = rows[0]
    assert (r["time_local"], r["time_utc"], r["level"], r["module"], r["client"], r["message"]) == (
        "2026-01-06 09:01:02", "2026-01-06 08:01:02", "error", "", "10.0.0.9",
        "File does not exist: /var/www/x")


def test_nginx_context_goes_to_its_own_columns(tmp_path):
    r, n = _rows(tmp_path)[5:]
    assert (r["time_local"], r["time_utc"], r["level"], r["pid"], r["client"]) == (
        "2026-10-11 15:00:01", "2026-10-11 13:00:01", "error", "812", "10.0.0.7")
    assert r["message"] == 'open() "/srv/www/x" failed (2: No such file)'
    assert (r["request"], r["server"], r["host"], r["referer"]) == (
        "GET /x?a=1, 2 HTTP/1.1", "example.local", "example.local", "http://example.local/")
    assert (n["message"], n["client"], n["level"]) == ("signal process started", "", "notice")


def test_no_zone_no_utc(tmp_path):
    rows = _rows(tmp_path, zone="")
    assert rows[1]["time_local"] and not any(r["time_utc"] for r in rows)


def test_no_error_log_writes_nothing(tmp_path):
    ev = tmp_path / "ev"
    (ev / "[root]" / "var" / "log" / "nginx").mkdir(parents=True)
    (ev / "[root]" / "var" / "log" / "nginx" / "access.log").write_text("x\n", encoding="utf-8")
    with pytest.raises(HandlerSkip):
        lin_web_errors.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
    assert not (tmp_path / "out" / "art_web_errors.csv").exists()


def test_an_error_log_with_only_blank_lines_writes_nothing(tmp_path):
    ev = tmp_path / "ev"
    d = ev / "[root]" / "var" / "log" / "apache2"
    d.mkdir(parents=True)
    (d / "error.log").write_text("\n\n", encoding="utf-8")
    lin_web_errors.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=None))
    assert not (tmp_path / "out" / "art_web_errors.csv").exists()
