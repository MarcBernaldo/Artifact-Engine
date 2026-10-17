"""v0.7.151: the log files a web server's config names, wherever they are --
CustomLog/TransferLog/ErrorLog (Apache) and access_log/error_log (nginx),
including a piped rotatelogs that stamps the date into the name. Synthetic
configs; paths and hosts are invented."""
from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

from artifact_engine.handlers import lin_web_errors
from artifact_engine.handlers._webcommon import configured_logs, iter_access_files, iter_error_files

APACHE = """\
ServerRoot "/etc/httpd"
<VirtualHost *:80>
    CustomLog "| /usr/sbin/rotatelogs /srv/weblogs/site/access.log.%Y%m%d.%H%M 86400" combined
    ErrorLog "|/usr/sbin/rotatelogs -l /srv/weblogs/site/error.log.%Y%m%d 86400"
    #CustomLog /srv/old/access.log combined
    CustomLog logs/relative_access_log combined
    CustomLog ${APACHE_LOG_DIR}/shop.log combined
    TransferLog /srv/plain/transfer.log
    CustomLog /var/log/apache2/access.log combined
    ErrorLog syslog:local1
    CustomLog /dev/null common
    CustomLog /srv/%{env}/x.log combined
</VirtualHost>
"""
NGINX = """\
http {
    access_log /data/nginx/api.log main;
    access_log /data/nginx/plain.log;
    access_log off;
    access_log syslog:server=10.0.0.5 combined;
    error_log /data/nginx/api-error.log warn;
}
"""
CLF = '10.0.0.5 - - [11/Oct/2026:14:32:52 +0200] "GET / HTTP/1.1" 200 5 "-" "x"\n'


def _write(base: Path, rel: str, text: str = CLF) -> None:
    f = base / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")


def _host(tmp_path: Path) -> Path:
    ev = tmp_path / "ev"
    r = ev / "[root]"
    _write(r, "etc/httpd/conf.d/site.conf", APACHE)
    _write(r, "etc/nginx/nginx.conf", NGINX)
    for rel in ("srv/weblogs/site/access.log.20261011.0000", "srv/weblogs/site/access.log.20261012.0000.gz",
                "srv/weblogs/site/error.log.20261011", "srv/weblogs/site/notes.txt",
                "srv/old/access.log", "srv/plain/transfer.log", "srv/plain/transfer.log.conf",
                "var/log/apache2/shop.log", "var/log/apache2/shop.log.1",
                "var/log/apache2/access.log", "var/log/apache2/error.log",
                "data/nginx/api.log", "data/nginx/plain.log", "data/nginx/api-error.log"):
        _write(r, rel)
    _write(r, "srv/weblogs/site/notes.txt", "rotate weekly\nask before deleting\n")
    return ev


def _rel(ev: Path, files) -> list[str]:
    return [f.relative_to(ev / "[root]").as_posix() for f in files]


def test_directives_give_directory_and_name_prefix(tmp_path):
    ev = _host(tmp_path)
    got = {k: [(d.relative_to(ev / "[root]").as_posix(), p) for d, p, _ in v]
           for k, v in configured_logs(ev).items()}
    assert got == {
        "access": [("srv/weblogs/site", "access.log."), ("var/log/apache2", "shop.log"),
                   ("srv/plain", "transfer.log"), ("var/log/apache2", "access.log"),
                   ("data/nginx", "api.log"), ("data/nginx", "plain.log")],
        "error": [("srv/weblogs/site", "error.log."), ("data/nginx", "api-error.log")],
    }


def test_access_files_add_the_configured_ones_once(tmp_path):
    ev = _host(tmp_path)
    assert _rel(ev, iter_access_files(ev)) == [
        "var/log/apache2/access.log",
        "srv/weblogs/site/access.log.20261011.0000", "srv/weblogs/site/access.log.20261012.0000.gz",
        "var/log/apache2/shop.log", "var/log/apache2/shop.log.1",
        "srv/plain/transfer.log",
        "data/nginx/api.log", "data/nginx/plain.log",
    ]


def test_error_files_add_the_configured_ones(tmp_path):
    ev = _host(tmp_path)
    assert _rel(ev, iter_error_files(ev)) == [
        "var/log/apache2/error.log", "srv/weblogs/site/error.log.20261011", "data/nginx/api-error.log"]


def test_web_errors_reads_a_configured_error_log(tmp_path):
    ev = _host(tmp_path)
    lin_web_errors.run(SimpleNamespace(evidence=ev, out=tmp_path / "out", log=logging.getLogger("t")))
    text = (tmp_path / "out" / "web_errors.csv").read_text(encoding="utf-8")
    assert "srv" in text and "api-error.log" in text


def test_a_loose_drop_reads_no_config(tmp_path):
    drop = tmp_path / "drop"
    _write(drop, "etc/nginx/nginx.conf", NGINX)
    _write(drop, "data/nginx/api.log")
    assert configured_logs(drop) == {"access": [], "error": []}


def test_an_access_prefix_does_not_take_the_vhost_error_log(tmp_path):
    ev = tmp_path / "ev"
    r = ev / "[root]"
    _write(r, "etc/apache2/sites-enabled/site", "CustomLog /srv/logs/site combined\n"
                                               "ErrorLog /srv/logs/site_error.log\n")
    for rel in ("srv/logs/site", "srv/logs/site.1", "srv/logs/site_error.log"):
        _write(r, rel)
    assert _rel(ev, iter_access_files(ev)) == ["srv/logs/site", "srv/logs/site.1"]
    assert _rel(ev, iter_error_files(ev)) == ["srv/logs/site_error.log"]


def test_pipe_options_defines_dated_dirs_and_symlinks(tmp_path):
    """The logfile of a piped logger is its first positional argument; `${X}` comes
    from `Define`; strftime directories are walked; a path through a symlink to a
    standard dir is read once, also when the evidence itself is opened through a
    link; a name starting with a variable is not guessed; `..` stays inside [root]."""
    ev = tmp_path / "real"
    r = ev / "[root]"
    _write(r, "etc/httpd/conf/httpd.conf",
           'Define SITELOGS /srv/site\n'
           'CustomLog "|/usr/bin/rotatelogs -l -p /usr/local/bin/post.sh -L /srv/cur.log '
           '/srv/rl/access.%Y%m%d 86400" combined\n'
           'CustomLog "|/usr/sbin/cronolog -l /srv/cur2.log /srv/cl/%Y/%m/access.log" combined\n'
           "CustomLog ${SITELOGS}/shop.log combined\n"
           "CustomLog /srv/../var/log/httpd/access_log combined\n"
           "ErrorLog logs/example.local-error_log\n"
           "CustomLog /var/log/httpd/example.local combined\n"
           "CustomLog /srv/sym/access_log combined\n"
           "CustomLog /../../outside/access.log combined\n")
    _write(tmp_path, "outside/access.log")
    _write(r, "etc/nginx/nginx.conf", "access_log /srv/ngx/$host.access.log;\n")
    for rel in ("usr/local/bin/post.sh", "srv/cur.log", "srv/cur2.log", "srv/rl/access.20261011",
                "srv/cl/2026/10/access.log", "srv/site/shop.log", "var/log/httpd/access_log",
                "var/log/httpd/example.local", "var/log/httpd/example.local-error_log",
                "srv/ngx/a.access.log"):
        _write(r, rel)
    try:
        (r / "srv" / "sym").symlink_to(r / "var" / "log" / "httpd", target_is_directory=True)
        (tmp_path / "ev").symlink_to(ev, target_is_directory=True)
        ev = tmp_path / "ev"
    except OSError:
        pass                                         # no symlink privilege: two cases fewer
    assert _rel(ev, iter_access_files(ev)) == [
        "var/log/httpd/access_log", "srv/rl/access.20261011", "srv/cl/2026/10/access.log",
        "srv/site/shop.log", "var/log/httpd/example.local"]
    assert _rel(ev, iter_error_files(ev)) == ["var/log/httpd/example.local-error_log"]


def test_a_configured_log_dir_gives_the_rotations_archived_below_it(tmp_path):
    """v0.7.159. A site keeps older rotations in a subdirectory of its log dir;
    they are the same log, further back. A dir right under `/` is not walked:
    `/srv` holds far more than the one log the config names there."""
    ev = tmp_path / "ev"
    r = ev / "[root]"
    _write(r, "etc/apache2/sites-enabled/site",
           'CustomLog "|/usr/sbin/rotatelogs /srv/weblogs/site/access.log.%Y%m%d 86400" combined\n'
           'ErrorLog "|/usr/sbin/rotatelogs /srv/weblogs/site/error.log.%Y%m%d 86400"\n'
           "CustomLog /srv/flat.log combined\n")
    err = "[Wed Oct 11 14:32:52 2026] [error] [client 10.0.0.5] File does not exist: /srv/x\n"
    for rel, text in (("srv/weblogs/site/access.log.20261012", CLF),
                      ("srv/weblogs/site/backup2026/access.log.20260101.gz", CLF),
                      ("srv/weblogs/site/backup2026/notes.txt", CLF),
                      ("srv/weblogs/site/error.log.20261012", err),
                      ("srv/weblogs/site/backup2026/error.log.20260101", err),
                      ("srv/flat.log", CLF),
                      ("srv/old/flat.log.1", CLF)):
        _write(r, rel, text)
    assert _rel(ev, iter_access_files(ev)) == [
        "srv/weblogs/site/access.log.20261012",
        "srv/weblogs/site/backup2026/access.log.20260101.gz",
        "srv/flat.log"]
    assert _rel(ev, iter_error_files(ev)) == [
        "srv/weblogs/site/backup2026/error.log.20260101",
        "srv/weblogs/site/error.log.20261012"]


def test_an_access_prefix_does_not_take_a_configured_error_log(tmp_path):
    ev = tmp_path / "ev"
    r = ev / "[root]"
    _write(r, "etc/nginx/conf.d/x.conf", "access_log /srv/logs/site combined;\nerror_log /srv/logs/site.err;\n")
    for rel in ("srv/logs/site", "srv/logs/site.err"):
        _write(r, rel)
    assert _rel(ev, iter_access_files(ev)) == ["srv/logs/site"]
    assert _rel(ev, iter_error_files(ev)) == ["srv/logs/site.err"]
