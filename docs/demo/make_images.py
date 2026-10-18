"""Regenerate the README's screenshots from a SYNTHETIC case.

Every host, account and address below is invented: private ranges for the
organisation, RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) for the internet. Nothing here is read from a real case.

    python docs/demo/make_images.py [--out DIR]

builds the synthetic tables under DIR (a temporary folder by default), runs the
engine's own renderers over them -- the same code a real run uses -- and
captures each page with Edge headless into docs/img/.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from artifact_engine.core import lateral
from artifact_engine.core.detector import Machine, Volume

DOCS = Path(__file__).resolve().parents[1]
IMG = DOCS / "img"

_SEC = ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider",
        "Channel", "ProcessId", "ThreadId", "Computer", "ChunkNumber", "UserId",
        "MapDescription", "UserName", "RemoteHost", "PayloadData1", "PayloadData2",
        "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo",
        "HiddenRecord", "SourceFile", "Keywords", "ExtraDataOffset", "Payload"]
_LOGINS = ["time_utc", "time_local", "end_local", "result", "type", "user", "tty", "host",
           "source", "file"]
DAY = "2026-03-14"

# name -> (os, addresses)
HOSTS = {
    "WS-07": ("windows", ["10.0.10.17"]),
    "WS-12": ("windows", ["10.0.10.22"]),
    "WS-21": ("windows", ["10.0.10.31"]),
    "FILES-03": ("windows", ["10.0.20.5"]),
    "SRV-APP02": ("windows", ["10.0.20.8"]),
    "DC-01": ("windows", ["10.0.0.10"]),
    "web-01": ("linux", ["10.0.30.5"]),
    "db-01": ("linux", ["10.0.30.9"]),
}


def _machine(root: Path, name: str) -> Machine:
    os_, ips = HOSTS[name]
    path = root / name
    (path / "CSVs" / "SystemInfo").mkdir(parents=True, exist_ok=True)
    (path / "CSVs" / "EventLogs").mkdir(parents=True, exist_ok=True)
    (path / "CSVs" / "SystemInfo" / "machine_info.json").write_text(
        json.dumps({"machine_name": name, "fqdn": f"{name.lower()}.example.local",
                    "IPs": ips}), encoding="utf-8")
    if os_ == "windows":
        return Machine(name, "windows", "kape", "windows_kape", path, "src",
                       [Volume("C", path, True)])
    return Machine(name + "_uac", "linux", "uac", "linux_uac", path, "src",
                   [Volume("live", path, True)])


def _write(path: Path, header: list[str], rows: list[dict]) -> None:
    with path.open("a" if path.exists() else "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=header, restval="")
        if fh.tell() == 0:
            w.writeheader()
        w.writerows(rows)


def _logon(host, t, eid, user, src, ltype=None, server=None, service=None):
    p2 = (f"LogonType {ltype}" if ltype is not None else
          f"TargetServerName: {server}" if server else f"ServiceName: {service}")
    return host, {"TimeCreated": f"{DAY} {t}", "EventId": eid,
                  "Computer": f"{host}.example.local", "UserName": user,
                  "RemoteHost": src, "PayloadData1": f"Target: {user}", "PayloadData2": p2}


def windows_events() -> list[tuple[str, dict]]:
    """An intrusion through an exposed RDP server, then the usual spread."""
    ev = []
    # 1. password spraying against the exposed application server, then a hit
    for i in range(38):
        ev.append(_logon("SRV-APP02", f"02:{10 + i // 2:02d}:{(i * 7) % 60:02d}", "4625",
                         "EXAMPLE\\administrator", "- (203.0.113.45)", 10))
    ev.append(_logon("SRV-APP02", "02:41:09", "4624", "EXAMPLE\\administrator",
                     "- (203.0.113.45)", 10))
    # 2. from there, RDP to the file server with an admin account
    ev.append(_logon("FILES-03", "02:58:30", "4624", "EXAMPLE\\adm-jdoe", "- (10.0.20.8)", 10))
    # 3. the file server reaches the DC and the workstations over SMB
    ev.append(_logon("DC-01", "03:12:44", "4624", "EXAMPLE\\adm-jdoe", "- (10.0.20.5)", 3))
    for ws, t in (("WS-12", "03:20:02"), ("WS-21", "03:21:40"), ("WS-07", "03:23:15")):
        ev.append(_logon(ws, t, "4624", "EXAMPLE\\adm-jdoe", "- (10.0.20.5)", 3))
    # 4. explicit credentials from a workstation, Kerberos seen on the DC
    ev.append(_logon("WS-07", "03:31:00", "4648", "EXAMPLE\\svc-backup", "-:-",
                     server="FILES-03"))
    ev.append(_logon("DC-01", "03:32:10", "4769", "", "::ffff:10.0.10.17:50211",
                     service="cifs/files-03.example.local"))
    # 5. a null session from the internet, and routine admin noise that stays in the CSV
    ev.append(_logon("FILES-03", "04:02:00", "4624", "NT AUTHORITY\\ANONYMOUS LOGON",
                     "- (198.51.100.77)", 3))
    for ws in ("WS-07", "WS-12", "WS-21"):
        ev.append(_logon(ws, "08:00:00", "4624", "EXAMPLE\\it-helpdesk", "- (10.0.0.10)", 3))
    return ev


def linux_logins() -> dict[str, list[dict]]:
    """SSH brute force that worked on the web server, then a hop to the database."""
    web = [{"time_utc": f"{DAY} 01:{30 + i:02d}:00", "result": "failed",
            "type": "LOGIN_PROCESS", "user": "root", "tty": "ssh:notty",
            "host": "198.51.100.23", "source": "btmp", "file": "[root]/var/log/btmp"}
           for i in range(12)]
    web.append({"time_utc": f"{DAY} 01:44:12", "result": "ok", "type": "USER_PROCESS",
                "user": "root", "tty": "pts/0", "host": "198.51.100.23", "source": "wtmp",
                "file": "[root]/var/log/wtmp"})
    db = [{"time_utc": f"{DAY} 02:05:40", "result": "ok", "type": "USER_PROCESS",
           "user": "root", "tty": "pts/1", "host": "10.0.30.5", "source": "wtmp",
           "file": "[root]/var/log/wtmp"}]
    return {"web-01": web, "db-01": db}


def build_case(root: Path) -> list[Machine]:
    machines = {n: _machine(root, n) for n in HOSTS}
    for host, row in windows_events():
        _write(machines[host].path / "CSVs" / "EventLogs" / "evtx_security.csv", _SEC, [row])
    for host, rows in linux_logins().items():
        _write(machines[host].path / "CSVs" / "EventLogs" / "logins.csv", _LOGINS, rows)
    return list(machines.values())


def _edge() -> str:
    for p in (Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
              Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")):
        if p.is_file():
            return str(p)
    found = shutil.which("msedge") or shutil.which("chrome") or shutil.which("chromium")
    if not found:
        sys.exit("Edge or Chrome is needed to capture the pages")
    return found


def capture(page: Path, png: Path, size=(1600, 960), wait_ms=8000, script: str = "") -> None:
    """A screenshot of `page`, after its scripts have run for `wait_ms`. `script`
    runs on load in a copy of the page (a view the analyst would pick, e.g. the
    edge labels off); the page the engine wrote is left as it is."""
    png.parent.mkdir(parents=True, exist_ok=True)
    if script:
        shot = page.with_name(page.stem + ".shot.html")
        shot.write_text(page.read_text(encoding="utf-8").replace(
            "</body>", f"<script>addEventListener('load',()=>{{{script}}})</script></body>"),
            encoding="utf-8")
        page = shot
    with tempfile.TemporaryDirectory() as profile:
        subprocess.run([_edge(), "--headless=new", "--disable-gpu", "--hide-scrollbars",
                        f"--user-data-dir={profile}", f"--window-size={size[0]},{size[1]}",
                        f"--virtual-time-budget={wait_ms}", f"--screenshot={png}",
                        page.as_uri()], check=True, capture_output=True, timeout=120)
    print(f"[+] {png.relative_to(DOCS.parent)}")


_UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
       "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0"]
_PAGES = ["/", "/shop/", "/shop/item?id=42", "/static/app.js", "/static/site.css",
          "/img/logo.png", "/account/", "/api/cart", "/contact"]


def access_log() -> list[str]:
    """Three days of a small shop: its customers, a crawler, and four attackers."""
    out = []

    def line(ip, day, sec, method, path, status, size, ua):
        h, m, s = sec // 3600 % 24, sec // 60 % 60, sec % 60
        return (f'{ip} - - [{day:02d}/Mar/2026:{h:02d}:{m:02d}:{s:02d} +0100] '
                f'"{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"')

    for day in (12, 13, 14):
        for i in range(900):                                          # customers
            ip = f"192.0.2.{10 + i % 120}"
            out.append(line(ip, day, 28800 + i * 47, "GET", _PAGES[i % len(_PAGES)],
                            200 if i % 23 else 304, 5120 + i % 4000, _UA[i % 3]))
        for i in range(120):                                          # a crawler
            out.append(line("198.51.100.200", day, 3600 + i * 300, "GET",
                            _PAGES[i % len(_PAGES)], 200, 2048, "ExampleBot/2.1"))
    for i in range(400):                                              # directory scan
        out.append(line("203.0.113.66", 13, 7200 + i, "GET", f"/backup{i}.zip", 404, 0,
                        "gobuster/3.6"))
    for p in ("/.env", "/.git/config", "/wp-config.php.bak", "/phpmyadmin/"):
        out.append(line("203.0.113.66", 13, 7700, "GET", p, 404, 0, "gobuster/3.6"))
    for i in range(180):                                              # login brute force
        out.append(line("198.51.100.23", 14, 3000 + i * 3, "POST", "/account/login", 401, 0,
                        "python-requests/2.32"))
    for i, q in enumerate(("1' OR '1'='1", "1 UNION SELECT user,pass FROM users--",
                           "1;WAITFOR DELAY '0:0:5'--")):            # SQL injection
        out.append(line("203.0.113.9", 14, 9000 + i * 20, "GET",
                        f"/shop/item?id={q.replace(' ', '%20')}", 500, 312, "sqlmap/1.8"))
    out.append(line("203.0.113.9", 14, 9100, "PROPFIND", "/webdav/", 405, 0, "sqlmap/1.8"))
    return out


def web_panel(root: Path) -> Path:
    """web_metrics over the synthetic access log, as a run writes it."""
    import logging

    from artifact_engine.config import DATA_DIR
    from artifact_engine.core.runner import ParserContext, run_parser
    from artifact_engine.models import ParserManifest
    host = root / "web-01"
    log = host / "[root]" / "var" / "log" / "apache2"
    log.mkdir(parents=True, exist_ok=True)
    (log / "access.log").write_text("\n".join(access_log()) + "\n", encoding="utf-8")
    ctx = ParserContext(evidence=host, out=host / "CSVs" / "Web", tools=host,
                        assets=DATA_DIR / "assets", machine_name="web-01", volume="live",
                        log=logging.getLogger("demo"))
    run_parser(ParserManifest(id="web_metrics",
                              handler="artifact_engine.handlers.lin_web_metrics:run"), ctx)
    return next(host.rglob("web_metrics.html"))


def stitch(png: Path, bands: list[tuple[int, int]]) -> None:
    """Keep only the horizontal `bands` (y from, y to) of `png`, one under the
    other: a panel that cannot be filled with invented data is left out rather
    than shown empty (the world map: documentation addresses have no country)."""
    from PIL import Image
    with Image.open(png) as im:
        parts = [im.crop((0, a, im.width, b)) for a, b in bands]
    out = Image.new("RGB", (parts[0].width, sum(x.height for x in parts)))
    y = 0
    for x in parts:
        out.paste(x, (0, y))
        y += x.height
    out.save(png, optimize=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, help="where to build the synthetic case")
    ap.add_argument("--no-capture", action="store_true", help="build the pages only")
    a = ap.parse_args()
    root = a.out or Path(tempfile.mkdtemp(prefix="aeng-demo-"))
    machines = build_case(root / "case")
    summary = lateral.build(machines, root)
    panel = web_panel(root / "web")
    print(f"[=] synthetic case at {root}: {summary}")
    if not a.no_capture:
        # usernames off: the accounts are in the timeline beside the graph
        capture(root / "lateral_movement.html", IMG / "lateral_movement.png",
                script="const c=document.getElementById('lbl');c.checked=false;"
                       "c.dispatchEvent(new Event('change'));"
                       "setTimeout(()=>document.getElementById('fit').click(),3000);")
        capture(panel, IMG / "web_metrics.png", size=(1600, 1100))
        stitch(IMG / "web_metrics.png", [(0, 460), (880, 1100)])
        capture(DOCS / "atlas.html", IMG / "atlas.png", size=(1600, 1000))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
