"""Render web_metrics.html from SYNTHETIC data to exercise the JS in a browser.
Invented paths/UAs and routable placeholder IPs (see build_preview.py's note on why
RFC 5737 ranges are avoided here)."""
import random
from pathlib import Path

from artifact_engine.handlers import _web_report

OUT = Path(__file__).resolve().parent
DAYS = [f"2026-03-{d:02d}" for d in range(1, 15)]
random.seed(11)

ips = []
for i in range(60):
    ip = f"45.66.{i // 254}.{i % 254 + 1}" if i % 3 else f"10.0.{i}.7"
    req = random.randint(5, 4000)
    s404 = random.randint(0, req // 2)
    hits = random.choice([0, 0, 0, random.randint(1, 30)])
    days = {str(d): random.randint(1, req // 4 + 1)
            for d in sorted(random.sample(range(len(DAYS)), random.randint(1, 6)))}
    flags = "+".join(f for f, on in (("attack", hits > 0), ("scan", s404 > req * 0.3),
                                     ("auth-fail", i % 7 == 0)) if on)
    ips.append([
        ip, random.choice(["ES", "NL", "US", "RU", "CN"]),
        random.choice(["foreign", "hosting", "tor", "private"]),
        f"AS{1000 + i} Example Networks", req,
        req - s404, 0, i % 7 == 0 and 12 or 0, 0, s404, 0, 0,
        round(random.random() * 40, 1), random.randint(1, 90), 0, hits,
        DAYS[0] + " 00:00:00", DAYS[-1] + " 23:59:59", flags, days,
        [["sqli", "/index.php?id=1' OR '1'='1"]] if hits else [],
        [["/admin/config.bak", 4]], {"GET": req, "POST": max(0, req // 10)},
        [["/index.php", req // 2], ["/<script>alert(1)</script>", 3]],
        [["curl/8.4.0", req // 3]], [["id=1' OR '1'='1", 2]],
    ])

_web_report.render(
    OUT / "web_metrics.html", "web01", "2026-03-15 08:00:00 UTC", DAYS,
    ips, [["/admin/config.bak", 40, 12, "yes"], ["/.git/config", 22, 9, "yes"]],
    [[ips[0][0], "/wp-login.php", 30, 4]],
    Path("src/artifact_engine/data/assets"),
    {"methods": [["GET", 9000], ["POST", 800], ["PROPFIND", 12]],
     "paths": [["/index.php", 5000]], "uas": [["curl/8.4.0", 2000, 12]],
     "queries": [["id=1", 900]]},
)
print("->", OUT / "web_metrics.html")
