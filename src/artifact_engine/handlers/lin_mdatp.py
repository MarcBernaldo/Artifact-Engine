"""Handler: Microsoft Defender for Endpoint (Linux) state. Output: mdatp.csv

Parses the mdatp_* command outputs UAC collects when Defender is installed:
- health      : is protection actually on? (real_time_protection, healthy, ...)
- threat /
  quarantine  : the AV's own detections on this host
- exclusion   : paths/extensions excluded from scanning -- a spot attackers add
                their tooling to evade AV

Self-gating: hosts without Defender are skipped. Detections and exclusions are
flagged; health is flagged when protection is off or unhealthy. It does not
assert maliciousness (an admin may set legitimate exclusions).
"""

from __future__ import annotations

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

_HEALTH_KEYS = {
    "healthy", "real_time_protection_enabled", "passive_mode_enabled",
    "definitions_status", "licensed", "release_ring", "app_version", "engine_version",
}


def _is_empty(s: str) -> bool:
    low = s.lower()
    return not s or low.startswith(("no threat", "no exclusion", "no quarantine")) or set(s) <= {"="}


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    sysd = (lr / "system") if lr else None
    if not sysd or not any(sysd.glob("mdatp_*")):
        raise HandlerSkip("Defender (mdatp) not present")

    rows: list[list] = []
    for ln in read_lines(sysd / "mdatp_health.txt"):
        if ":" not in ln:
            continue
        key, _, val = ln.partition(":")
        key, val = key.strip(), val.strip().strip('"')
        if key not in _HEALTH_KEYS:
            continue
        susp = "yes" if (
            (key == "healthy" and val.lower() != "true")
            or (key == "real_time_protection_enabled" and val.lower() == "false")
            or (key == "passive_mode_enabled" and val.lower() == "true")
        ) else ""
        rows.append(["health", key, val, susp])

    for cat, fname in (("threat", "mdatp_threat_list.txt"),
                       ("quarantine", "mdatp_threat_quarantine_list.txt"),
                       ("exclusion", "mdatp_exclusion_list.txt")):
        for ln in read_lines(sysd / fname):
            s = ln.strip()
            if not _is_empty(s):
                rows.append([cat, "", s, "yes"])

    rows.sort(key=lambda r: (r[3] != "yes", r[0]))
    write_csv(ctx.out, "mdatp.csv", ["category", "item", "detail", "suspicious"], rows)
