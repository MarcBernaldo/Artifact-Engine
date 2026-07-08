"""Handler: authorized SSH keys per user (~/.ssh/authorized_keys). Output: ssh.csv"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.handlers._lincommon import root, write_csv


def run(ctx) -> None:
    base = root(ctx.evidence)
    rows: list[list] = []
    homes: list[tuple[str, Path]] = []
    home_dir = base / "home"
    if home_dir.is_dir():
        homes += [(d.name, d) for d in home_dir.iterdir() if d.is_dir()]
    if (base / "root").is_dir():
        homes.append(("root", base / "root"))
    for user, home in homes:
        for keyfile in ("authorized_keys", "authorized_keys2"):
            ak = home / ".ssh" / keyfile
            if not ak.is_file():
                continue
            for line in ak.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    parts = s.split()
                    ktype = parts[0] if parts else ""
                    comment = parts[2] if len(parts) > 2 else ""
                    rows.append([user, ktype, comment, s[:100]])
    write_csv(ctx.out, "ssh.csv", ["user", "key_type", "comment", "key_preview"], rows)
