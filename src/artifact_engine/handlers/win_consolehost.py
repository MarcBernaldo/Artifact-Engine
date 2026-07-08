"""Handler: PowerShell console history (PSReadLine). Output: consolehost.csv

Every interactive PowerShell command each user ever typed survives in
Users/<u>/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/
ConsoleHost_history.txt (no size/date limit by default) - the Windows
counterpart of the Linux `bash` parser, and often the only place attacker
console activity is visible when 4688 has no command line.

Multi-line commands are stored with a trailing backtick per continuation
line; they are re-joined into one row. A `flag` column marks low-FP attacker
idioms (download cradle, -EncodedCommand payloads, Defender tampering,
LOLBin downloads, credential-access tooling) plus any match from the
analyst-editable `assets/suspicious_tools.txt` indicator list (named
offensive tooling); everything else is surfaced unflagged - the full
history IS the artifact.
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.handlers._indicators import load_indicators, match_labels
from artifact_engine.handlers._lincommon import write_csv

# PSReadLine dir is "PSReadLine" on PS5+/7, "PSReadline" on older builds; the
# evidence tree may sit on a case-sensitive filesystem, so glob instead of a
# fixed path.
_HISTORY_GLOB = "AppData/Roaming/Microsoft/Windows/PowerShell/PSRead[Ll]ine/ConsoleHost_history.txt"

# (label, pattern) - first match wins. Tight on purpose: plain `iex`/`bypass`
# are everyday admin usage, so only combinations that are rarely benign flag.
_FLAGS: tuple[tuple[str, re.Pattern], ...] = (
    ("download_cradle", re.compile(
        r"downloadstring\s*\(|downloadfile\s*\(|\|\s*iex\b"
        r"|iex\s*\(\s*(?:irm|iwr|invoke-restmethod|invoke-webrequest)\b", re.I)),
    ("encoded_command", re.compile(r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{16,}", re.I)),
    ("base64_decode", re.compile(r"frombase64string\s*\(", re.I)),
    ("defender_tamper", re.compile(r"\b(?:set|add)-mppreference\b", re.I)),
    ("lolbin_download", re.compile(r"\bcertutil\b.*-urlcache|\bbitsadmin\b.*[/-]transfer", re.I)),
    ("credential_access", re.compile(
        r"mimikatz|\brubeus\b|\bsharphound\b|\bseatbelt\b|\blazagne\b"
        r"|comsvcs(?:\.dll)?\W+(?:#\s*)?24|procdump.{0,40}lsass|rundll32.{0,40}comsvcs", re.I)),
)


def _flag(cmd: str, tools: list | None = None) -> str:
    for label, rx in _FLAGS:
        if rx.search(cmd):
            return label
    # analyst list (suspicious_tools.txt): named offensive tooling on top of
    # the built-in idioms; several labels can hit the same command.
    return "+".join(match_labels(tools, cmd)) if tools else ""


def iter_history(evidence: Path):
    """Yield (user, seq, command) per PSReadLine history line; continuation
    lines (trailing backtick) are re-joined into the one command they belong to."""
    users = evidence / "Users"
    if not users.is_dir():
        return
    for home in sorted(users.iterdir()):
        if not home.is_dir():
            continue
        for hist in sorted(home.glob(_HISTORY_GLOB)):
            seq = 0
            pending = ""
            for line in hist.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                s = pending + (line.strip() if pending else line.rstrip())
                if s.endswith("`"):          # continuation: join with the next line
                    pending = s[:-1] + " "
                    continue
                pending = ""
                s = s.strip()
                if not s:
                    continue
                seq += 1
                yield home.name, seq, s
            if pending.strip():              # unterminated continuation at EOF
                seq += 1
                yield home.name, seq, pending.strip()


def run(ctx) -> None:
    tools = load_indicators(Path(ctx.assets) / "suspicious_tools.txt")
    rows = [[seq, user, _flag(cmd, tools), cmd]
            for user, seq, cmd in iter_history(Path(ctx.evidence))]
    write_csv(ctx.out, "consolehost.csv", ["id", "user", "flag", "command"], rows)
