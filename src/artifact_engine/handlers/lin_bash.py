"""Handler: per-user shell history (Linux/UAC acquisitions). Output: bash.csv

Reads each user's shell history under [root]/home/<user> and [root]/root. Covers
bash and the other common shells (zsh/sh/ash) so a non-bash user's commands are
not missed; a `shell` column says which. HISTTIMEFORMAT '#<epoch>' marker lines
are dropped (they are not commands). A `flag` column marks matches from the
analyst-editable `assets/suspicious_tools.txt` list (named offensive tooling);
technique-level detection (reverse shells, GTFOBins escapes) stays in gtfobins.

Each command gets a per-user sequential `id` (1..N, reset for every user) that
preserves the on-disk order: id 1 is the oldest command, the max id the latest,
so the table can be re-sorted back to chronological order after loading.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.handlers._indicators import load_indicators, match_labels
from artifact_engine.handlers._lincommon import root, write_csv

# history filename -> shell label
_HISTORIES = {
    ".bash_history": "bash",
    ".zsh_history": "zsh",
    ".sh_history": "sh",
    ".ash_history": "ash",
    ".histfile": "zsh",
}


def _home_dirs(base: Path):
    home = base / "home"
    if home.is_dir():
        for d in home.iterdir():
            if d.is_dir():
                yield d.name, d
    if (base / "root").is_dir():
        yield "root", base / "root"


def iter_history(base: Path):
    """Yield (user, shell, seq, command) for every shell-history line under `base`.

    `seq` is the per-user 1..N on-disk order (reset for each user). zsh
    extended-history prefixes are stripped and HISTTIMEFORMAT epoch/comment
    markers are dropped, so callers get clean command text. Shared by the bash
    handler and the GTFOBins history scanner so both see identical commands.
    """
    seen: set[Path] = set()
    for user, home in _home_dirs(base):
        seq = 0  # per-user sequence, independent of other users
        for fname, shell in _HISTORIES.items():
            hist = home / fname
            if not hist.is_file():
                continue
            rp = hist.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            for line in hist.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                # zsh ':<start>:<elapsed>;cmd' extended-history prefix -> keep the cmd
                if shell == "zsh" and s.startswith(":") and ";" in s:
                    s = s.split(";", 1)[1].strip()
                if not s or s.startswith("#"):  # blanks + HISTTIMEFORMAT epoch markers
                    continue
                seq += 1
                yield user, shell, seq, s


def run(ctx) -> None:
    # analyst-editable named-tooling indicators (suspicious_tools.txt); the
    # technique-level hunt (reverse shells, GTFOBins escapes) is gtfobins.csv.
    tools = load_indicators(Path(ctx.assets) / "suspicious_tools.txt")
    rows = [[seq, user, shell, "+".join(match_labels(tools, cmd)) if tools else "", cmd]
            for user, shell, seq, cmd in iter_history(root(ctx.evidence))]
    write_csv(ctx.out, "bash.csv", ["id", "user", "shell", "flag", "command"], rows)
