"""Handler: per-user shell history (Linux/UAC acquisitions). Output: art_shell_history.csv

Reads each user's shell history under [root]/home/<user>, [root]/root and,
since v0.7.166, every other home `/etc/passwd` declares -- a service account's
(`www-data` in /var/www, `postgres` in /var/lib/postgresql) is where a shell
obtained through that service leaves its commands. Covers bash, the other common
shells (zsh/sh/ash) and fish (`~/.local/share/fish/fish_history`, v0.7.166) so a
non-bash user's commands are not missed; a `shell` column says which. A `flag` column marks matches from the
analyst-editable `assets/suspicious_tools.txt` list (named offensive tooling);
technique-level detection (reverse shells, GTFOBins escapes) stays in gtfobins.

Each command gets a per-user sequential `id` (1..N, reset for every user) that
preserves the on-disk order: id 1 is the oldest command, the max id the latest,
so the table can be re-sorted back to chronological order after loading.

`time_utc` (v0.7.146) is when the command was run, where the shell wrote it
down: bash with HISTTIMEFORMAT set puts a `#<epoch>` line before each command,
zsh's extended history prefixes it `: <epoch>:<elapsed>;`. Without either the
column is empty -- the order is all there is. Every row of a history is
otherwise in the same table, timed or not.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.handlers._indicators import load_indicators, match_labels
from artifact_engine.handlers._lincommon import read_text, root, write_csv

# history filename -> shell label
_HISTORIES = {
    ".bash_history": "bash",
    ".zsh_history": "zsh",
    ".sh_history": "sh",
    ".ash_history": "ash",
    ".histfile": "zsh",
}


_FISH = Path(".local") / "share" / "fish" / "fish_history"


def _passwd_home(base: Path, home: str) -> Path | None:
    """`home` (a Linux path from the evidence's /etc/passwd) as a folder of the
    acquisition, decided on the TEXT before anything touches the disk: on the
    Windows host running the engine a UNC path (`//server/share` written with
    backslashes) or `C:` in it would turn
    the stat itself into a network logon or a read of the analyst's own drive.
    None for `..`, a backslash, a colon or a NUL, and for the root (`/`, `/.`) -- every
    account's and nobody's."""
    if not home.startswith("/") or "\\" in home or ":" in home or "\0" in home:
        return None
    parts = [p for p in home.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return base.joinpath(*parts)


def _passwd_homes(base: Path):
    """(account, home) for every home `/etc/passwd` names that exists in the
    acquisition (`_passwd_home`), not reached through a link leading out of it
    or back to its root."""
    top = base.resolve()
    for line in read_text(base / "etc" / "passwd").splitlines():
        f = line.split(":")
        if len(f) < 7 or not f[0]:
            continue
        home = _passwd_home(base, f[5])
        if home is None:
            continue
        try:
            rp = home.resolve()
            inside = home.is_dir() and rp != top and rp.is_relative_to(top)
        except (OSError, ValueError):     # 3.10's resolve raises ValueError too
            inside = False
        if inside:
            yield f[0], home


def _home_dirs(base: Path):
    """(user, home): /home/<user>, /root, then the other homes /etc/passwd names
    (`_passwd_homes`), each folder once."""
    seen: set[Path] = set()

    def first(d: Path) -> bool:
        rp = d.resolve()
        if rp in seen:
            return False
        seen.add(rp)
        return True

    home = base / "home"
    if home.is_dir():
        for d in home.iterdir():
            if d.is_dir() and first(d):
                yield d.name, d
    if (base / "root").is_dir() and first(base / "root"):
        yield "root", base / "root"
    for user, d in _passwd_homes(base):
        if first(d):
            yield user, d


def _fish_unescape(s: str) -> str:
    """fish writes a backslash as `\\` and a newline as `\n` in its history."""
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in "\\n":
            out.append("\n" if s[i + 1] == "n" else "\\")
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _fish(path: Path):
    """(time_utc, command) per entry of a fish history: `- cmd: <command>` with an
    optional `  when: <epoch>` after it. An entry with no command still ends the
    one before it, so its `when` is not taken for that one's."""
    cmd = None
    when = ""
    for line in read_text(path).splitlines():
        if line.startswith("- cmd:"):
            if cmd is not None:
                yield when, cmd
            cmd, when = _fish_unescape(line[len("- cmd:"):]).strip(), ""
        elif line.startswith("  when: ") and cmd is not None:
            epoch = line[len("  when: "):].strip()
            when = _utc(epoch) if epoch.isdigit() else ""
    if cmd is not None:
        yield when, cmd


# bash's HISTTIMEFORMAT marker and zsh's extended-history prefix.
_BASH_TIME = re.compile(r"^#(\d{9,11})$")
_ZSH_TIME = re.compile(r"^:\s*(\d{9,11}):\d*;")


def _utc(epoch: str) -> str:
    return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def iter_history(base: Path):
    """Yield (user, shell, seq, command) for every shell-history line under `base`.

    `seq` is the per-user 1..N on-disk order (reset for each user). zsh
    extended-history prefixes are stripped and HISTTIMEFORMAT epoch/comment
    markers are dropped, so callers get clean command text. Shared by the bash
    handler and the GTFOBins history scanner so both see identical commands.
    """
    for user, shell, seq, _when, cmd in iter_history_timed(base):
        yield user, shell, seq, cmd


def iter_history_timed(base: Path):
    """`iter_history` with the time each command was run, UTC, or '' when the
    shell did not record one: (user, shell, seq, time_utc, command)."""
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
            when = ""                 # a bash marker times the command after it
            for line in hist.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                m = _BASH_TIME.match(s)
                if m:
                    when = _utc(m.group(1))
                    continue
                # zsh ':<start>:<elapsed>;cmd' extended-history prefix -> keep the cmd
                if shell == "zsh" and s.startswith(":") and ";" in s:
                    z = _ZSH_TIME.match(s)
                    when = _utc(z.group(1)) if z else ""
                    s = s.split(";", 1)[1].strip()
                if not s or s.startswith("#"):  # blanks + comment lines
                    continue
                seq += 1
                yield user, shell, seq, when, s
                when = ""
        fish = home / _FISH
        if fish.is_file() and fish.resolve() not in seen:
            seen.add(fish.resolve())
            for when, cmd in _fish(fish):
                if cmd:
                    seq += 1
                    yield user, "fish", seq, when, cmd


def run(ctx) -> None:
    # analyst-editable named-tooling indicators (suspicious_tools.txt); the
    # technique-level hunt (reverse shells, GTFOBins escapes) is alert_gtfobins.csv.
    tools = load_indicators(Path(ctx.assets) / "suspicious_tools.txt")
    rows = [[seq, user, shell, when, "+".join(match_labels(tools, cmd)) if tools else "", cmd]
            for user, shell, seq, when, cmd in iter_history_timed(root(ctx.evidence))]
    write_csv(ctx.out, "art_shell_history.csv", ["id", "user", "shell", "time_utc", "flag", "command"], rows)
