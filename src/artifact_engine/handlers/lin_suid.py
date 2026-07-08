"""Handler: SUID/SGID binaries. Output: suid_sgid.csv

UAC pre-collects the set-uid / set-gid binary lists in
live_response/system/{suid,sgid}.txt (one absolute path per line). This reads
them and flags the entries that matter for privilege-escalation triage:

- gtfobins   : the binary is exploitable-if-suid (shell/interpreter/find/vim/
               tar/... -- things that should never carry the bit)
- unusual_path: the binary sits outside the standard system directories
               (a set-uid binary dropped in /tmp, /home, ... is a red flag)
- hidden_name: the file name starts with a dot

btrfs/zfs read-only snapshot copies are skipped (they only duplicate the live
filesystem and cannot be exploited read-only). It does not assert maliciousness.
"""

from __future__ import annotations

import re

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

# Exploitable-if-suid binaries (GTFOBins). Binaries that are *legitimately*
# set-uid on stock systems (su, sudo, passwd, mount, ping, pkexec, ...) are
# deliberately absent so they do not flag.
_GTFOBINS = frozenset((
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "ash", "busybox",
    "vi", "vim", "view", "vimdiff", "rvim", "rview", "nano", "pico", "ed", "emacs",
    "less", "more", "pg", "man",
    "awk", "gawk", "mawk", "nawk", "perl", "python", "python2", "python3",
    "ruby", "php", "lua", "luajit", "node", "nodejs", "tclsh", "wish", "expect", "rscript",
    "nc", "ncat", "netcat", "socat", "nmap", "tftp", "ftp", "wget", "curl",
    "ssh", "scp", "rsync", "ncftp", "telnet",
    "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "xz", "cpio", "ar",
    "7z", "7za", "rar", "unrar", "dd", "cp", "mv", "install",
    "env", "nice", "ionice", "nohup", "setarch", "unshare", "chroot", "taskset",
    "stdbuf", "timeout", "time", "watch", "flock", "start-stop-daemon", "run-parts", "xargs",
    "gdb", "strace", "ltrace", "make", "cmake", "gcc", "cc", "as", "ld",
    "systemctl", "docker", "lxc", "runc", "ctr",
    "sed", "cut", "sort", "tac", "head", "tail", "tee", "cat", "dialog", "whiptail",
    "comm", "paste", "join", "nl", "od", "xxd", "hexdump", "strings", "split",
    "csplit", "fold", "fmt", "grep", "egrep",
    "openssl", "gpg", "ip", "nft", "iptables", "tcpdump", "capsh", "setcap",
    "find", "file", "base64", "base32", "basenc", "date", "rev", "look", "column",
    "pr", "ptx", "readelf", "nm", "objdump", "dmsetup", "eqn", "troff", "tbl",
    "soelim", "ul", "uniq", "wc", "shuf", "sqlite3", "jq", "tmux", "ss", "sysctl",
    "journalctl", "git", "chmod", "chown", "choom", "cpulimit", "dig", "gcore",
    "genisoimage", "hping3", "scanmem", "restic", "terraform", "vigr", "vipw",
))

# Directories where a set-uid binary legitimately lives.
_STD_PREFIXES = (
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
    "/usr/local/sbin/", "/usr/local/lib", "/usr/lib", "/lib", "/opt/", "/snap/",
)

# btrfs (/.snapshots/<n>/snapshot/...) and zfs (/.zfs/snapshot/...) copies.
_SNAPSHOT = re.compile(r"/\.snapshots/\d+/snapshot/|/\.zfs/snapshot/")


def _classify(path: str, name: str) -> str:
    if not path.startswith(_STD_PREFIXES):
        return "unusual_path"
    if name in _GTFOBINS:
        return "gtfobins"
    if name.startswith("."):
        return "hidden_name"
    return ""


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    sysd = (lr / "system") if lr else None
    rows: list[list] = []
    if sysd:
        for kind, fname in (("suid", "suid.txt"), ("sgid", "sgid.txt")):
            for ln in read_lines(sysd / fname):
                p = ln.strip()
                if not p or _SNAPSHOT.search(p):
                    continue
                name = p.rsplit("/", 1)[-1]
                reason = _classify(p, name)
                rows.append([kind, p, name, reason, "yes" if reason else ""])
    # Suspicious first, then by type/path.
    rows.sort(key=lambda r: (r[4] == "", r[0], r[1]))
    write_csv(ctx.out, "suid_sgid.csv",
              ["type", "path", "name", "reason", "suspicious"], rows)
