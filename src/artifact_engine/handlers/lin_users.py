"""Handler: local accounts from /etc/passwd, enriched with /etc/group and
/etc/shadow. Output: users.csv

Per the SANS Linux hunt guidance this surfaces, for each account: primary and
supplementary groups (so membership in privileged groups -- root/sudo/wheel/
adm -- is visible), the password status from shadow (locked / no password /
set) and the login shell. Flags the entries that matter: a non-root account
with UID 0, and accounts with no password. shadow is root-only and many
acquisitions do not collect it; pw_status is then blank.

`pw_changed_utc` (v0.7.170) is the day shadow says the password last changed
(field 3, days since 1970-01-01): a change on the day of an intrusion is a
lead. Only the status and that date are read from shadow, never the hash.
"""

from __future__ import annotations

from datetime import date, timedelta

from artifact_engine.handlers._lincommon import read_lines, root, write_csv

# Groups whose membership grants administrative / privilege-escalation power.
_PRIV_GROUPS = {"root", "sudo", "wheel", "adm", "admin", "sudoers", "docker",
                "lxd", "disk", "shadow"}


def _groups(base):
    """Parse /etc/group -> (gid->name, user->set(supplementary group names))."""
    gid_name: dict[str, str] = {}
    member_of: dict[str, set] = {}
    for line in read_lines(base / "etc" / "group"):
        if not line.strip() or line.startswith("#"):
            continue
        p = line.split(":")
        if len(p) < 4:
            continue
        name, _, gid, members = p[0], p[1], p[2], p[3]
        gid_name[gid] = name
        for m in (m.strip() for m in members.split(",") if m.strip()):
            member_of.setdefault(m, set()).add(name)
    return gid_name, member_of


def _changed(days: str) -> str:
    """shadow's last-change field as a date; 0 means a change is forced at the
    next login."""
    if not days.strip().isdigit():
        return ""
    n = int(days)
    if n == 0:
        return "change forced at next login"
    try:
        return (date(1970, 1, 1) + timedelta(days=n)).isoformat()
    except OverflowError:
        return ""


def _shadow(base):
    """Parse /etc/shadow -> user -> (pw_status, pw_changed_utc). pw_status is
    locked | no_password | password_set; the hash itself is never kept."""
    status: dict[str, tuple[str, str]] = {}
    for line in read_lines(base / "etc" / "shadow"):
        if not line.strip() or line.startswith("#") or ":" not in line:
            continue
        fields = line.split(":")
        user, pw = fields[0], fields[1]
        changed = _changed(fields[2]) if len(fields) > 2 else ""
        if pw == "":
            state = "no_password"
        elif pw[0] in "!*" or pw == "!!":
            state = "locked"
        else:
            state = "password_set"
        status[user] = (state, changed)
    return status


def run(ctx) -> None:
    base = root(ctx.evidence)
    gid_name, member_of = _groups(base)
    pw_status = _shadow(base)

    rows: list[list] = []
    for line in read_lines(base / "etc" / "passwd"):
        if not line.strip() or line.startswith("#"):
            continue
        p = line.split(":")
        if len(p) < 7:
            continue
        user, uid, gid, gecos, home, shell = p[0], p[2], p[3], p[4], p[5], p[6]
        primary = gid_name.get(gid, "")
        extra = sorted(member_of.get(user, set()))
        all_groups = ({primary} if primary else set()) | set(extra)
        privileged = "yes" if all_groups & _PRIV_GROUPS else ""
        status, changed = pw_status.get(user, ("", ""))
        suspicious = "yes" if (uid == "0" and user != "root") or status == "no_password" else ""
        rows.append([user, uid, gid, primary, ";".join(extra), shell,
                     status, changed, privileged, gecos, home, suspicious])

    # Suspicious first, then privileged, then by uid.
    rows.sort(key=lambda r: (r[11] != "yes", r[8] != "yes", _int(r[1])))
    write_csv(ctx.out, "users.csv",
              ["user", "uid", "gid", "group", "extra_groups", "shell",
               "pw_status", "pw_changed_utc", "privileged", "gecos", "home",
               "suspicious"], rows)


def _int(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 1 << 30
