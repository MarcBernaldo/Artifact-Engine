"""Handler: failed login attempts from var/log/btmp (binary utmp). Output: btmp.csv

btmp records FAILED logins (wrong user/password) -- the primary artifact for
brute-force / password-spray detection. Same binary layout as wtmp, parsed by
the shared parse_utmp. Complements logins.csv (which carries the text `lastb`
output) with the always-present binary source: the `host` column is the source
IP/host of each attempt and `user` is the account that was tried.
"""

from __future__ import annotations

from artifact_engine.handlers._lincommon import root, write_csv
from artifact_engine.handlers.lin_wtmp import COLUMNS, parse_utmp


def run(ctx) -> None:
    btmp = root(ctx.evidence) / "var" / "log" / "btmp"
    rows = parse_utmp(btmp) if btmp.is_file() else []
    write_csv(ctx.out, "btmp.csv", COLUMNS, rows)
