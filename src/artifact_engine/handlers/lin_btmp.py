"""Handler: failed login attempts from var/log/btmp (binary utmp). Output: btmp.csv

btmp records FAILED logins (wrong user/password) -- the primary artifact for
brute-force / password-spray detection. Same binary layout as wtmp, parsed by
the shared parse_utmp. Complements logins.csv (which carries the text `lastb`
output) with the always-present binary source: the `host` column is the source
IP/host of each attempt and `user` is the account that was tried.
"""

from __future__ import annotations

from artifact_engine.handlers._lincommon import root
from artifact_engine.handlers.lin_wtmp import write_utmp


def run(ctx) -> None:
    write_utmp(ctx, root(ctx.evidence) / "var" / "log" / "btmp", "btmp.csv")
