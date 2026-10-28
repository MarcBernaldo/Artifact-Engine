"""Handler: Linux command lines that look like data leaving the host.
Output: alert_exfil_commands.csv (see `_exfil`).

Command lines from each user's shell history and from UAC's process list
(`ps`), matched against LOLExfil's patterns. A history line is timed when the
shell wrote a time for it, a process by its start (in UTC when the host's zone
is known).
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _exfil
from artifact_engine.handlers._lincommon import live_response, read_lines, root, write_csv
from artifact_engine.handlers._syslogtime import host_zone
from artifact_engine.handlers.lin_bash import iter_history_timed
from artifact_engine.handlers.lin_process_network import _parse_ps_lstart, lstart_utc


def _lines(ctx):
    for user, shell, _seq, when, cmd in iter_history_timed(root(Path(ctx.evidence))):
        yield f"{shell}_history", user, cmd, when
    lr = live_response(Path(ctx.evidence))
    if lr:
        ps: list[list] = []
        _parse_ps_lstart(read_lines(lr / "process" / "ps_-axo_pid_user_lstart_args.txt"), ps)
        zone = host_zone(Path(ctx.evidence))
        for pid, user, started, command in ps:
            yield "uac_process", f"pid {pid} {user}", command, lstart_utc(started, zone)


def run(ctx) -> None:
    patterns = _exfil.load(Path(ctx.assets))
    if not patterns:
        raise HandlerSkip(f"no LOLExfil patterns ({_exfil.ASSET})")
    write_csv(ctx.out, _exfil.TABLE, _exfil.HEADER, _exfil.scan(_lines(ctx), patterns))
