"""Handler: Linux command lines that look like data leaving the host.
Output: exfil_commands.csv (see `_exfil`).

Command lines from each user's shell history and from UAC's process list
(`ps`), matched against LOLExfil's patterns.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _exfil
from artifact_engine.handlers._lincommon import live_response, read_lines, root, write_csv
from artifact_engine.handlers.lin_bash import iter_history
from artifact_engine.handlers.lin_processes import _parse_ps_lstart


def _lines(ctx):
    for user, shell, _seq, cmd in iter_history(root(Path(ctx.evidence))):
        yield f"{shell}_history", user, cmd
    lr = live_response(Path(ctx.evidence))
    if lr:
        ps: list[list] = []
        _parse_ps_lstart(read_lines(lr / "process" / "ps_-axo_pid_user_lstart_args.txt"), ps)
        for pid, user, _started, command in ps:
            yield "uac_process", f"pid {pid} {user}", command


def run(ctx) -> None:
    patterns = _exfil.load(Path(ctx.assets))
    if not patterns:
        raise HandlerSkip(f"no LOLExfil patterns ({_exfil.ASSET})")
    write_csv(ctx.out, _exfil.TABLE, _exfil.HEADER, _exfil.scan(_lines(ctx), patterns))
