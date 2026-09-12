"""Handler: DeepBlueCLI (SANS) over the Event Logs.

DeepBlue.ps1 is a PowerShell script that analyzes a .evtx for suspicious activity
(obfuscated PowerShell, brute force, persistence, etc.). It is run per log and the
result is written to DeepBlue-<log>.csv (normalized to deepblue_<log> via short).
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core import evidence, procs
from artifact_engine.core.runner import HandlerSkip

# DeepBlue.ps1's own words when it gives up on a log, and the ONLY way to know it
# did. MEASURED, against the samples that ship with the tool and 200 KB of random
# bytes named `.evtx`: the script catches the `Get-WinEvent` failure itself,
# prints this with `Write-Host` -- so STDOUT, not stderr -- and then calls a bare
# `exit`, which is exit code 0. The pipeline behind it still runs, so `Export-Csv`
# writes a 3-byte file.
#
# Every signal a caller normally reads therefore says the log was analysed and was
# clean: exit 0, empty stderr, a CSV that looks exactly like the one a quiet log
# produces. A corrupt or truncated Security.evtx -- the one an attacker who
# tampered with the logs leaves behind -- would have passed as nothing to see.
#
# The literal is English because the script writes it; the operating system's own
# message on the next line is localised and is not matched.
_BAILED_OUT = "Get-WinEvent error:"

# Logs where DeepBlueCLI adds value.
_LOGS = [
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Windows PowerShell.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
]


def _ps_quote(path: Path) -> str:
    """A path as a PowerShell single-quoted literal.

    Everything else here passes argv lists to CreateProcess, but DeepBlue needs a
    pipeline, so this one builds a `-Command` string - and inside a single-quoted
    PowerShell string the only escape is a doubled quote. A case folder whose name
    carries an apostrophe (`C:\\Cases\\Web d'Exemple compromesa`) - routine in
    Catalan, Spanish, French and Irish naming - otherwise ends the string early:
    the rest of the path is parsed as code, the command fails, and the logs for
    that machine are silently never analysed.
    """
    return "'" + str(path).replace("'", "''") + "'"


def run(ctx) -> None:
    # The script AND the interpreter come from the one resolver, which for a
    # `.ps1` returns both: (interpreter, script). Reported as an ERROR and not a
    # skip, even on a host that can never run it -- `skipped` is a statement about
    # the MACHINE ("no such artifact here"), and reading a limited installation as
    # a quiet host is the confusion `aeng preflight` exists to prevent.
    if ctx.tool is None or not ctx.tool.ok:
        raise RuntimeError(ctx.tool.reason if ctx.tool else "DeepBlueCLI is not declared")
    ps1 = Path(ctx.tool.argv[-1])
    shell_argv = ctx.tool.argv[:-1]

    logs_dir = evidence.in_tree(ctx.evidence, "Windows/System32/winevt/Logs")
    ctx.out.mkdir(parents=True, exist_ok=True)

    analysed, failed = 0, []
    for log in _LOGS:
        evtx = logs_dir / log
        if not evtx.is_file():
            continue
        analysed += 1
        safe = log.replace("%4", "-").replace(" ", "").replace(".evtx", "")
        out_csv = ctx.out / f"DeepBlue-{safe}.csv"
        # Set-Location to the script folder: DeepBlue reads regexes.txt relative to the CWD.
        # -Command receives the WHOLE pipeline as a single argument (there is no shell here).
        ps = (
            f"Set-Location {_ps_quote(ps1.parent)}; "
            f"& {_ps_quote(ps1)} {_ps_quote(evtx)} | "
            f"Export-Csv -NoTypeInformation -Encoding UTF8 -Path {_ps_quote(out_csv)}"
        )
        cmd = [*shell_argv, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps]
        rc, out, err = procs.run(cmd, timeout=1800)
        if rc != 0 or _BAILED_OUT in out:
            # No table at all beats an empty one. `Export-Csv` still created the
            # file, and a header-only DeepBlue CSV is indistinguishable from the
            # result for a log that was read and held nothing -- which is the
            # reading an analyst would give it.
            out_csv.unlink(missing_ok=True)
            failed.append(safe)
            if ctx.log:
                detail = (err.strip() or out.strip()).splitlines()
                ctx.log.warning(f"[!] deepblue could not analyse {safe} (exit {rc}): "
                                f"{detail[0][:160] if detail else 'no output'}")

    if not analysed:
        raise HandlerSkip("none of the event logs DeepBlueCLI reads are present")
    if len(failed) == analysed:
        raise RuntimeError(f"DeepBlueCLI read none of the {analysed} log(s) it was "
                           f"given: {', '.join(failed)}")
