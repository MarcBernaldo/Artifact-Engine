"""Handler: the Linux detections gathered by the artifact they read.
Outputs: alerts_bodyfile.csv, alerts_shell.csv (see `_alertgroups`).
"""

from __future__ import annotations

from artifact_engine.handlers._alertgroups import HEADER, SPECS, gather, machine_root
from artifact_engine.handlers._lincommon import write_csv


def run(ctx) -> None:
    csvs = machine_root(ctx.out) / "CSVs"
    for table, specs in SPECS["linux"].items():
        write_csv(ctx.out, f"{table}.csv", HEADER, gather(csvs, specs))
