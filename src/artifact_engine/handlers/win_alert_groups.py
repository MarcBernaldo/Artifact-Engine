"""Handler: the Windows detections gathered by the artifact they read.
Outputs: alerts_mft.csv, alerts_execution.csv, alerts_shell.csv (see `_alertgroups`).
"""

from __future__ import annotations

from artifact_engine.handlers._alertgroups import HEADER, SPECS, gather, machine_root
from artifact_engine.handlers._lincommon import write_csv


def run(ctx) -> None:
    csvs = machine_root(ctx.out) / "CSVs"
    for table, specs in SPECS["windows"].items():
        write_csv(ctx.out, f"{table}.csv", HEADER, gather(csvs, specs))
