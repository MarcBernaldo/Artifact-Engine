"""Regression over the DFIR Artifact Museum's public samples (opt-in, slow).

AENG_MUSEUM names a case laid out by `tests/museum_layout.py`. The engine parses it
from scratch: every parser must finish without an error (exit 0), and every machine
holding a file `_FED` names must get rows in the tables it feeds. The samples are
real files from dozens of Windows builds and tools, dirty hives and torn databases
among them -- the variety synthetic bytes stand in for.
"""

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

CASE = os.environ.get("AENG_MUSEUM", "")
pytestmark = pytest.mark.skipif(not CASE, reason="AENG_MUSEUM names no museum case")

# table prefix -> what feeds it, as a glob under the volume root
_FED = {
    "art_mft": "$MFT",
    "art_usn": "$Extend/$J",
    "art_prefetch": "Windows/prefetch/*.pf",
    "art_amcache_": "Windows/AppCompat/Programs/Amcache.hve",
    "art_reg_shimcache": "Windows/System32/config/SYSTEM",
    "art_reg_services": "Windows/System32/config/SYSTEM",
    "art_reg_users": "Windows/System32/config/SAM",
    "art_evtx_system": "Windows/System32/winevt/Logs/System.evtx",
    "art_evtx_security": "Windows/System32/winevt/Logs/Security.evtx",
    "art_srum_": "Windows/System32/sru/SRUDB.dat",
    "art_search_": "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb",
    "art_sum_": "Windows/System32/LogFiles/SUM/Current.mdb",
    "art_lnk": "Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk",
    "art_jumplist_": "Users/*/AppData/Roaming/Microsoft/Windows/Recent/*Destinations/*",
    "art_recentfilecache": "Windows/AppCompat/Programs/RecentFileCache.bcf",
    "art_wer": "ProgramData/Microsoft/Windows/WER/ReportArchive/*/Report.wer",
    "art_win_timeline": "Users/*/AppData/Local/ConnectedDevicesPlatform/*/ActivitiesCache.db",
}


@pytest.fixture(scope="module")
def summary() -> dict:
    case = Path(CASE)
    rc = subprocess.run([sys.executable, "-m", "artifact_engine", "run", "-p", str(case),
                         "--force"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=4 * 3600, check=False).returncode
    data = json.loads((case / "run-summary.json").read_text(encoding="utf-8"))
    data["rc"] = rc
    return data


def test_every_parser_finishes(summary):
    assert summary["errors"] == []
    assert summary["rc"] == 0


def test_every_artifact_present_gives_rows(summary):
    missing = []
    for vol in sorted(Path(CASE).glob("*/C")):
        dbs = list(vol.glob("*.db"))
        assert dbs, f"{vol.parent.name}: no database"
        con = sqlite3.connect(dbs[0])
        try:
            tables = [t for (t,) in con.execute(
                "select name from sqlite_master where type='table'")]
            for prefix, feed in _FED.items():
                if not any(vol.glob(feed)):
                    continue
                rows = sum(con.execute(f'select count(*) from "{t}"').fetchone()[0]
                           for t in tables if t.startswith(prefix))
                if not rows:
                    missing.append(f"{vol.parent.name}: {prefix} (fed by {feed})")
        finally:
            con.close()
    assert not missing, "\n".join(missing)
