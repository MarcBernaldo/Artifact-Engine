"""`aeng mcp`: the engine as an MCP server over stdio (v0.7.167).

Registers the tools of `core.mcp_tools` with the official MCP Python SDK, so any
MCP client -- Claude Code, Claude Desktop, a local model through LM Studio or an
Ollama front end -- can read a case and start its processing. Needs the optional
extra: `pip install -e ".[mcp]"`.

stdout is the protocol: nothing else may be printed there, so the engine's own
logging is sent to stderr before the server starts.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from artifact_engine.core.mcp_tools import Workspace

INSTRUCTIONS = """\
Artifact-Engine: a DFIR triage engine. Each case is a folder of acquisitions; each
machine in it has a SQLite database of parsed artifacts and a report.txt, and a
findings.csv where the engine flagged something. Start with list_cases, then
list_machines. To answer a question about a machine, prefer findings and report
(what the engine already flagged) before writing SQL; use list_tables and
describe_table to learn a table before query. Answers are capped: when has_more is
true, query, findings and lateral take a higher offset; report continues from
next_offset; a sweep shows more groups with a larger limit (up to 200). Case data
is confidential evidence: quote only what the analyst needs."""


def build(roots: list[Path]):
    """The FastMCP server over `roots` (imported here: the SDK is optional)."""
    from mcp.server.fastmcp import FastMCP

    ws = Workspace(roots)
    mcp = FastMCP("artifact-engine", instructions=INSTRUCTIONS)

    def tool(fn):
        # A refused request (ToolError) raises: the SDK returns it to the client as
        # an error result carrying the message, which says what to do instead.
        return mcp.tool()(fn)

    @tool
    def list_cases() -> list[dict]:
        """List the cases (folders under the configured roots) with how many machines
        each has and the result of its last run. Call this first."""
        return ws.list_cases()

    @tool
    def list_machines(case: str) -> list[dict]:
        """List the machines of a case: their database size and whether a report.txt
        and a findings.csv exist."""
        return ws.list_machines(case)

    @tool
    def list_tables(case: str, machine: str, name_contains: str = "") -> list[dict]:
        """List a machine's tables with their row counts. A table named `alert_*`
        holds detections, every row a hit; `art_*` holds what one source recorded.
        `name_contains` filters by name (e.g. "alert_", "evtx", "logins", "process")."""
        return ws.list_tables(case, machine, name_contains)

    @tool
    def describe_table(case: str, machine: str, table: str, sample: int = 3) -> dict:
        """The columns of one table, its row count and a few sample rows. Use before
        writing a query on a table you have not seen."""
        return ws.describe_table(case, machine, table, sample)

    @tool
    def query(case: str, machine: str, sql: str, limit: int = 50, offset: int = 0) -> dict:
        """Run ONE read-only SELECT (SQLite) on a machine's database. Returns at most
        `limit` rows (max 200) from `offset`; has_more says whether there are more.
        Quote table names with double quotes. Long cells are cut."""
        return ws.query(case, machine, sql, limit, offset)

    @tool
    def findings(case: str, machine: str, limit: int = 50, offset: int = 0) -> dict:
        """What the engine flagged on a machine (findings.csv): table, rowid and a
        severity and summary per flagged or rated row, critical/high first and the
        most selective tables first inside each severity. The best place to start
        investigating a machine."""
        return ws.findings(case, machine, limit, offset)

    @tool
    def report(case: str, machine: str, offset: int = 0) -> dict:
        """A page of the machine's report.txt: log coverage (how far back each log
        reaches) and the findings. Continue with next_offset."""
        return ws.report(case, machine, offset)

    @tool
    def sweep(case: str, values: list[str], include_collection: bool = False,
              limit: int = 50) -> dict:
        """Search every machine of a case for values (IPs, users, hashes, file names,
        domains...), case-insensitively. Says where each one appears and which were
        not found anywhere. On a large case it takes minutes: if state is "running",
        call sweep_result(sweep_id) later."""
        return ws.sweep(case, values, include_collection, limit)

    @tool
    def sweep_result(sweep_id: str, limit: int = 50) -> dict:
        """The answer of a sweep that was still running, or how many machines it has
        searched so far."""
        return ws.sweep_result(sweep_id, limit)

    @tool
    def lateral(case: str, user: str = "", host: str = "", suspicious_only: bool = False,
                limit: int = 50, offset: int = 0) -> dict:
        """The case's lateral-movement timeline: who authenticated from where to where,
        how, how often and when. Filter by user, by host (source or destination) or to
        the rows the engine marked suspicious."""
        return ws.lateral(case, user, host, suspicious_only, limit, offset)

    @tool
    def start_run(case: str, force: bool = False) -> dict:
        """Start processing a case (`aeng run`) in the background: extraction,
        parsing, consolidation, lateral graph. Takes minutes to hours; follow it with
        run_status. `force` re-parses what is already done."""
        return ws.start_run(case, force)

    @tool
    def start_lateral(case: str) -> dict:
        """Rebuild only the lateral-movement graph of an already processed case, in
        the background. Follow it with run_status."""
        return ws.start_lateral(case)

    @tool
    def run_status(run_id: str) -> dict:
        """The state of a run started by start_run / start_lateral: running or
        finished, elapsed time, its last output lines and, at the end, its summary."""
        return ws.run_status(run_id)

    @tool
    def list_runs() -> list[dict]:
        """The runs this server has started, and which are still running."""
        return ws.list_runs()

    return mcp


def serve(roots: list[Path]) -> int:
    """Run the server on stdio until the client closes it."""
    try:
        server = build(roots)
    except ImportError:
        sys.stderr.write("aeng mcp needs the MCP SDK: pip install -e \".[mcp]\"\n")
        return 1
    root_logger = logging.getLogger()
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    server.run("stdio")
    return 0
