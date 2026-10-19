# Security policy

## Supported versions

Artifact-Engine is released from a single branch. Only the latest version on
`main` receives fixes; `aeng update` brings an installation up to it.

## Reporting a vulnerability

Report it privately through GitHub: the repository's **Security** tab, then
**Report a vulnerability**. Please do not open a public issue for it.

Redact the report as you would a bug report. This tool reads real evidence, so a
log or a sample can carry hostnames, usernames, IP addresses, domains and paths
from a case. Use placeholders (`HOST-01`, `jdoe`, `10.0.0.5`, `example.local`)
and describe the shape of a value rather than the value. If a crafted file is
needed to reproduce it, build one with synthetic content.

This is a one-person project: reports are handled as soon as possible, with no
fixed response time. You will be told when a fix is released.

## Scope

The engine treats every acquisition it processes as untrusted input. In scope:

- extraction writing outside the case folder (path traversal in an archive), or
  an archive that exhausts the disk or memory of the analyst's machine;
- crafted evidence that makes the engine run code, or that silently drops
  results while the run still reports success;
- `aeng setup` and `aeng update` fetching or running something other than what
  they name;
- anything in the generated reports (`.html`, `.xlsx`) that runs when an
  analyst opens them.

Out of scope, and reported upstream instead: vulnerabilities in the third-party
tools the engine runs as separate processes (EZ Tools, Hayabusa, Volatility 3,
7-Zip). A detection that misses something is a bug, not a vulnerability: open an
issue.
