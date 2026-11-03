# Improvements backlog

What is still open, one entry each with the reason it is worth doing. Items that
were built or dropped are not kept here: git holds every earlier version of this
file, with the reasoning that closed them. What each parser does today is in
[`atlas.html`](atlas.html) and `aeng list-parsers`.

## Detection and triage

- **Known-benign publisher allowlist.** Security agents, remote-support clients
  and vendor updaters trip the service and path rules on every host. Key it on the
  Amcache publisher + install path + service ImagePath and downgrade, never drop:
  the row stays, with the reason it was downgraded.
- **Package integrity, reasoned over (Linux).** `art_packages`' verification rows
  are parsed and nothing judges them. Two cheap rules: a package-owned shared object
  under a `security/` path failing its checksum (a PAM module replaced), and the
  same hash in the 32- and 64-bit library paths (impossible for a genuine library).
- **Uneven package-verification coverage.** Full verification finished on some
  hosts and covered a few dozen files on others; until the cause is known (a
  timeout, the collector profile, a silent failure), report the file count beside
  any "clean" verdict drawn from it.
- **BITS download URLs on the front page.** A BITS job `art_bits_jobs` flags
  reaches the findings like any flagged row; the unflagged URLs, and the
  `art_evtx_bits` channel, are never summarised. BITS is a standard download
  channel and its URLs belong beside the browser downloads.

## Sources collected and not read

- **Community lists not yet matched** (mthcht/awesome-lists): double extensions,
  `/Hijacklibs/` against MFT DLL paths, suspicious ports, hostnames, DynDNS and TLDs.
  The named-pipe, mutex, USB-id and firewall-rule lists need data disk triage does
  not collect. The large user-agent and DoH lists would change the web hunt's
  character: an opt-in second file at most.

## Validation waiting on evidence

- **PCA** is wired and unit-tested but never run on a real artifact: needs a Win11
  22H2+ collection with `C:\Windows\appcompat\pca`. The museum has none. The same
  collection would confirm `art_pca_general`'s field order for PcaGeneralDb0/1, which
  is the community's (Microsoft documents none); a line that does not split into
  its 8 fields is kept whole in `extra`.
- **WMI CCM RUA**: the binary-header path of `OBJECTS.DATA` is unit-tested only on
  the XML path.
- **MDATP threats**: the threat/quarantine branch of `art_mdatp` is exercised only
  by fixtures; the acquisitions at hand had none.

## Engine

- **Pin the downloaded tools' hashes** (EZ tools, SIDR) once known.
- **Port `aeng mcp` to mcp 2.** The SDK's 2.x renamed `FastMCP` to `MCPServer` and
  changed other server APIs; `mcp_server.py` is written for 1.x and the extra is
  capped `<2`. Dependabot ignores the major until the port is done.

## Judged, not built

| Artifact | Why not |
|---|---|
| ThumbCache | answers "this image existed"; the MFT already has the name |
| RDP bitmap cache | output is image tiles, a manual deep dive after the graph points at a session |
| `Syscache.hve` | only with a registry pass that happens anyway |
| ETL traces (WMI, WDI, SleepStudy, DeliveryOptimization) | needs an ETL decoder; only DeliveryOptimization has clear triage value |
| `$LogFile`, `$SDS`, `$Boot`, `$T` | `$LogFile` analysis is specialist and spans hours; `$SDS` answers only ACL questions |
| .NET CLR usage logs | Prefetch and Amcache usually carry the same execution |
| P2P / torrent / IRC clients | not in `!SANS_Triage` |
