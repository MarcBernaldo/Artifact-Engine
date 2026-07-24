# Lateral movement graph (pipeline phase 5)

`core/lateral.py`. Runs once per case, after every machine is parsed and
consolidated, and correlates authentication events **across** machines into a
single picture of who moved where. Rebuild it alone (no re-parse) with:

```
aeng lateral -p <evidence_dir>
```

| Output (at the evidence root) | Content |
|---|---|
| `lateral_movement.csv` | Full aggregated edge list — every logon relation seen, one row per (src, dst, user, logon_type, event_id). |
| `lateral_movement.html` | Curated interactive graph (vanilla-JS force-directed SVG, self-contained, zero external requests — opens on an air-gapped box). |

## Where the data comes from

Phase 5 reads **the per-machine outputs of earlier parsers**, never raw
evidence. Per Windows machine (VSS snapshots are skipped — a point-in-time copy
of the live host would duplicate every edge):

| File (under `<machine>/CSVs/`) | Producer | Contribution |
|---|---|---|
| `EventLogs/evtx_security.csv` | EvtxECmd | Destination-side logons: 4624/4625/4648/4768/4769. |
| `EventLogs/evtx_rdpOut.csv` | EvtxECmd (TerminalServices-RDPClient) | Source-side RDP dial-outs (1024 `Dest:`, 1102 `Address:`) with the real per-connection time. |
| `EventLogs/evtx_rdpSessions.csv` | EvtxECmd (TerminalServices-LocalSessionManager) | Destination-side inbound RDP: 21 logon / 25 **reconnect** (source in RemoteHost, account in UserName). Survives the Security log's rollover. |
| `EventLogs/evtx_rdpAuth.csv` | EvtxECmd (TerminalServices-RemoteConnectionManager) | Destination-side RDP auth success (1149). Same source/account columns. |
| `Registry/rdp_outbound.csv` | Terminal Server Client MRU parser | Every host this box ever RDP'd to + the account used (survives for years, and log rollover). |
| `Registry/reg_profList.csv` | RECmd (ProfileList) | SID → profile name, used to attribute RDPClient dial-outs (their `UserId` is a SID, `UserName` is empty). |
| `Registry/explorer_input.csv` | TypedPaths parser | Hand-typed UNC paths (`\\host\share`) — deliberate SMB access the client's Security log never records. |
| `SystemInfo/machine_info.json` | systeminfo parser | Host identity: name, FQDN, IPs → the host-resolution index. |
| `EventLogs/chainsaw_*.csv` | chainsaw | Rule verdicts (e.g. "Account Brute Force") attached to matching edges. |

Destination-side and source-side artifacts complement each other: the Security
log of the destination may have rolled over (or the destination was never
acquired), while the source-side MRU/RDPClient traces persist on the machine
that *initiated* the movement.

### Linux/UAC hosts (same graph)

Linux hosts join the **same** unified graph — their identity comes from the same
`machine_info.json` (Linux `SystemInfo/machine_info.json`, written by the UAC
machineinfo parser), so IPs/names resolve against the shared index and cross-OS
pivots (Windows → Linux and back) show up as ordinary edges. Loose-drop log
folders (`weblogs*`/`fortigate*`) are *not* hosts and never become nodes.

| File (under `<machine>/CSVs/`) | Producer | Contribution |
|---|---|---|
| `EventLogs/wtmp.csv` | `lin_wtmp` | Inbound login (`USER_PROCESS` with a remote `host`), with a real epoch timestamp — the Linux **timeline/chain** source. |
| `EventLogs/auth.csv` | `lin_auth` | sshd `Accepted` (the auth method), `Failed`/`Invalid user` (brute force). Carries the method and the failures; see the timestamp caveat below. |
| `EventLogs/btmp.csv` | `lin_btmp` | Failed logins (binary, always timestamped) — brute force / password spray. |
| `Network/known_hosts.csv` | `lin_known_hosts` | Per-account **outbound** SSH targets (reference, like RDP-MRU): a graph edge only when it lands on another acquired host. |

**Timestamp caveat.** Classic syslog `auth.log` lines carry **no year**
(`Mar 31 09:28:47`), so `auth.csv` timestamps usually don't parse into a real
time — those edges still count (method + failures) but can't sit on the timeline
or in a chain. `wtmp`/`btmp` are binary with epoch timestamps and carry the
Linux timeline instead. (Modern ISO-8601 syslog *does* parse; its zone offset is
treated as UTC — good enough for triage windows.)

## Event model

| Event | Direction | Kept when |
|---|---|---|
| 4624 successful logon | remote → this host | LogonType ∈ {3 network, 9 runas, 10 RDP}. Local/service types (2/4/5/7/11) are not lateral movement. |
| 4625 failed logon | remote → this host | Same type filter; reason `failed_logon` (spraying / brute force). |
| 4648 explicit credentials | this host → `TargetServerName` | Always (runas / outbound lateral); reason `explicit_creds`. |
| 4768 Kerberos TGT | source IP → DC | Logged only by DCs — seeing 4768/4769 is how a machine is marked `dc`. Flagged only if the source is an acquired host. |
| 4769 Kerberos TGS | source → **SPN host** | When the requested SPN is a host principal (`HOST$`, `cifs/host`, …) and the source is an acquired host, the edge is drawn source → that host (the resource actually reached), not source → DC. |
| RDPClient 1024/1102 | this host → RDP target | Source-side. The channel logs in the user's session, so the account arrives only as a SID (`UserId`); it is resolved to a name through the machine's own ProfileList (the profile-folder name — a renamed account may differ). An unresolvable SID leaves the edge account-less. |
| `LSM-21` / `LSM-25` | remote → this host | LocalSessionManager logon / **reconnect**; category `rdp`. Destination-side, outlives the Security log. A `LOCAL` (console) or IPv6 link-local source is not lateral movement and is dropped. |
| `RCM-1149` | remote → this host | RemoteConnectionManager "RDP authentication succeeded"; category `rdp`. Same drop rules. |
| `TSC-MRU` | this host → RDP target | From the registry MRU; `cert_accepted=yes` adds reason `untrusted_cert` (user clicked through a bad certificate). |
| `TypedPath` | this host → UNC host | Only `\\host\...` values. |

A network null-session logon (`ANONYMOUS LOGON`) gets reason `anonymous_logon`
— an enumeration / SMB-relay / exploit IOC that is always surfaced in the graph.

**Linux SSH events** map onto the same model:

| Event id | Direction | Kept when |
|---|---|---|
| `wtmp` | remote → this host | `USER_PROCESS` with a remote `host` (successful login; the timeline source). |
| `ssh` | remote → this host | `auth.log` `Accepted` (successful SSH, carries the method). |
| `ssh_fail` / `ssh_invalid` | remote → this host | `auth.log` `Failed` / `Invalid user` → reason `failed_logon` (+ `invalid_user`). |
| `btmp` | remote → this host | Any failed-login record → reason `failed_logon`. |
| `known_host` | this host → peer | `known_hosts` target; reference — reason only when the target is another acquired host. |

Same low-FP rule as Windows: a **routine** successful inbound SSH stays in the
CSV; the graph keeps failures, inter-case movement, chains, and `brute_success`.

## Identity resolution

**Hosts** — `machine_info.json` builds an index of every known IP / name / FQDN
→ canonical machine name. Tokens resolve by full value, then by short hostname;
a trailing `$` (machine account) is stripped, so `HOST07$` resolves to `HOST07`.
Unresolved names are canonicalised to short lower-case (FQDN/short/case variants
of the same external host merge); unresolved IPs stay verbatim.

**Accounts** — Windows accounts are case-insensitive and the KDC/EvtxECmd emit
the same principal many ways (`CORP\Administrator`, `corp\administrator`,
`CORP.LOCAL\Administrator`). `_clean_user` canonicalises to
`<NETBIOS_UPPER>\<user_lower>` (domain reduced to its first DNS label, so
`CORP.LOCAL` == `CORP`) so one principal is one node — while a genuinely
different domain (`OTHERDOM\`, `WORKGROUP\`) stays distinct.

## Edge aggregation and reasons

Rows collapse on the key `(src, dst, user, logon_type, event_id)`: `count`,
`first_seen`/`last_seen` window, and a capped sample of event timestamps (for
chain pairing). Each edge carries zero or more **reasons**; any reason ⇒
`suspicious=yes` in the CSV and inclusion in the graph:

`rdp`, `rdp_outbound`, `failed_logon`, `invalid_user`, `anonymous_logon`,
`explicit_creds`, `typed_unc`, `kerberos_service`, `untrusted_cert`,
`brute_success`, `case_to_case` (movement between two acquired hosts), `chainsaw`
(a chainsaw rule matched the same dst+user+event), `chain` (part of a pivot
chain, below).

`brute_success` (Linux) marks a successful SSH login where the **same account,
from the same source** first failed ≥ 5 times against that host — a brute force
that worked. It is keyed by `(src, dst, account)` on purpose: keying by
`(src, dst)` alone would fire on every user of a shared login/bastion host whose
accumulated failures cross the threshold.

Routine inbound network auth and outside-the-case Kerberos ticketing stay in
the CSV only — that keeps a DC that sees the whole domain from flooding the
graph.

## Pivot chains (X → B → Y)

The defining lateral-movement pattern: a successful inbound 4624 of account *U*
onto acquired host *B*, followed by outbound activity **from** *B* by the same
account within 12 h (or 1 h for the rare account-less RDP dial-out whose SID
did not resolve, which can only be tied to a session by proximity). Machine accounts (`HOST$`) are excluded —
their mutual authentication would chain everything. Both edges get reason
`chain`, and each chain is listed in the graph's **Attack paths** panel
(click to highlight the pair). Timestamps pair via a two-pointer scan over the
per-edge samples: each outbound event is matched to the latest inbound not
after it.

## Graph curation (what the HTML shows)

The CSV keeps everything; the HTML keeps it readable:

- Only edges with reasons; acquired hosts always present.
- External peers capped to the top-40 by volume — **except** any external
  touching a high-signal edge (`anonymous_logon`, `failed_logon`, `chain`,
  `chainsaw`, `explicit_creds`, `untrusted_cert`), which is never culled: a
  one-shot brute-force source matters at count 1.
- A **successful inbound RDP from a public (globally-routable) IP** is also never
  culled, even at count 1: internet-facing RDP landing straight on an internal
  host is a top-tier finding (initial access / hands-on-keyboard). Routine
  *internal* RDP (RFC1918/CGNAT/link-local source) stays under the volume cap so
  the graph doesn't fill with every workstation that ever RDP'd in.
- Node roles: `dc` (logged Kerberos KDC events — ground truth, so multi-DC
  domains mark all of them), `case` (acquired Windows host), `linux` (acquired
  Linux/UAC host), `server` (off-case node reached by NAME — an internal box
  someone hit), `external` (a bare IP — a logon source / attacker origin).
  Servers and externals are coloured apart so "where it reached" reads separately
  from "who came in".

Interactive features: direction arrows on curved edges, per-edge user + date
labels, search by user/host, filter by logon category (failed / explicit / rdp
/ rdp_mru / ssh / runas / kerberos / typed_unc / ssh_known_host / network), a
time-range slider with chronological playback, wheel zoom + pan, a chronological
timeline sidebar, and the Attack-paths panel. Embedded JSON is `</`-escaped —
usernames come from event logs and are attacker-controllable.

## CSV columns

`src, dst, user, logon_type, event_id, status(ok|failed), count, first_seen,
last_seen, src_in_case, suspicious, reasons(+joined), chainsaw(+joined)`.
Sorted most-flagged first. All timestamps UTC.

## Reading tips

- An edge's `count` is events, not sessions — a service reconnecting inflates it.
- `4769` edges into the DC from non-case sources are routine domain noise
  (CSV only); the interesting Kerberos edges are the re-pointed SPN ones.
- Source-side edges (`TSC-MRU`, `TypedPath`) may carry registry key-write
  timestamps, i.e. *last* use, not each use.
- If a machine lacks `machine_info.json` its IPs won't resolve to it, and
  inbound edges will show the bare IP as an `external` node instead.
