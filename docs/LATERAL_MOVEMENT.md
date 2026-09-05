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

### Loose EVTX drops (same graph)

A folder of hand-delivered event logs (`evtx[-label]`, see
[ARCHITECTURE](ARCHITECTURE.md#loose-drops-weblogs--fortigate--evtx-profiles))
**is** a host: its logons are the same 4624/4625/LSM/RCM evidence an acquisition
would carry, so it joins the graph like any Windows machine. Detection can only
name it after its folder, so as soon as phase 3 finishes it is renamed to the host
its events name — the most frequent `Computer` value in the parsed EVTX CSVs
(`detector.name_evtx_drops`) — and it lands on that host's node. `lateral.build`
repeats the rename (idempotent) because `aeng lateral` re-detects from scratch, and
since 0.7.12 `pipeline.detect` does too, so the names are settled before the graph
rather than inside it. Note it has no
`machine_info.json`, so its own IPs are unknown: peers referring to that host **by
IP** stay separate nodes unless the same host was also acquired. Dropping logs of
a host that is *also* in the case is fine (same node), but overlapping events are
counted from both sources.

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

`rdp_public`, `rdp_outbound`, `failed_logon`, `invalid_user`, `anonymous_logon`,
`explicit_creds`, `typed_unc`, `kerberos_service`, `untrusted_cert`,
`brute_success`, `case_to_case` (movement between two acquired hosts), `chainsaw`
(a chainsaw rule matched the same dst+user+event), `chain` (part of a pivot
chain, below).

**A successful inbound RDP is not, by itself, a reason.** RDP is the normal
administration transport on a Windows estate, so flagging every session is the
same mistake as flagging every successful SSH — on a real case it put 89 % of all
edges under `suspicious=yes`, most of them one private host reaching another and
nothing more, which makes the column meaningless. Routine inbound RDP therefore
stays in the CSV like a routine inbound SSH, and only the notable shapes carry a
reason: `rdp_public` (the source is a globally-routable internet address —
internet-facing RDP straight onto an internal host) and `case_to_case`. A failed
attempt, a chainsaw verdict, an `ANONYMOUS LOGON` or a pivot chain each add their
own reason, so an attack-shaped session never depends on this gate.
**Source-side** RDP evidence (`rdp_outbound`, `typed_unc`) is untouched: it comes
from a machine we hold and is low-volume, so it stays flagged as the reach-out
map it is.

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
- External peers capped to the top-40 by volume — **except** any external that
  authenticated **successfully** on a high-signal edge (`anonymous_logon`,
  `rdp_public`, `chain`, `chainsaw`, `explicit_creds`, `untrusted_cert`,
  `brute_success`), which is never culled: one of those matters at count 1.
- **A peer seen only on FAILED logons never got in**, so hundreds of them are one
  spray campaign rather than hundreds of findings. They are all kept while few;
  past `_MAX_BRUTE` only the loudest are drawn and the rest are counted in the
  header. The test is the *outcome*, not the label — our own `failed_logon` and
  chainsaw's "Account Brute Force" describe the same thing, and keying on the
  outcome survives a ruleset change. On a real case this took the graph from 443
  nodes (368 of them internet sources that had only ever failed, 334 of those held
  in by that one chainsaw rule) down to 115, without losing a single pivot chain.
- **The header states what was left out** — `115 hosts, 460 edges · 353 peer(s)
  hidden (326 brute-force sources) — full list in lateral_movement.csv`. A graph
  that trims silently is how three internet-facing RDP sources once went unnoticed;
  the CSV is always complete.
- Chainsaw's RDP/logon rulesets label ordinary session events ("RDS - Session
  logoff succeeded", "RDP Session Connected", "User Authentication Succeeded", …)
  alongside real detections. Those labels are dropped (`_CHAINSAW_SKIP`), so
  `chainsaw` in the reasons column always means an actual verdict — an edge is
  never flagged for the crime of being an RDP session, which `event_id` /
  `logon_type` already record.
  That includes `rdp_public` — a **successful inbound RDP from a globally-routable
  IP** is never hidden, even at count 1: internet-facing RDP landing straight on an
  internal host is a top-tier finding (initial access / hands-on-keyboard). Routine
  *internal* RDP carries no reason at all (above), so it never reaches the graph.
- Node roles: `dc` (logged Kerberos KDC events — ground truth, so multi-DC
  domains mark all of them), `case` (acquired Windows host), `linux` (acquired
  Linux/UAC host), `server` (off-case node reached by NAME — an internal box
  someone hit), and a bare source IP split into `public` (a globally-routable
  internet address — attacker origin / C2 / internet-facing access, coloured hot
  magenta so it jumps out) vs `external` (an internal host: a private
  RFC1918/CGNAT/link-local IP, or any address inside a range declared in the
  config's `internal_networks`, however routable that range is).
  The four off-case roles are coloured apart so "where it reached", "who came in"
  from inside, and "who came in from the internet" all read separately.

Interactive features: direction arrows on curved edges, per-edge user + date
labels, search by user/host, filter by **mechanism** (explicit / rdp / rdp_mru /
ssh / runas / kerberos / typed_unc / ssh_known_host / network) and, on a separate
axis, by **outcome** (ok / failed), a **public-IP-only** toggle (show only edges touching a public internet address —
isolate internet-facing access in one click) and a case-to-case-only toggle, a
time-range slider with chronological playback, wheel zoom + pan, and the
Attack-paths panel. Embedded JSON is `</`-escaped — usernames come from event
logs and are attacker-controllable.

**Mechanism and outcome are separate axes.** The category names HOW access was
attempted and never whether it worked; `status` carries that. Until v0.7.7 a
failure overrode the mechanism, so a failed Kerberos request and a failed network
logon collapsed into one class and the graph could say that something failed but
not what. Colour now carries the mechanism, a failure is drawn **dashed** (which
is what it always was), and the two filters combine — "failed Kerberos" is two
clicks. Because the drawn-edge key includes the status, a successful and a failed
attempt between the same pair stay two distinct edges.

**Every chip explains itself on hover.** One sentence per mechanism and per
reason, held in `CAT_DESC` / `REASON_DESC` in `core/lateral_report.py`. Two meta-tests
pin both vocabularies to what the code actually emits, so a new class or reason
cannot ship without an explanation.

**Filter by reason.** A second chip row lists every reason present with its edge
count. Unlike the category chips (all on, click to remove) this is a *positive*
selection: none picked = no filter, picking some shows the edges carrying **any**
of them — `chain` alone, or `brute_success` + `anonymous_logon`, which is how you
actually hunt. It filters on the canonical tokens, not on the displayed text
(which substitutes chainsaw's rule names and would otherwise give one chip per
rule).

**Get the view out.** `copy IPs` puts the visible external/public peers on the
clipboard (blocklist / IOC list) and `export CSV` downloads the visible edges as
`lateral_movement_filtered.csv` — whatever you narrowed down to is usually the
next thing that goes into a ticket, and re-deriving it by hand from the full CSV
was a tax the web report never charged.

**Node detail + scoped timeline.** Selecting a host opens a panel that *stays*
(the hover tooltip disappears the moment the mouse moves): role, edge/peer counts,
the UTC window, its reasons, the accounts seen, and its busiest peers with
direction. The timeline sidebar narrows to that host's events at the same time
(`Timeline — HOST (n, UTC)`). Clicking one of its rows keeps the scope — you were
reading that host — while clicking a chain drops it, since a chain spans three.

## CSV columns

`src, dst, user, logon_type, event_id, status(ok|failed), count, first_seen_utc,
last_seen_utc, src_in_case, src_scope, suspicious, reasons(+joined),
chainsaw(+joined)`. Sorted most-flagged first.

`src_scope` is which side of the perimeter the source is on: `public`,
`internal` (inside a range declared in `internal_networks`), `private`, or EMPTY
when the source is a host NAME rather than an address — which is a different
answer from `private` and must not be read as one.

**All timestamps are UTC**, and the columns say so — every source feeding an edge
is UTC already (EvtxECmd renders the event log's UTC FILETIME, `wtmp`/`btmp` are
epoch→UTC, the registry key-write columns are `_utc`). The HTML carries the same
"all times UTC" marker in its header: its JS anchors each value to UTC before
`Date.parse` and formats with `getUTC*`, so opening the report on a UTC+2
workstation shows the case clock, not the analyst's.

## Reading tips

- An edge's `count` is events, not sessions — a service reconnecting inflates it.
- `4769` edges into the DC from non-case sources are routine domain noise
  (CSV only); the interesting Kerberos edges are the re-pointed SPN ones.
- Source-side edges (`TSC-MRU`, `TypedPath`) may carry registry key-write
  timestamps, i.e. *last* use, not each use.
- If a machine lacks `machine_info.json` its IPs won't resolve to it, and
  inbound edges will show the bare IP as an `external` node instead.
