# Custom detection lists (`data/assets/`)

The engine has three detection layers:

1. **Built-in parser logic** — the hardcoded low-FP heuristics inside each
   handler (GTFOBins techniques, PowerShell download cradles, staging-dir cron
   jobs, ratio-guarded web flags, …). Changing these means editing code.
2. **Community rulesets** — SigmaHQ (Linux, web, and Windows process_creation over memory processes), YARA signature-base,
   hayabusa EVTX rules, LOLDrivers. Updated upstream, fetched or
   bundled by `aeng setup`.
3. **Custom lists** — *this document*: analyst-editable files under
   `src/artifact_engine/data/assets/` that the parsers read **at run time**.
   Growing a detection here is editing a text file, no code, no redeploy.

A match from any list is a **lead, not a verdict** — it labels a row the
analyst then confirms in context. Keep every entry low-false-positive: a broad
pattern buries the real hits it sits next to.

## The lists

| File | OS | Consumer parser | Matched against | Where a hit shows |
|---|---|---|---|---|
| `web_suspicious.txt` | web (linux + `weblogs` drop) | `alert_web` (`web_hunt` until v0.7.170) | Decoded path + query as a URI on **served (200)** requests only; User-Agent at any status (a refused probe is not a finding) | `alert_web.csv`, one row per label and source IP, rule `web_suspicious.txt: <label>`, level medium (not `art_web_metrics`' per-IP `attack` ranking, which counts the built-in signatures) |
| `alert_suspicious_tools.txt` | windows + linux | `win_consolehost`, `lin_bash`, `lin_app_history`, `exec_hunt`, `cmd_hunt` | Every command in PowerShell ConsoleHost history / per-user shell history / vim, less and REPL histories (`art_app_history`, file paths too); on Windows also every command line `cmd_hunt` reads (processes, tasks, services, PowerShell 400/800/4103/4104, Sysmon 1) and the FILE NAME of every program an execution artifact recorded (action categories such as `lsass_dump` stay command-line only) | `flag` column of `art_consolehost.csv` / `art_shell_history.csv` / `art_app_history.csv` (several labels can join with `+`); `alert_suspicious_commands.csv`; `alert_suspicious_tools.csv` |
| `rmm_tools.yaml` | windows | `exec_hunt` (catalog in `win_rmm`) | Every execution artifact (Amcache, Prefetch, ShimCache, BAM, UserAssist, PCA, SRUM, services, tasks, LNK, jump lists, live processes): exact exe basename (`files`) or install-path substring (`paths`) | `alert_rmm.csv` with the artifacts that saw it, first/last seen, runs, users, SHA1 |
| `alert_lolbas.yaml` | windows | `exec_hunt` (catalog in `win_lolbas`) | Every execution artifact with a path: a LOLBAS basename sitting in a staging / user-writable dir (relocation = evasion) | `alert_lolbas.csv` |
| `lottunnels/tunnels.yaml` | windows | `exec_hunt`, `alert_remote_access_domains` | Tunnelling tools (ngrok, cloudflared, chisel...) by program name in every execution artifact and by domain in browser history and the DNS cache. Written by `aeng setup` / `update` from LOTTunnels (GPL-3.0) -- not in the repository, don't edit, never commit | `alert_rmm.csv`, `alert_remote_access_domains.csv` |
| `wtfbins.yaml` | windows | `exec_hunt`, `cmd_hunt` | Legitimate programs that behave like an intrusion (WTFBins), by file name: the program a `alert_suspicious_tools` row names, or the program a `alert_suspicious_commands` line starts with or runs in (generated -- `python -m artifact_engine.core.lol_import wtfbins <repo.zip>`, don't edit) | `known_benign` column of `alert_suspicious_tools.csv` / `alert_suspicious_commands.csv`; the severity is unchanged |
| `exfil_lolexfil.yaml` | windows + linux + memory | `cmd_hunt`, `alert_exfil_commands_linux`, `alert_mem_exfil_commands` | Every command line in shell / PowerShell history, live-response process lists and memory images, and on Windows tasks, services, PowerShell and Sysmon events, by LOLExfil's endpoint patterns (generated, regex per pattern -- regenerate with `python -m artifact_engine.core.lol_import exfil <tools.json>`, don't edit) | `alert_exfil_commands.csv`; in memory also `exfil_command` rows in `alert_mem` |
| `loldrivers_hashes.json` | windows | `exec_hunt` (catalog in `win_byovd`) | SHA1 of every driver Amcache saw vs the LOLDrivers set | `alert_byovd.csv` (`malicious` vs merely `vulnerable`) |

## Indicator format (`web_suspicious.txt`, `alert_suspicious_tools.txt`)

Parsed by `handlers/_indicators.py` — one indicator per line, matched as a
**case-insensitive regex**:

```
# comment lines and blanks are ignored
sqlmap                          <- bare line: pattern AND its own label
scanner_ua = nikto|nuclei       <- label = regex (label is the shown category)
rce = /cgi-bin/.*bash    # note <- trailing comment (2+ spaces then "# ") is
                                   stripped; '#' INSIDE a pattern is kept
```

A bad regex is warned about and skipped — it never aborts the parser. The
haystacks are already normalised for you:

- **alert_web**: the request is `\xNN`-resolved, URL-decoded twice and lowercased
  before matching, so `%2e%2e%2f` hits the same rule as `../`.
- **histories**: the raw command line as typed (case-insensitive match).

`rmm_tools.yaml` / `alert_lolbas.yaml` are YAML (name + `files`/`paths`, or a flat
basename list); `loldrivers_hashes.json` maps SHA1 → driver metadata and is
refreshed from loldrivers.io rather than edited by hand.

## What each list is for (and what NOT to put in it)

- **`web_suspicious.txt`** — things that are odd to see answered in an
  access log (a path or query on a served request) or asked at all (a
  User-Agent, any status): scanner User-Agents, webshell filenames, backup leaks, miners, and
  specific CVE fingerprints
  (shellshock, spring4shell, struts OGNL, proxyshell, citrix traversal,
  phpunit/pearcmd/php-cgi RCE, text4shell, JBoss/WebLogic consoles,
  F5/Fortinet/Pulse/Cisco edge RCE, IoT-router paths, cloud-metadata SSRF, …).
  Injection *payloads* (SQLi/XSS/cmdi/LFI…) are the SigmaHQ web rules' job
  (and `handlers/_webrules.py` counts them per IP in `web_metrics.html`), which
  fire on content, not reputation. Don't add
  broad path words (`/(shell|cmd)\.` also matches `shell.png`, `/upload.php`
  is a real endpoint on many sites); anchor to an executable extension or a
  specific tool/CVE path. New CVE fingerprints were FP-tested against a real
  218k-line access-log capture (zero benign hits).
- **`alert_suspicious_tools.txt`** — *named* offensive tooling + high-signal
  anti-forensics idioms in command histories: credential theft
  (mimikatz/secretsdump), Kerberos & AD abuse (rubeus, sharphound), lateral
  tooling (psexec/wmiexec/evil-winrm), C2 frameworks, scanners from a
  compromised box, exfil (rclone/mega), shadow-copy sabotage, AV-killer
  utilities, AMSI bypass, firewall-disable, event-log/history wiping,
  pipe-to-shell payload staging, reverse tunnels (chisel/ngrok/frpc). Each new
  idiom was checked to match its attack form but NOT the benign look-alike
  (`wevtutil cl` yes / `wevtutil qe` no; `ssh -R` yes / `ssh -L` no; `history
  -c` yes / `history` no). Technique-level patterns (reverse shells,
  `-EncodedCommand`, GTFOBins escapes) are built into `win_consolehost` /
  `lin_gtfobins` and fire even with an empty list — don't duplicate them here.
- **`rmm_tools.yaml`** — dual-use remote-access software (curated from
  LOLRMM). A hit means "this remote-access tool touched the box"; the analyst
  checks whether it is the org's authorised one. `files` catches the binary
  anywhere (incl. renamed install dirs); `paths` use a leading `\` and no
  trailing one so `\screenconnect` still matches a suffixed install folder.
  Read first; behind it, **`rmm_lolrmm.yaml`** is the LOLRMM catalog -- every
  tool that yields a file, folder or domain, less any the publication filter
  withholds (counted in its header) -- generated by `python -m artifact_engine.core.lol_import rmm <rmm_tools.json>`
  (v0.7.100) -- don't edit it, regenerate it. The generator keeps it narrow: a
  file name two tools claim, or a generic one (`agent.exe`, Windows's own
  `svchost.exe`), is left out; an install folder is closed (`\level\`) unless
  the catalog says the name continues (`\anydesk-`); shared vendor folders are
  dropped. Of ~295 tools, ~136 carry a file name or folder the execution artifacts can match;
  the rest only carry `domains`, kept for the network side.
- **`alert_lolbas.yaml`** — legit Windows binaries abused when *relocated* into
  Temp/Downloads/ProgramData. In-place abuse-by-argument is covered by the
  LiveResponse LOLBIN command-line check instead.

## Operational notes

- The lists ship with the package -- except `lottunnels/tunnels.yaml`, which `aeng
  setup` / `update` write on your machine and which is never shipped or committed; edits apply to the **installed** copy under
  `src/artifact_engine/data/assets/`.
- **Editing a list re-runs what reads it** (v0.7.160): the next run re-parses,
  in every case, the parsers whose code names that file -- and what depends on
  them -- with no `--force`. The content each one last ran with is kept in
  `.<parser>.assets` beside its marker. Two limits: the IP-origin databases and
  the Tor exit list are not followed (`aeng update` refreshes them; use
  `--force` to apply a refresh to a parsed case), and a case parsed before
  v0.7.160 takes the lists as they are on its first run with it -- a list edited
  before that upgrade still needs `--force` for that case.
- Any handler can adopt an indicator list the same way — `load_indicators()` +
  `match_labels()` from `handlers/_indicators.py` are shared.
