# Custom detection lists (`data/assets/`)

The engine has three detection layers:

1. **Built-in parser logic** — the hardcoded low-FP heuristics inside each
   handler (GTFOBins techniques, PowerShell download cradles, staging-dir cron
   jobs, ratio-guarded web flags, …). Changing these means editing code.
2. **Community rulesets** — SigmaHQ (Linux + web), YARA signature-base,
   chainsaw/hayabusa EVTX rules, LOLDrivers. Updated upstream, fetched or
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
| `web_suspicious.txt` | web (linux + `weblogs` drop) | `huntweb` | Every request: decoded path + query + User-Agent, **any status** (a 404'd probe still counts) | `huntweb.csv`, label as category; feeds the IP's `attack` ranking |
| `suspicious_tools.txt` | windows + linux | `win_consolehost`, `lin_bash` | Every command in PowerShell ConsoleHost history / per-user shell history | `flag` column of `consolehost.csv` / `bash.csv` (several labels can join with `+`) |
| `rmm_tools.yaml` | windows | `win_rmm` | Amcache file entries: exact exe basename (`files`) or install-path substring (`paths`) | `rmm.csv` with SHA1 + first-seen from Amcache |
| `lolbas.yaml` | windows | `win_lolbas` | Amcache entries: a LOLBAS basename sitting in a staging / user-writable dir (relocation = evasion) | `lolbas.csv` |
| `loldrivers_hashes.json` | windows | `win_byovd` | SHA1 of every driver Amcache saw vs the LOLDrivers set | `byovd.csv` (`malicious` vs merely `vulnerable`) |

## Indicator format (`web_suspicious.txt`, `suspicious_tools.txt`)

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

- **huntweb**: the request is `\xNN`-resolved, URL-decoded twice and lowercased
  before matching, so `%2e%2e%2f` hits the same rule as `../`.
- **histories**: the raw command line as typed (case-insensitive match).

`rmm_tools.yaml` / `lolbas.yaml` are YAML (name + `files`/`paths`, or a flat
basename list); `loldrivers_hashes.json` maps SHA1 → driver metadata and is
refreshed from loldrivers.io rather than edited by hand.

## What each list is for (and what NOT to put in it)

- **`web_suspicious.txt`** — "things that are odd to see in an access log at
  all": scanner User-Agents, webshell filenames, exposed secrets/VCS paths,
  admin surfaces, backup leaks, miners, and specific CVE fingerprints
  (shellshock, spring4shell, struts OGNL, proxyshell, citrix traversal,
  phpunit/pearcmd/php-cgi RCE, text4shell, JBoss/WebLogic consoles,
  F5/Fortinet/Pulse/Cisco edge RCE, IoT-router paths, cloud-metadata SSRF, …).
  Injection *payloads* (SQLi/XSS/cmdi/LFI…) belong to the built-in rules in
  `handlers/_webrules.py`, which fire on content, not reputation. Don't add
  broad path words (`/(shell|cmd)\.` also matches `shell.png`, `/upload.php`
  is a real endpoint on many sites); anchor to an executable extension or a
  specific tool/CVE path. New CVE fingerprints were FP-tested against a real
  218k-line access-log capture (zero benign hits).
- **`suspicious_tools.txt`** — *named* offensive tooling + high-signal
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
- **`lolbas.yaml`** — legit Windows binaries abused when *relocated* into
  Temp/Downloads/ProgramData. In-place abuse-by-argument is covered by the
  LiveResponse LOLBIN command-line check instead.

## Operational notes

- The lists ship with the package; edits apply to the **installed** copy under
  `src/artifact_engine/data/assets/`.
- **Cache caveat**: a parser's `.done` fingerprint covers its manifest and
  handler code, not the asset lists. After editing a list, re-run with
  `--force` (or delete the machine's `.<parser>.done` marker) for the change
  to reach an already-parsed case.
- Any handler can adopt an indicator list the same way — `load_indicators()` +
  `match_labels()` from `handlers/_indicators.py` are shared.
