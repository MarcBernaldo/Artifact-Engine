"""`docs/atlas.html`: the map of every parser, generated from the manifests.

The overview of what this tool reads and what it produces was written by hand
once. It was true on the day it was written and started ageing with the next
parser, and nothing in the repository would have noticed. So it is an OUTPUT of
the tool rather than a document about it: every figure, every row and every
category on the page comes from `data/parsers` and `data/profiles`, and
`tests/test_atlas.py` regenerates it and compares -- a parser added without
regenerating turns CI red, and one landing with no `source:`/`alert:` fails a
test of its own.

Two things are deliberately NOT on the page:

- **No version stamp and no date.** Every commit in this repository carries a
  version bump, so a stamp would mean regenerating this file on every commit and
  a red CI on every one that forgot. The page cannot be stale anyway -- that is
  what the comparison test is for -- and a "generated on" line would only invite
  the reader to wonder whether it still holds.
- **No per-file output list.** 23 of the 113 manifests declare `outputs`; the
  rest is known only to the handler that writes it, and a column that is right
  for a fifth of the rows is worse than no column. What the page names instead
  is the FOLDER each table lands in, which is derived from the category, and the
  parser id, which is what the table is named after.

Self-contained by the same rule the two existing reports follow: no external
request, no library, no font that has to be fetched. It holds no case data --
every string on it comes from the repository.

Regenerate with `python -m artifact_engine.core.atlas`.
"""
from __future__ import annotations

import html
from pathlib import Path

from artifact_engine.config import DATA_DIR
from artifact_engine.core.scheduler import _CATEGORY_DIR
from artifact_engine.models import ParserManifest, ProfileManifest
from artifact_engine.registry import load_parsers, load_profiles

# Where the generated copy lives, relative to the repository root.
PAGE = Path("docs") / "atlas.html"

ALERT_LABEL = {"detect": "Detection", "flag": "Flags rows", "context": "Context"}
ALERT_CLASS = {"detect": "det", "flag": "flag", "context": "ctx"}

# A manifest's category is a lowercase key; this is the word a reader sees. The
# FOLDER beside it comes from `scheduler._CATEGORY_DIR`, so the page names the
# directory the tables are actually written to.
CATEGORY_LABEL = {
    "filesystem": "Filesystem",
    "execution": "Execution",
    "eventlogs": "Event logs",
    "registry": "Registry",
    "shellbags": "Folder access",
    "systeminfo": "System",
    "shell": "Shell",
    "browser": "Browser",
    "persistence": "Persistence",
    "search": "Search",
    "network": "Network",
    "processes": "Processes",
    "detections": "Detections",
    "web": "Web",
    "liveresponse": "Live response",
}

# Two binaries whose file name is not what anybody calls the tool.
TOOL_LABEL = {
    "chainsaw_x86_64-pc-windows-msvc": "Chainsaw",
    "DeepBlue": "DeepBlueCLI",
}


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


def _folder(category: str) -> str:
    """Where this category's tables land, as the run writes them."""
    if category == "liveresponse":
        return "JSONs/"
    return f"CSVs/{_CATEGORY_DIR.get(category, category or 'Other')}/"


def _engine(p: ParserManifest) -> str:
    if p.handler:
        return "Python"
    stem = Path(p.tool.binary).stem if p.tool else ""
    return TOOL_LABEL.get(stem, stem)


def rows(parsers: list[ParserManifest]) -> list[dict]:
    """One dict per parser, in the order the page shows them: by display name, so
    a reader looking for an artifact finds it without knowing its id."""
    return [
        {
            "id": p.id,
            "name": p.display_name,
            "os": p.os,
            "category": p.category,
            "folder": _folder(p.category),
            "source": p.source,
            "what": p.description,
            "engine": _engine(p),
            "alert": p.alert,
        }
        for p in sorted(parsers, key=lambda p: p.display_name.lower())
    ]


# --------------------------------------------------------------------------- #
# Prose: the parts of the page no manifest knows
# --------------------------------------------------------------------------- #
LEDE = (
    "Modular DFIR triage: it takes Windows and Linux acquisitions, verifies them, "
    "extracts them, detects each machine, runs the parsers that apply and leaves a "
    "database, a spreadsheet and a report per machine. It runs on Windows; the "
    "evidence can be from Windows or from Linux."
)

PHASES = [
    {"n": "phase 0", "h": "Integrity", "p": (
        "SHA256 of every original that has arrived, into <code>traces.txt</code>, "
        "before anything else is touched. Append-only; what was extracted is not an "
        "original.")},
    {"n": "phase 1", "h": "Extraction", "p": (
        "Nested zip/tar/7z in parallel. Never re-extracts destructively; an "
        "acquisition that did not come out whole stays <code>partial</code> in its "
        "marker and moves the exit code.")},
    {"n": "phase 2", "h": "Detection", "p": (
        "The profiles recognise each machine (KAPE, UAC, Velociraptor, loose "
        "folders), its volumes and its VSS snapshots.")},
    {"n": "phase 3", "h": "Parsing", "p": (
        "Every parser in one pool ordered by <code>depends_on</code>; one failing "
        "does not stop the run, and what an earlier run parsed comes back as "
        "<code>cached</code>.")},
    {"n": "phase 4", "h": "Consolidation", "p": (
        "<code>&lt;machine&gt;.db</code>, <code>.xlsx</code> and "
        "<code>report.txt</code> with log coverage and findings, plus the case's "
        "<code>run-summary</code>.")},
    {"n": "phase 5", "h": "Lateral movement", "p": (
        "Logon correlation across machines: <code>lateral_movement.csv</code> and an "
        "interactive offline graph with pivot chains.")},
]

# The profile that has no manifest: `core/detector.py` builds it when a Velociraptor
# collection arrives without a KAPE tree around it, so it cannot be read off
# `data/profiles` like the other five. Inserted third, beside the two acquisitions.
LIVERESPONSE = {
    "id": "windows_liveresponse", "os": "windows",
    "title": "Velociraptor LiveResponse",
    "text": (
        "Volatile state. Joined to its host when it arrives inside a KAPE "
        "acquisition; on its own it is registered as a machine of its own with a "
        "<code>-LR</code> suffix. Built by the detector, not by a profile manifest."),
}

PROFILE_TITLE = {
    "windows_kape": "KAPE / CyLR",
    "linux_uac": "UAC",
    "evtx": "Loose <code>evtx[-label]</code> folder",
    "weblogs": "Loose <code>weblogs[-label]</code> folder",
    "fortigate": "Loose <code>fortigate[-label]</code> folder",
}
PROFILE_ORDER = ["windows_kape", "linux_uac", "evtx", "weblogs", "fortigate"]

LEGEND = [
    {"c": "det", "h": "Detection", "p": (
        "The whole table is findings: rules (Sigma, YARA, GTFOBins) or threat lists "
        "(LOLDrivers, LOLRMM, LOLBAS, ransomware).")},
    {"c": "flag", "h": "Flags rows", "p": (
        "A complete inventory with a <code>suspicious</code> (or <code>flag</code>) "
        "column set to <code>yes</code> on what matters. Those rows reach the "
        "Findings section of the report and <code>findings.csv</code>.")},
    {"c": "ctx", "h": "Context", "p": (
        "Evidence with no verdict: timelines, channel dumps, inventories. Many feed "
        "another parser or the lateral-movement graph.")},
]

RESULTS = [
    [
        {"t": "&lt;machine&gt;/CSVs/&lt;Category&gt;/", "d": (
            "One CSV per parser output, grouped by DFIR category. Velociraptor stays "
            "in <code>JSONs/</code>.")},
        {"t": "&lt;machine&gt;.db &middot; .xlsx", "d": (
            "Everything consolidated into SQLite and Excel (a sheet past Excel's row "
            "limit lives only in the .db).")},
        {"t": "report.txt &middot; findings.csv", "d": (
            "Log coverage first, then the findings ordered by how selective each flag "
            "is, with <code>table + rowid</code> to reach the row.")},
        {"t": "web_metrics.html", "d": (
            "Self-contained web panel: KPIs, timeline, map and an IP table with "
            "crossed filters.")},
    ],
    [
        {"t": "traces.txt", "d": (
            "Chain of custody: the SHA256 of every original, in dated deliveries.")},
        {"t": "run-summary.txt &middot; .json", "d": (
            "The case's verdict in one field: ok / cached / skipped / errors per "
            "machine, acquisitions that did not extract whole and ones that have not "
            "finished arriving. Exit code <code>2</code> whenever that field is not "
            "<code>complete</code>.")},
        {"t": "lateral_movement.csv &middot; .html", "d": (
            "Every logon relation and the offline interactive graph (filters, "
            "playback, attack paths).")},
        {"t": "stale-outputs.txt", "d": (
            "Old outputs that no longer correspond to anything. The engine never "
            "deletes anything in a case; it lists them.")},
    ],
]

FOOTER = (
    "Generated from the manifests in <code>data/parsers</code> and "
    "<code>data/profiles</code> by <code>core/atlas.py</code>. A test in this "
    "repository regenerates this page and compares it, so it cannot describe a "
    "different set of parsers from the one that ships. It holds no case data."
)

_CSS = """\
:root{
  --ground:#F3F5F4; --surface:#FFFFFF; --sunk:#E8ECEA; --ink:#17201D; --muted:#5A6762;
  --line:#D5DCD9; --accent:#23577F; --accent-soft:#DCE8F2;
  --det:#A8291F; --det-soft:#F8E1DE; --flag:#8A5A00; --flag-soft:#F7EACB;
  --ctx:#58656F; --ctx-soft:#E6EAEC; --win:#1F5F99; --lin:#5B6E1E;
  --sans:system-ui,-apple-system,"Segoe UI",sans-serif;
  --cond:"Segoe UI Semibold","Arial Narrow",system-ui,sans-serif;
  --mono:ui-monospace,"Cascadia Mono",Consolas,monospace;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --ground:#101614; --surface:#171F1C; --sunk:#1E2824; --ink:#E2E9E5; --muted:#98A6A0;
    --line:#2C3833; --accent:#8DB8DE; --accent-soft:#1D3144;
    --det:#F08A80; --det-soft:#3A1E1B; --flag:#E2B44F; --flag-soft:#352A12;
    --ctx:#A5B1B8; --ctx-soft:#232C30; --win:#8DB8DE; --lin:#B5C878;
  }
}
:root[data-theme="dark"]{
  --ground:#101614; --surface:#171F1C; --sunk:#1E2824; --ink:#E2E9E5; --muted:#98A6A0;
  --line:#2C3833; --accent:#8DB8DE; --accent-soft:#1D3144;
  --det:#F08A80; --det-soft:#3A1E1B; --flag:#E2B44F; --flag-soft:#352A12;
  --ctx:#A5B1B8; --ctx-soft:#232C30; --win:#8DB8DE; --lin:#B5C878;
}
*{box-sizing:border-box}
body{background:var(--ground);color:var(--ink);font-family:var(--sans);font-size:15px;
     line-height:1.55;margin:0}
.wrap{max-width:1240px;margin:0 auto;padding-inline:clamp(16px,4vw,40px);
      padding-block:36px 72px;display:grid;gap:56px}
h1,h2,h3{font-family:var(--cond);text-wrap:balance;margin:0;line-height:1.15}
h1{font-size:clamp(34px,5vw,52px);font-weight:700;letter-spacing:-.01em}
h2{font-size:26px;font-weight:600}
h3{font-size:17px;font-weight:600}
p{margin:0;max-width:68ch}
code,.mono{font-family:var(--mono);font-size:.86em}
.eyebrow{font-family:var(--mono);font-size:12px;letter-spacing:.08em;
         text-transform:uppercase;color:var(--muted)}
.lede{color:var(--muted);font-size:17px}
section{display:grid;gap:20px}
.head{display:grid;gap:14px}
.head-top{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:baseline}
.figs{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
      border-top:2px solid var(--ink);border-bottom:1px solid var(--line)}
.fig{padding:14px 16px 14px 0;display:grid;gap:2px}
.fig b{font-family:var(--cond);font-size:34px;font-weight:600;
       font-variant-numeric:tabular-nums;line-height:1}
.fig span{color:var(--muted);font-size:13px}
.pipe{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));border:1px solid var(--line);
      background:var(--surface);border-radius:6px;overflow:hidden}
.ph{padding:14px 14px 16px;border-right:1px solid var(--line);display:grid;gap:6px;
    align-content:start}
.ph:last-child{border-right:0}
.ph .n{font-family:var(--mono);font-size:12px;color:var(--accent)}
.ph p{font-size:13px;color:var(--muted)}
@media (max-width:900px){.pipe{grid-template-columns:repeat(2,minmax(0,1fr))}
                         .ph{border-bottom:1px solid var(--line)}}
@media (max-width:460px){.pipe{grid-template-columns:1fr}.ph{border-right:0}}
.inputs{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}
.inp{background:var(--surface);border:1px solid var(--line);border-radius:6px;
     padding:14px 16px;display:grid;gap:6px;align-content:start}
.inp .tag{justify-self:start}
.inp p{font-size:13.5px;color:var(--muted)}
.tag{font-family:var(--mono);font-size:11.5px;padding:1px 7px;border-radius:3px;
     white-space:nowrap;border:1px solid currentColor}
.tag.win{color:var(--win)} .tag.lin{color:var(--lin)} .tag.any{color:var(--muted)}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:500;
      padding:2px 9px 2px 7px;border-radius:999px;white-space:nowrap}
.pill::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}
.pill.det{color:var(--det);background:var(--det-soft)}
.pill.flag{color:var(--flag);background:var(--flag-soft)}
.pill.ctx{color:var(--ctx);background:var(--ctx-soft)}
.legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
.leg{display:grid;gap:6px;padding:12px 0;border-top:1px solid var(--line)}
.leg p{font-size:13.5px;color:var(--muted)}
.controls{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center;position:sticky;
          top:0;z-index:2;background:var(--ground);padding-block:10px;
          border-bottom:1px solid var(--line)}
.search{flex:1 1 240px;min-width:0}
.search input{width:100%;font:inherit;color:var(--ink);background:var(--surface);
              border:1px solid var(--line);border-radius:5px;padding:8px 11px}
.search input:focus-visible,.seg button:focus-visible,select:focus-visible{
  outline:2px solid var(--accent);outline-offset:1px}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:5px;overflow:hidden;
     background:var(--surface)}
.seg button{font:inherit;font-size:13px;color:var(--muted);background:none;border:0;
            border-right:1px solid var(--line);padding:6px 11px;cursor:pointer}
.seg button:last-child{border-right:0}
.seg button[aria-pressed="true"]{background:var(--accent-soft);color:var(--ink);
                                 font-weight:500}
select{font:inherit;font-size:13px;color:var(--ink);background:var(--surface);
       border:1px solid var(--line);border-radius:5px;padding:6px 8px;max-width:100%}
.count{font-family:var(--mono);font-size:12.5px;color:var(--muted);
       font-variant-numeric:tabular-nums}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:6px;
           background:var(--surface)}
table{border-collapse:collapse;width:100%;min-width:1000px}
th,td{text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid var(--line)}
th{font-family:var(--mono);font-size:11.5px;font-weight:500;letter-spacing:.06em;
   text-transform:uppercase;color:var(--muted);background:var(--sunk);position:sticky;top:0}
tbody tr:last-child td{border-bottom:0}
td.art{width:20%} td.art b{display:block;font-weight:600}
td.art code{color:var(--muted);font-size:12px}
td.cat{width:13%;font-size:12.5px;color:var(--muted)}
td.cat .folder{display:block;font-family:var(--mono);font-size:11.5px;
               overflow-wrap:anywhere}
td.src{width:20%;font-size:13.5px}
td.what{font-size:13.5px}
td.eng{width:9%;font-size:13px;color:var(--muted)}
.tagrow{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.empty{padding:28px;text-align:center;color:var(--muted)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:28px}
dl{margin:0;display:grid;gap:10px}
dt{font-family:var(--mono);font-size:13px;font-weight:500}
dd{margin:2px 0 0;color:var(--muted);font-size:13.5px}
footer{color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);
       padding-top:16px}
"""

_JS = """\
const q = document.getElementById('q'), tb = document.getElementById('rows'),
      empty = document.getElementById('empty'), count = document.getElementById('count'),
      fcat = document.getElementById('fcat');
let fos = '', fal = '';
function seg(id, set) {
  const g = document.getElementById(id);
  g.addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b) return;
    [...g.children].forEach(x => x.setAttribute('aria-pressed', String(x === b)));
    set(b.dataset.v);
    apply();
  });
}
seg('fos', v => fos = v);
seg('fal', v => fal = v);
function apply() {
  const needle = q.value.trim().toLowerCase(), cat = fcat.value;
  let shown = 0;
  for (const tr of tb.children) {
    const hit = (!fos || tr.dataset.os === fos) && (!fal || tr.dataset.alert === fal)
             && (!cat || tr.dataset.cat === cat)
             && (!needle || tr.dataset.hay.includes(needle));
    tr.hidden = !hit;
    if (hit) shown++;
  }
  count.textContent = shown + ' of ' + tb.children.length;
  empty.hidden = shown > 0;
}
q.addEventListener('input', apply);
fcat.addEventListener('change', apply);
apply();
"""


def _figs(rs: list[dict]) -> list[tuple[int, str]]:
    return [
        (len(rs), "artifacts"),
        (sum(1 for r in rs if r["os"] == "windows"), "Windows"),
        (sum(1 for r in rs if r["os"] == "linux"), "Linux"),
        (sum(1 for r in rs if r["alert"] == "detect"), "detection tables"),
        (sum(1 for r in rs if r["alert"] == "flag"), "flagged inventories"),
        (sum(1 for r in rs if r["engine"] != "Python"), "via an external tool"),
    ]


def _row_html(r: dict) -> str:
    os_class = {"windows": "win", "linux": "lin"}.get(r["os"], "any")
    os_label = {"windows": "Windows", "linux": "Linux"}.get(r["os"], "Any")
    hay = " ".join((r["id"], r["name"], r["source"], r["what"], r["category"],
                    r["folder"], r["engine"])).lower()
    pill = ALERT_CLASS[r["alert"]]
    return (
        f'<tr data-os="{_esc(r["os"])}" data-alert="{pill}"'
        f' data-cat="{_esc(r["category"])}" data-hay="{_esc(hay)}">'
        f'<td class="art"><b>{_esc(r["name"])}</b><code>{_esc(r["id"])}</code>'
        f'<div class="tagrow"><span class="tag {os_class}">{os_label}</span>'
        f'<span class="pill {pill}">{ALERT_LABEL[r["alert"]]}</span></div></td>'
        f'<td class="cat">{_esc(CATEGORY_LABEL.get(r["category"], r["category"]))}'
        f'<span class="folder">{_esc(r["folder"])}</span></td>'
        f'<td class="src">{_esc(r["source"])}</td>'
        f'<td class="what">{_esc(r["what"])}</td>'
        f'<td class="eng">{_esc(r["engine"])}</td></tr>'
    )


def _input_cards(profiles: list[ProfileManifest]) -> list[dict]:
    known = {p.id: p for p in profiles}
    cards = [{"id": pid, "os": known[pid].os,
              "title": PROFILE_TITLE.get(pid, pid),
              "text": _esc(known[pid].description)}
             for pid in PROFILE_ORDER if pid in known]
    # A profile added without a title here still appears, under its own id.
    cards += [{"id": pid, "os": p.os, "title": PROFILE_TITLE.get(pid, pid),
               "text": _esc(p.description)}
              for pid, p in sorted(known.items()) if pid not in PROFILE_ORDER]
    cards.insert(2, LIVERESPONSE)
    return cards


def render(parsers: list[ParserManifest], profiles: list[ProfileManifest]) -> str:
    """The whole page, as a string. Deterministic: the same manifests render the
    same bytes, which is what makes the comparison test possible."""
    rs = rows(parsers)
    o: list[str] = []
    a = o.append

    a("<!DOCTYPE html>")
    a('<html lang="en">')
    a("<head>")
    a('<meta charset="utf-8">')
    a('<meta name="viewport" content="width=device-width,initial-scale=1">')
    a("<title>Artifact Engine Atlas</title>")
    a(f"<style>\n{_CSS}</style>")
    a("</head>")
    a("<body>")
    a('<div class="wrap">')

    a('<header class="head">')
    a('<div class="head-top"><span class="eyebrow">Map of the tool</span></div>')
    a("<h1>Artifact Engine</h1>")
    a(f'<p class="lede">{LEDE}</p>')
    a('<div class="figs">')
    for n, what in _figs(rs):
        a(f'<div class="fig"><b>{n}</b><span>{what}</span></div>')
    a("</div>")
    a("</header>")

    a("<section>")
    a('<div class="head"><span class="eyebrow">One run</span>'
      "<h2>Six phases, in this order</h2></div>")
    a('<div class="pipe">')
    for ph in PHASES:
        a(f'<div class="ph"><span class="n">{ph["n"]}</span><h3>{ph["h"]}</h3>'
          f'<p>{ph["p"]}</p></div>')
    a("</div>")
    a("</section>")

    a("<section>")
    a('<div class="head"><span class="eyebrow">What comes in</span>'
      "<h2>Acquisitions it recognises</h2></div>")
    a('<div class="inputs">')
    for card in _input_cards(profiles):
        cls = {"windows": "win", "linux": "lin"}.get(card["os"], "any")
        a(f'<div class="inp"><span class="tag {cls}">{_esc(card["id"])}</span>'
          f'<h3>{card["title"]}</h3><p>{card["text"]}</p></div>')
    a("</div>")
    a("</section>")

    a('<section id="catalogue">')
    a('<div class="head"><span class="eyebrow">What comes out</span>'
      f"<h2>The {len(rs)} artifacts</h2>"
      "<p>One row per parser: where it reads from in the acquisition, what it gets, "
      "which folder its tables land in and whether it produces alerts. A table is "
      "named after the parser id; a parser driven by an external tool can write "
      "several.</p></div>")
    a('<div class="legend">')
    for leg in LEGEND:
        a(f'<div class="leg"><span class="pill {leg["c"]}">{leg["h"]}</span>'
          f'<p>{leg["p"]}</p></div>')
    a("</div>")
    a('<div class="controls" role="search">')
    a('<label class="search" for="q"><input id="q" type="search" '
      'placeholder="Search: amcache, rdp, /var/log, persistence..." '
      'autocomplete="off"></label>')
    a('<div class="seg" role="group" aria-label="System" id="fos">'
      '<button type="button" data-v="" aria-pressed="true">All</button>'
      '<button type="button" data-v="windows" aria-pressed="false">Windows</button>'
      '<button type="button" data-v="linux" aria-pressed="false">Linux</button></div>')
    a('<div class="seg" role="group" aria-label="Alerts" id="fal">'
      '<button type="button" data-v="" aria-pressed="true">All</button>'
      '<button type="button" data-v="det" aria-pressed="false">Detection</button>'
      '<button type="button" data-v="flag" aria-pressed="false">Flags rows</button>'
      '<button type="button" data-v="ctx" aria-pressed="false">Context</button></div>')
    cats = sorted({r["category"] for r in rs},
                  key=lambda c: CATEGORY_LABEL.get(c, c).lower())
    opts = "".join(f'<option value="{_esc(c)}">{_esc(CATEGORY_LABEL.get(c, c))}</option>'
                   for c in cats)
    a('<select id="fcat" aria-label="Category">'
      f'<option value="">All categories</option>{opts}</select>')
    a('<span class="count" id="count"></span>')
    a("</div>")
    a('<div class="tablewrap">')
    a("<table><thead><tr><th>Artifact</th><th>Category</th><th>Reads from</th>"
      "<th>What it gets</th><th>Engine</th></tr></thead>")
    a('<tbody id="rows">')
    for r in rs:
        a(_row_html(r))
    a("</tbody></table>")
    a('<div class="empty" id="empty" hidden>No artifact matches those filters.</div>')
    a("</div>")
    a("</section>")

    a("<section>")
    a('<div class="head"><span class="eyebrow">Results</span>'
      "<h2>What is left in the case</h2></div>")
    a('<div class="cols">')
    for column in RESULTS:
        a("<dl>")
        for item in column:
            a(f'<div><dt>{item["t"]}</dt><dd>{item["d"]}</dd></div>')
        a("</dl>")
    a("</div>")
    a("</section>")

    a(f"<footer>{FOOTER}</footer>")
    a("</div>")
    a(f"<script>\n{_JS}</script>")
    a("</body>")
    a("</html>")
    return "\n".join(o) + "\n"


def build() -> str:
    """The page, rendered from the BUNDLED manifests only.

    Not from `Config.all_parser_dirs`: that includes `./parsers`, so the page the
    committed copy is compared against would depend on the directory the test ran
    in and on whatever the analyst added of their own.
    """
    return render(load_parsers([DATA_DIR / "parsers"]),
                  load_profiles([DATA_DIR / "profiles"]))


def write(repo_root: Path) -> Path:
    path = repo_root / PAGE
    path.write_text(build(), encoding="utf-8")
    return path


if __name__ == "__main__":
    # src/artifact_engine/core/atlas.py -> the repository root
    print(f"written: {write(Path(__file__).resolve().parents[3])}")
