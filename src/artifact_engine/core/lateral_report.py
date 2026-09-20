r"""The lateral-movement page: the legend's wording, and the page itself.

Split out of `lateral.py`, which had grown to 1698 lines of which 600 were a
literal HTML/CSS/JS document. That document is why the whole module carried an
E501 exemption -- and the exemption did not know where the markup stopped, so a
thousand lines of correlation logic went unchecked behind it. Separated, the line
limit applies to the logic again and is waived only over the template, which is
the only place a wrapped line would change what the analyst sees.

Nothing here reads evidence or decides anything. It receives a model that
`lateral._graph_model` already curated and turns it into a page.
"""
import html
import json

# One sentence per category, shown on hover in the HTML legend. The meta-test
# test_every_graph_category_is_explained pins this to what _edge_category can
# actually return, so a new class cannot ship without an explanation.
CAT_DESC = {
    "explicit": "Explicit credentials: an account on this host launched something "
                "AS someone else against the target (Windows 4648, runas/PsExec).",
    "kerberos": "Kerberos ticket requested at the domain controller (4768 TGT, "
                "4769 service ticket) -- recorded on the DC, not on the target.",
    "rdp": "Remote Desktop session (logon type 10, or the RDP client/operational "
           "logs). The interactive path an operator uses by hand.",
    "rdp_mru": "Remote Desktop history from the registry: a host this box connected "
               "to at some point, and the account used. No time of its own.",
    "typed_unc": "A UNC path (\\\\host\\share) typed into Explorer by hand -- "
                 "deliberate share access the client's Security log never records.",
    "ssh": "SSH session or login record from the Linux host (auth.log, wtmp/btmp).",
    "ssh_known_host": "The target appears in a user's known_hosts: this box has SSH'd "
                      "there before. Evidence of a route, not of a session.",
    "runas": "Logon type 9: a process ran with different credentials while keeping "
             "the original session (the classic pass-the-hash shape).",
    "network": "Logon type 3: a plain network logon -- SMB share access, remote "
               "service control, WMI. The bulk of ordinary domain traffic.",
    "other": "A logon that matched none of the above classes; check the event id "
             "and logon type in the detail panel.",
}

# Same idea for the reason vocabulary, which is just as opaque to a reader.
REASON_DESC = {
    "failed_logon": "The attempt did not succeed. On its own this is noise; it "
                    "matters in volume, or paired with a later success.",
    "brute_success": "This source failed repeatedly against this account and then "
                     "SUCCEEDED. The single strongest signal the graph carries.",
    "explicit_creds": "Credentials were supplied explicitly rather than reused from "
                      "the session.",
    "rdp_outbound": "Seen from the SOURCE host we hold -- it survives the "
                    "destination's log rollover, and the destination may not be "
                    "acquired at all.",
    "rdp_public": "Inbound RDP from a globally-routable address. Never hidden by "
                  "the graph's culling, however low its volume.",
    "typed_unc": "A share path typed by hand, so a deliberate act rather than "
                 "something an application did.",
    "untrusted_cert": "The user clicked through a certificate warning to connect.",
    "invalid_user": "The account did not exist -- enumeration rather than a "
                    "mistyped password.",
    "kerberos_service": "A 4769 whose requested service points at a THIRD host: the "
                        "account asked the DC for a ticket to somewhere else, so the "
                        "edge is drawn to the service, not to the DC.",
    "case_to_case": "Both ends are hosts in this case: movement inside the "
                    "acquired estate, not traffic in or out of it.",
    "anonymous_logon": "Logon as ANONYMOUS LOGON / null session.",
    "chain": "This edge is part of a pivot: something arrived at the host and then "
             "left it towards a third one.",
    "chainsaw": "A chainsaw detection rule fired on the underlying event; the rule "
                "name is shown in place of this token.",
}


def _json_island(obj) -> str:
    """JSON for embedding in a <script> block: neutralise a "</script>" breakout
    (event-log usernames are attacker-controllable). "<\\/" is valid inside JSON."""
    return json.dumps(obj).replace("</", "<\\/")


def _count_label(nodes: list, links: list, stats: dict) -> str:
    """Header line. It states what the graph LEFT OUT as well as what it shows: the
    curation is aggressive on purpose, and an analyst reading only the HTML must not
    mistake it for the complete case (lateral_movement.csv always is)."""
    txt = f"{len(nodes)} hosts, {len(links)} edges"
    hidden, brute = stats.get("hidden", 0), stats.get("brute", 0)
    if hidden:
        detail = f" ({brute} brute-force sources)" if brute else ""
        txt += f" · {hidden} peer(s) hidden{detail} — full list in lateral_movement.csv"
    return txt


def render_html(nodes: list, links: list, chains: list, stats: dict) -> str:
    return _HTML.replace("__NODES__", _json_island(nodes)).replace(
        "__LINKS__", _json_island(links)).replace(
        "__CHAINS__", _json_island(chains)).replace(
        "__CATDESC__", _json_island(CAT_DESC)).replace(
        "__REASONDESC__", _json_island(REASON_DESC)).replace(
            "__COUNT__", html.escape(_count_label(nodes, links, stats)))


# Self-contained interactive graph (no external JS/libs, works offline): force-directed
# SVG with filters (user/host search, logon category, and a UTC calendar picking a day,
# a range or several single days plus a half-hour window), per-edge username + date
# labels, and a chronological timeline sidebar. Hover a node for detail;
# click one to focus its neighbourhood. Busy cases start with edges aggregated per
# host pair + category, the layout world scales with the host count (fit to frame).
_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Lateral movement</title>
<style>
 body{margin:0;font:13px system-ui,sans-serif;background:#0f1115;color:#d7dae0}
 #bar,#ctl{padding:6px 12px;background:#161922;border-bottom:1px solid #2a2f3a;display:flex;flex-wrap:wrap;align-items:center;gap:10px}
 #ctl{background:#12151d}
 #bar b{font-size:14px}
 label{cursor:pointer;user-select:none}
 input[type=search]{background:#0f1115;border:1px solid #2a2f3a;color:#d7dae0;padding:3px 7px;border-radius:4px;width:190px}
 .dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px;vertical-align:middle}
 .chip{padding:2px 8px;border-radius:11px;border:1px solid #2a2f3a;cursor:pointer;user-select:none;font-size:12px}
 .chip.off{opacity:.32}
 .chip.rs{color:#8a93a3;font-size:11px}
 .chip.rs.on{border-color:#e0533d;color:#e0533d;font-weight:600}
 #detail{padding:7px 10px;border-bottom:1px solid #2a2f3a;font-size:12px}
 #detail .k{color:#8a93a3}
 #detail .peer{padding:1px 0}
 .tpick{position:relative}
 #tbtn[aria-expanded=true]{border-color:#4f9cf2}
 #tbtn[disabled]{opacity:.45;cursor:default}
 #cal{position:absolute;top:26px;left:0;z-index:6;background:#161922;border:1px solid #2a2f3a;border-radius:6px;
      padding:8px;width:252px;box-shadow:0 8px 24px #0009}
 #cal .mrow{display:flex;align-items:center;justify-content:space-between;gap:6px;margin-bottom:6px}
 #cal .mrow b{font-size:12px}
 #cal .dow,#cal .grid{display:grid;grid-template-columns:repeat(7,1fr);gap:2px}
 #cal .dow span{text-align:center;font-size:10px;color:#586074}
 #cal .day{position:relative;height:30px;border:1px solid transparent;border-radius:4px;background:#1b2130;
           color:#d7dae0;font:inherit;font-size:11px;cursor:pointer;padding:0 0 5px}
 #cal .day.none{background:#141822;color:#454c5c;cursor:default}
 #cal .day.pad{background:none;border:0;cursor:default}
 #cal .day.on{background:#2b4a72;border-color:#4f9cf2}
 #cal .day.pre{border-color:#4f9cf2}
 #cal .day i{position:absolute;left:3px;right:3px;bottom:3px;height:3px;border-radius:2px;background:#4f9cf2;display:block}
 #cal .day.none i{display:none}
 #cal .trow{display:flex;align-items:center;gap:5px;margin-top:7px;font-size:11px;color:#8a93a3}
 #cal select{background:#0f1115;border:1px solid #2a2f3a;color:#d7dae0;border-radius:4px;padding:2px 4px;font:inherit;font-size:11px}
 #cal .hint{margin-top:6px;font-size:10.5px;color:#586074;line-height:1.35}
 button{background:#1b2130;color:#d7dae0;border:1px solid #2a2f3a;border-radius:4px;cursor:pointer;padding:3px 8px}
 #wrap{display:flex;height:calc(100vh - 84px)}
 svg{flex:1;cursor:grab}
 .edge{fill:none}.edge.focus{filter:drop-shadow(0 0 3px #fff)}
 .edge.dim{opacity:.12}.node.dim{opacity:.22}
 .node.sel circle{stroke:#fff;stroke-width:2.5}
 .node circle{stroke:#0f1115;stroke-width:2;cursor:pointer}
 .node text{fill:#e8eaed;font-size:12px;pointer-events:none}
 .elbl{fill:#c7ccd6;font-size:10px;pointer-events:none;paint-order:stroke;stroke:#0f1115;stroke-width:3px;stroke-linejoin:round}
 .dlbl{fill:#8a93a3;font-size:9px;pointer-events:none;paint-order:stroke;stroke:#0f1115;stroke-width:3px;stroke-linejoin:round}
 #side{width:300px;background:#12151d;border-left:1px solid #2a2f3a;overflow:auto}
 #side h3{margin:0;padding:7px 10px;font-size:12px;position:sticky;top:0;background:#12151d;border-bottom:1px solid #2a2f3a}
 .tl{padding:5px 10px;border-bottom:1px solid #1c2030;cursor:pointer;font-size:12px}
 .tl:hover,.tl.sel{background:#1b2130}.tl .t{color:#8a93a3}.tl .r{color:#e0533d;font-size:11px}
 code{color:#9ecbff}
 #tip{position:fixed;background:#000d;border:1px solid #3a4150;padding:6px 8px;border-radius:4px;pointer-events:none;display:none;max-width:360px;z-index:5}
</style></head><body>
<div id="bar"><b>Lateral movement</b> <span id="count">__COUNT__</span>
 <span style="color:#8a93a3">&middot; all times UTC</span>
 <label><input type="checkbox" id="agg"> aggregate</label>
 <label><input type="checkbox" id="lbl" checked> usernames</label>
 <label><input type="checkbox" id="dts"> dates</label>
 <label><input type="checkbox" id="ext"> case-to-case only</label>
 <label><input type="checkbox" id="pub"> public IP only</label>
 <span style="color:#586074">wheel: zoom &middot; drag bg: pan &middot; click node: focus &middot; dblclick: fit</span>
 <span style="margin-left:auto">
  <span class="dot" style="background:#f2c14e"></span>DC
  <span class="dot" style="background:#4f9cf2"></span>host
  <span class="dot" style="background:#56b6c2"></span>linux
  <span class="dot" style="background:#7fb069"></span>server
  <span class="dot" style="background:#e0533d"></span>internal IP
  <span class="dot" style="background:#ff2e88"></span>public IP
 </span></div>
<div id="ctl">
 <input type="search" id="q" placeholder="filter user / host...">
 <span id="cats"></span>
 <span id="stat" title="succeeded vs did not: an independent axis from the mechanism, so &quot;failed Kerberos&quot; is two clicks"></span>
 <span class="tpick"><button id="tbtn" aria-expanded="false" aria-haspopup="dialog"
   title="pick a day, a range (drag or shift-click) or single days (ctrl/cmd-click), then a half-hour window">&#128197; <span id="tlab">all dates</span></button>
  <div id="cal" role="dialog" aria-label="Date and time window (UTC)" hidden>
   <div class="mrow"><button id="cprev" title="previous month">&#9664;</button><b id="cmon"></b><button id="cnext" title="next month">&#9654;</button><button id="call" title="every date in the case">all</button></div>
   <div class="dow"><span>Mo</span><span>Tu</span><span>We</span><span>Th</span><span>Fr</span><span>Sa</span><span>Su</span></div>
   <div class="grid" id="cgrid"></div>
   <div class="trow">from <select id="h0"></select> to <select id="h1"></select> <span id="hnote"></span></div>
   <div class="hint">Click a day &middot; drag or shift-click for a range &middot; ctrl/cmd-click adds a separate day. The bar under a day is the dated edges it holds; undated ones (registry, known_hosts) show whatever you pick.</div>
  </div></span>
 <button id="play">&#9654; play</button>
 <button id="fit">fit</button>
 <button id="rst">reset</button>
 <button id="cpy" title="copy the IPs of the peers currently visible (blocklist / IOCs)">copy IPs</button>
 <button id="csv" title="download the edges currently visible as CSV">export CSV</button>
 <span id="vis" style="color:#8a93a3"></span>
</div>
<div id="ctl"><span class="lblr" style="color:#8a93a3">why flagged &middot; none picked = no filter:</span>
 <span id="reasons"></span></div>
<div id="wrap"><svg id="g"></svg><div id="side">
 <div id="detail" style="display:none"></div>
 <h3 id="ph">Attack paths (<span id="pcount">0</span>)</h3><div id="plist"></div>
 <h3 id="th">Timeline (chronological, UTC)</h3><div id="tlist"></div>
</div></div>
<div id="tip"></div>
<script>
const NODES=__NODES__, LINKS=__LINKS__, CHAINS=__CHAINS__;
const CAT_DESC=__CATDESC__, REASON_DESC=__REASONDESC__;
// Colour now carries the MECHANISM only. Whether it succeeded is the dash, which
// is what a failure was already drawn with -- so nothing new to learn, and an
// edge finally says both things at once.
const CAT_COL={explicit:'#c77dff',rdp:'#f2994a',rdp_mru:'#f29fd8',ssh:'#57b894',runas:'#f2c14e',kerberos:'#4f9cf2',typed_unc:'#4fd6c0',ssh_known_host:'#8bd450',network:'#8a93a3',other:'#6f7787'};
const FAIL_COL='#e0533d';   // the status chip only, so the red still marks failure
const CAT_ORDER=['explicit','rdp','rdp_mru','ssh','runas','kerberos','typed_unc','ssh_known_host','network','other'];
const roleCol={dc:'#f2c14e',case:'#4f9cf2',linux:'#56b6c2',server:'#7fb069',external:'#e0533d',public:'#ff2e88'};
const svg=document.getElementById('g'), tip=document.getElementById('tip');
let W=svg.clientWidth||1200,H=svg.clientHeight||700;   // 0 when loaded hidden -> sane default, viewBox rescales on show
// The layout world grows with the host count, so a big case spreads out instead
// of cramming into one screen; fit() then frames whatever is visible.
const L=Math.max(1100,Math.round(Math.sqrt(NODES.length)*300));
const WLD=L, HLD=Math.round(L*0.72);
let cam={x:0,y:0,w:W,h:H}, fitW=W;
const setVB=()=>svg.setAttribute('viewBox',cam.x+' '+cam.y+' '+cam.w+' '+cam.h);
const roleOf={}; NODES.forEach(n=>roleOf[n.id]=n.role);
const isCase=id=>roleOf[id]==='dc'||roleOf[id]==='case'||roleOf[id]==='linux';   // server/external are off-case
const esc=t=>(t+'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// Every timestamp reaching the graph is UTC, but "2026-07-24 11:40:40" has no zone
// so Date.parse would read it in the VIEWER's local zone -- the same report would
// then show different hours on a UTC+2 analyst's laptop than on the case clock.
// Anchor it to UTC (unless the value already states a zone) and format with getUTC*.
const pt=s=>{if(!s)return null;let t=s.replace(' ','T').replace(/(\.\d{3})\d+/,'$1');
 if(!/(Z|[+-]\d\d:?\d\d)$/.test(t))t+='Z';
 const d=Date.parse(t);return isNaN(d)?null:d;};
const deg={};LINKS.forEach(l=>{deg[l.source]=(deg[l.source]||0)+1;deg[l.target]=(deg[l.target]||0)+1;});
const N={}; NODES.forEach((n,i)=>{n.x=WLD/2+(Math.random()-.5)*WLD*.6;
  n.y=HLD/2+(Math.random()-.5)*HLD*.6;n.vx=0;n.vy=0;
  n.r=(n.role==='dc'?15:10)+Math.min(7,Math.sqrt(deg[n.id]||1)*1.4);N[n.id]=n;});
LINKS.forEach((l,i)=>{l.i=i;l.s=N[l.source];l.t=N[l.target];l.t0=pt(l.first);l.t1=pt(l.last)||l.t0;});
const _grp={};LINKS.forEach(l=>{const k=[l.source,l.target].sort().join('|');(_grp[k]=_grp[k]||[]).push(l);});
Object.keys(_grp).forEach(k=>_grp[k].forEach((l,i)=>{l.pi=i;l.pn=_grp[k].length;}));
const times=LINKS.map(l=>l.t0).filter(x=>x!=null);
const TMIN=times.length?Math.min(...times):0, TMAX=times.length?Math.max(...times):1;
const CATS=CAT_ORDER.filter(c=>LINKS.some(l=>l.cat===c));
const activeCats=new Set(CATS);
const activeSt=new Set(['ok','failed']);   // status is its own axis
const AGG_DEFAULT=LINKS.length>60;   // busy case -> start with one edge per host pair+category
// Reasons are what make an edge worth looking at, so they are pickable. Unlike the
// category chips (all on, click to remove) this is a POSITIVE selection: none
// picked = no filter, and picking some shows only edges carrying ANY of them --
// which is how you actually hunt ("just the chains", "just brute_success").
const REASONS=[...new Set(LINKS.flatMap(l=>l.rs||[]))].sort();
const pickedR=new Set();
let q='',showLbl=true,showDates=false,caseOnly=false,pubOnly=false,focusSet=new Set(),selNode=null,
    playCap=null,drag=null,pan=null,playing=null,moved=0,aggOn=AGG_DEFAULT;
let VLINKS=[],VNODES=[];
const $=id=>document.getElementById(id);
$('agg').checked=aggOn;
$('agg').onchange=e=>{aggOn=e.target.checked;render();};
const catLabel=l=>l.cat+(l.ltype&&l.ltype!==l.cat?'/'+l.ltype:'')+(l.status==='failed'?' (failed)':'');
const _p2=n=>(''+n).padStart(2,'0');
const fmt=ms=>{if(ms==null)return '';const d=new Date(ms);return d.getUTCFullYear()+'-'+_p2(d.getUTCMonth()+1)+'-'+_p2(d.getUTCDate())+' '+_p2(d.getUTCHours())+':'+_p2(d.getUTCMinutes());};
const DEFS='<defs>'+Object.entries(CAT_COL).map(([c,col])=>`<marker id="arr-${c}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="${col}"/></marker>`).join('')+'</defs>';
$('cats').innerHTML=CATS.map(c=>`<span class="chip" data-c="${c}" title="${esc(CAT_DESC[c]||c)}" style="border-color:${CAT_COL[c]}"><span class="dot" style="background:${CAT_COL[c]}"></span>${c}</span>`).join(' ');
$('cats').querySelectorAll('.chip').forEach(el=>el.onclick=()=>{const c=el.dataset.c;
  activeCats.has(c)?(activeCats.delete(c),el.classList.add('off')):(activeCats.add(c),el.classList.remove('off'));applyFilters();});
// Status: its own axis, same negative selection as the categories (both on, click
// to drop one). Combined with a category this answers "failed Kerberos?" directly,
// which the old single class could not express at all.
const ST_DESC={ok:'Succeeded. In volume this is ordinary domain traffic; it matters as the second half of a brute-force, or when the pair itself is unexpected.',
               failed:'Did not succeed. Drawn dashed. On its own it is noise -- it counts when it repeats, or when the same pair later succeeds.'};
$('stat').innerHTML=['ok','failed'].map(s=>{const col=s==='failed'?FAIL_COL:'#8a93a3';
  const n=LINKS.filter(l=>(l.status==='failed')===(s==='failed')).length;
  return `<span class="chip" data-s="${s}" title="${esc(ST_DESC[s])}" style="border-color:${col};color:${col}">${s} <b>${n}</b></span>`;}).join(' ');
$('stat').querySelectorAll('.chip').forEach(el=>el.onclick=()=>{const s=el.dataset.s;
  activeSt.has(s)?(activeSt.delete(s),el.classList.add('off')):(activeSt.add(s),el.classList.remove('off'));applyFilters();});
$('reasons').innerHTML=REASONS.map(r=>
  `<span class="chip rs" data-r="${esc(r)}" title="${esc(REASON_DESC[r]||r)}">${esc(r)} <b>${LINKS.filter(l=>(l.rs||[]).includes(r)).length}</b></span>`).join(' ')
  || '<span style="color:#586074">no reasons on the visible edges</span>';
$('reasons').querySelectorAll('.chip').forEach(el=>el.onclick=()=>{const r=el.dataset.r;
  pickedR.has(r)?pickedR.delete(r):pickedR.add(r);el.classList.toggle('on');applyFilters();});
// ---- Date window: a calendar, not two sliders ------------------------------
// The sliders mapped the whole case onto 1000 notches, so their resolution was
// whatever the case happened to span -- on a 90-day case one notch was two hours,
// and "just the 24th" was a drag-and-squint. Days are what an analyst actually
// has (a ticket names a date), so days are what this picks: one, a dragged range,
// or several separate ones. Everything stays UTC, like every other time on the
// page, and the grid is built from getUTC* so a viewer in another zone sees the
// same days as the case clock.
const DAY=864e5, HALF=18e5;          // one day, half an hour
const dayOf=ms=>Math.floor(ms/DAY)*DAY;
// An edge's span is bounded before it is walked day by day: a FILETIME that never
// got set parses as 1601-01-01, and an edge from there to today is 155,000 days --
// enough keys to blow the argument limit of a Math.max(...spread) and take the
// whole page down with it, a blank report rather than a wrong one.
const MAXSPAN=800;
// Edges per day, counted the way the FILTER counts them (an edge spans first..last
// and shows on every day it touches), so the bar under a day predicts what picking
// it will give you rather than telling a different story.
const DAYC={}, WIDES=[];
LINKS.forEach(l=>{if(l.t0==null)return;
 const from=dayOf(l.t0), to=dayOf(l.t1==null?l.t0:Math.max(l.t0,l.t1));
 // A span past the cap is kept as an INTERVAL rather than walked or trimmed:
 // trimming it made the day's bar promise one edge fewer than picking that day
 // returned, which is the one thing the bar is there to get right.
 if(to-from>MAXSPAN*DAY)WIDES.push([from,to]);
 else for(let d=from;d<=to;d+=DAY)DAYC[d]=(DAYC[d]||0)+1;});
const dayCount=d=>(DAYC[d]||0)+WIDES.reduce((n,w)=>n+(d>=w[0]&&d<=w[1]?1:0),0);
let DAYMAX=1, D0=dayOf(TMIN), D1=dayOf(TMAX);
// The bounds follow the DAYS THAT HOLD EDGES, not the first/last start: an edge
// that began in January and ended in March put March days on the calendar while
// `next month` stopped at January, so those days could be seen and never picked.
Object.keys(DAYC).forEach(k=>{const d=+k;if(DAYC[k]>DAYMAX)DAYMAX=DAYC[k];
 if(d<D0)D0=d;if(d>D1)D1=d;});
WIDES.forEach(w=>{if(w[0]<D0)D0=w[0];if(w[1]>D1)D1=w[1];});
DAYMAX+=WIDES.length;
let SEL=[],            // selected day starts (ms, ascending); empty = the whole case
    H0=0, H1=48,       // half-hour marks: start 0..47, end 1..48 (48 = 24:00)
    calMon=null, anchor=null, dragging=false, dragMoved=false, lastOver=null, preview=null;
const hhLabel=i=>_p2(Math.floor(i/2))+':'+(i%2?'30':'00');
const timeOpts=(el,from,to,sel)=>{let h='';for(let i=from;i<=to;i++)h+=`<option value="${i}"${i===sel?' selected':''}>${i===48?'24:00':hhLabel(i)}</option>`;el.innerHTML=h;};
// Contiguous selected days collapse into one block; the half-hour marks apply to
// the FIRST and LAST day of the whole selection (what a from/to picker means),
// and any day in between is whole.
function windows(){
 if(!SEL.length)return [[TMIN,TMAX]];
 const blocks=[];
 SEL.forEach(d=>{const last=blocks[blocks.length-1];
  if(last&&d===last[1]+DAY)last[1]=d;else blocks.push([d,d]);});
 // A day ends at 23:59:59.999, not at the next midnight: with `<=` on the upper
 // bound an edge starting exactly at 00:00:00 of the following day (a scheduled
 // task, and second-resolution timestamps make the exact hit ordinary) landed in
 // the day before it -- one more edge than the day's own bar had promised.
 const last=blocks.length-1;
 return blocks.map(([a,b],i)=>[a+(i===0?H0*HALF:0),
                               i===last?(H1===48?b+DAY-1:b+H1*HALF):b+DAY-1]);
}
let WINS=windows();
const inWin=l=>l.t0==null||WINS.some(w=>l.t1>=w[0]&&l.t0<=(playCap==null?w[1]:Math.min(w[1],playCap)));
const dLabel=ms=>{const d=new Date(ms);return d.getUTCFullYear()+'-'+_p2(d.getUTCMonth()+1)+'-'+_p2(d.getUTCDate());};
function syncT(){
 WINS=windows();
 let t;
 // Said in syncT rather than once at startup, because the init pass calls this
 // after it and would put "all dates" back on a page that has no date at all.
 if(!times.length){$('tlab').textContent='no dates';$('hnote').textContent='';return;}
 const h0=H0?' '+hhLabel(H0):'', h1=H1===48?'':' '+hhLabel(H1);
 // A time window that the label does not mention is a filter the reader cannot
 // see: with several days picked the old label stopped at the dates, so edges
 // outside 09:00-09:30 were missing with nothing on screen saying why.
 if(!SEL.length)t='all dates';
 else if(SEL.length===1)t=dLabel(SEL[0])+(h0||h1?' '+hhLabel(H0)+'–'+(H1===48?'24:00':hhLabel(H1)):'');
 else{const cont=SEL[SEL.length-1]-SEL[0]===(SEL.length-1)*DAY;
      t=(cont?dLabel(SEL[0])+h0+' → '+dLabel(SEL[SEL.length-1])+h1
             :SEL.length+' days picked'+(h0||h1?', '+hhLabel(H0)+'–'+(H1===48?'24:00':hhLabel(H1))+' at the ends':''))
        +(cont?' ('+SEL.length+'d)':'');}
 $('tlab').textContent=t;
 $('hnote').textContent=SEL.length>1?'(first and last day)':'';
}
function drawCal(){
 const d=new Date(calMon);
 $('cmon').textContent=d.getUTCFullYear()+'-'+_p2(d.getUTCMonth()+1);
 $('cprev').disabled=calMon<=monOf(D0);$('cnext').disabled=calMon>=monOf(D1);
 const first=new Date(calMon), days=new Date(Date.UTC(first.getUTCFullYear(),first.getUTCMonth()+1,0)).getUTCDate();
 const pad=(first.getUTCDay()+6)%7;   // week starts Monday
 let h='';
 for(let i=0;i<pad;i++)h+='<span class="day pad"></span>';
 for(let n=1;n<=days;n++){
  const ms=Date.UTC(first.getUTCFullYear(),first.getUTCMonth(),n), c=dayCount(ms);
  // A day with no edges is not `disabled`: a disabled button swallows mouse events,
  // so dragging a range ACROSS a quiet day stopped following the pointer there. It
  // is dimmed, skipped by the keyboard, and ignored on its own click instead.
  h+=`<button type="button" class="day${c?'':' none'}" data-d="${ms}"${c?' ':' tabindex="-1" aria-disabled="true" '}`
    +`title="${dLabel(ms)}: ${c} dated edge(s)">${n}`
    +(c?`<i style="width:${Math.max(12,Math.round(c/DAYMAX*100))}%"></i>`:'')+'</button>';
 }
 $('cgrid').innerHTML=h;
 // Handlers bound once per month; picking a day only REPAINTS (paint()), because
 // rebuilding the grid under the pointer detaches the node being clicked -- which
 // lost the drag half-way and made the outside-click check close the panel.
 $('cgrid').querySelectorAll('.day:not(.pad)').forEach(el=>{
  const ms=+el.dataset.d;
  el.onmousedown=e=>{if(e.shiftKey||e.ctrlKey||e.metaKey)return;dragging=true;dragMoved=false;anchor=ms;lastOver=ms;};
  // Selection on CLICK, not mousedown, so Enter or Space on a focused day works
  // the same as the mouse -- the calendar is reachable with the keyboard alone.
  el.onclick=e=>{
   if(dragMoved){dragMoved=false;return;}
   if(!dayCount(ms)&&!(e.shiftKey||e.ctrlKey||e.metaKey))return;   // nothing happened that day
   if(e.ctrlKey||e.metaKey){SEL.includes(ms)?SEL=SEL.filter(x=>x!==ms):SEL.push(ms);SEL.sort((a,b)=>a-b);anchor=ms;}
   else if(e.shiftKey&&anchor!=null)pickRange(anchor,ms);
   else {SEL=[ms];anchor=ms;}
   commit();};
 });
 // The drag reads the pointer on the GRID and resolves the cell under it, rather
 // than a mouseenter per cell: the cells are re-painted mid-drag, and an enter
 // that lands on a stale node is a range that stops growing half-way.
 $('cgrid').onmousemove=e=>{
  if(!dragging)return;
  const el=e.target.closest('.day:not(.pad)');
  if(!el)return;
  const ms=+el.dataset.d;
  if(ms===lastOver)return;
  lastOver=ms;dragMoved=true;preview=[anchor,ms];pickRange(anchor,ms);commit();
 };
 paint();
}
function paint(){
 const lo=preview?Math.min(preview[0],preview[1]):0, hi=preview?Math.max(preview[0],preview[1]):-1;
 $('cgrid').querySelectorAll('.day:not(.pad)').forEach(el=>{const ms=+el.dataset.d;
  const on=SEL.includes(ms);
  el.classList.toggle('on',on);el.classList.toggle('pre',ms>=lo&&ms<=hi);
  el.setAttribute('aria-pressed',String(on));});
}
const monOf=ms=>{const d=new Date(ms);return Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),1);};
function pickRange(a,b){SEL=[];for(let d=Math.min(a,b);d<=Math.max(a,b);d+=DAY)SEL.push(d);}
function commit(){stopPlay();syncT();syncH();paint();applyFilters();}
document.addEventListener('mouseup',()=>{if(dragging){dragging=false;preview=null;paint();}});
function openCal(open){
 $('cal').hidden=!open;$('tbtn').setAttribute('aria-expanded',String(open));
 if(open){calMon=SEL.length?monOf(SEL[0]):busiestMonth();drawCal();}
}
// Opens on the month holding the most edges: on a case whose evidence spans a year
// the interesting fortnight is not the one the calendar happens to start on.
function busiestMonth(){
 const per={};Object.entries(DAYC).forEach(([d,c])=>{const t=new Date(+d);
  const k=Date.UTC(t.getUTCFullYear(),t.getUTCMonth(),1);per[k]=(per[k]||0)+c;});
 const best=Object.entries(per).sort((a,b)=>b[1]-a[1])[0];
 return best?+best[0]:Date.UTC(new Date(D1).getUTCFullYear(),new Date(D1).getUTCMonth(),1);
}
timeOpts($('h0'),0,47,0);timeOpts($('h1'),1,48,48);
// Both ends are inert while the whole case is selected -- there are no ends to
// apply them to -- so they are disabled rather than left showing a window that
// is not in force.
const syncH=()=>{$('h0').disabled=$('h1').disabled=!SEL.length;};
$('h0').onchange=()=>{H0=+$('h0').value;if(H1<=H0){H1=Math.min(48,H0+1);$('h1').value=H1;}commit();};
$('h1').onchange=()=>{H1=+$('h1').value;if(H0>=H1){H0=Math.max(0,H1-1);$('h0').value=H0;}commit();};
$('tbtn').onclick=()=>openCal($('cal').hidden);
$('cprev').onclick=()=>{const d=new Date(calMon);calMon=Date.UTC(d.getUTCFullYear(),d.getUTCMonth()-1,1);drawCal();};
$('cnext').onclick=()=>{const d=new Date(calMon);calMon=Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+1,1);drawCal();};
$('call').onclick=()=>{SEL=[];H0=0;H1=48;$('h0').value=0;$('h1').value=48;commit();};
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('cal').hidden)openCal(false);});
document.addEventListener('mousedown',e=>{if(!$('cal').hidden&&!e.target.closest('.tpick'))openCal(false);},true);
if(!times.length)$('tbtn').disabled=true;
$('q').oninput=e=>{q=e.target.value;applyFilters();};
$('lbl').onchange=e=>{showLbl=e.target.checked;render();};
$('dts').onchange=e=>{showDates=e.target.checked;render();};
$('ext').onchange=e=>{caseOnly=e.target.checked;applyFilters();};
$('pub').onchange=e=>{pubOnly=e.target.checked;applyFilters();};
// Stopping drops the cap as well as the timer: a cap left behind is an upper
// bound nothing on the page shows -- the label, the calendar and `reset` all say
// the window is wider -- and it would silently shorten `export CSV` too.
function stopPlay(){playCap=null;if(playing){clearInterval(playing);playing=null;$('play').innerHTML='&#9654; play';}}
// Playback fills in the window you picked, half an hour at a time -- and skips
// the gaps between separate days, so picking the 24th and the 2nd plays those two
// days back to back instead of eleven empty ones. A long window steps in bigger
// jumps (600 frames is the whole show) rather than running for an hour.
$('play').onclick=()=>{
 if(playing){stopPlay();return;}
 const wins=windows(), total=wins.reduce((a,w)=>a+(w[1]-w[0]),0)||1;
 const step=Math.max(HALF,total/600);
 let wi=0, cur=wins[0][0];
 playCap=cur;applyFilters();
 $('play').innerHTML='&#9632; stop';
 playing=setInterval(()=>{
  cur+=step;
  if(cur>wins[wi][1]){if(wi+1<wins.length){wi++;cur=wins[wi][0];}else{stopPlay();applyFilters();return;}}
  playCap=cur;applyFilters();
 },50);
};
$('rst').onclick=()=>{stopPlay();q='';$('q').value='';activeCats.clear();CATS.forEach(c=>activeCats.add(c));
  activeSt.clear();['ok','failed'].forEach(s=>activeSt.add(s));$('stat').querySelectorAll('.chip').forEach(el=>el.classList.remove('off'));
  $('cats').querySelectorAll('.chip').forEach(el=>el.classList.remove('off'));
  SEL=[];H0=0;H1=48;$('h0').value=0;$('h1').value=48;openCal(false);caseOnly=false;$('ext').checked=false;
  pubOnly=false;$('pub').checked=false;
  pickedR.clear();$('reasons').querySelectorAll('.chip').forEach(el=>el.classList.remove('on'));
  focusSet=new Set();selNode=null;aggOn=AGG_DEFAULT;$('agg').checked=aggOn;syncT();syncH();applyFilters();fit();};
$('fit').onclick=()=>fit();
// Getting the current view OUT of the page: whatever you have narrowed down to is
// usually the next thing you paste into a ticket or a blocklist, and re-deriving it
// from the full CSV by hand is the tax the web report never charged.
function _drop(name,text,type){const a=document.createElement('a');
 a.href=URL.createObjectURL(new Blob([text],{type}));a.download=name;a.click();
 URL.revokeObjectURL(a.href);}
$('cpy').onclick=()=>{
 const ips=VNODES.filter(n=>n.role==='public'||n.role==='external').map(n=>n.id);
 const t=ips.join('\n');
 (navigator.clipboard&&t?navigator.clipboard.writeText(t):Promise.reject())
  .then(()=>{$('cpy').textContent=`copied ${ips.length}`;
   setTimeout(()=>$('cpy').textContent='copy IPs',1500);})
  .catch(()=>window.prompt('Peer IPs currently visible (Ctrl+C):',t));};
$('csv').onclick=()=>{
 const q=v=>{v=String(v==null?'':v);return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
 const head='src,dst,user,logon_type,event_id,status,count,first_seen_utc,last_seen_utc,reasons';
 const body=VLINKS.map(l=>[l.source,l.target,l.user,l.ltype,l.eid,l.status,l.count,
                           l.first,l.last,(l.reasons||[]).join('+')].map(q).join(','));
 _drop('lateral_movement_filtered.csv',head+'\n'+body.join('\n'),'text/csv');};
function showDetail(){
 // A node's whole story in one place. The hover tooltip vanishes the moment you
 // move the mouse, which makes it useless for reading -- this stays put.
 const d=$('detail');
 if(!selNode){d.style.display='none';return;}
 const inc=VLINKS.filter(l=>l.source===selNode||l.target===selNode);
 const users=[...new Set(inc.map(l=>l.user).filter(Boolean))];
 const rs=[...new Set(inc.flatMap(l=>l.rs||[]))].sort();
 const ts=inc.map(l=>l.t0).filter(x=>x!=null);
 // key keeps the direction as a plain marker, NOT an HTML entity: the peer name is
 // attacker-controllable and goes through esc(), which would print "&rarr;" literally
 const peers=new Map();
 for(const l of inc){const o=l.source===selNode?l.target:l.source;
  const k=(l.source===selNode?'>':'<')+o;peers.set(k,(peers.get(k)||0)+l.count);}
 d.style.display='block';
 d.innerHTML=`<div><b>${esc(selNode)}</b> <span class="k">(${esc(roleOf[selNode]||'')})</span>`
  +`<span class="k" style="float:right;cursor:pointer" id="dx">&#10005;</span></div>`
  +`<div class="k">${inc.length} edge(s) &middot; ${peers.size} peer(s)`
  +(ts.length?` &middot; ${esc(fmt(Math.min(...ts)))} &rarr; ${esc(fmt(Math.max(...ts)))} UTC`:'')+`</div>`
  +(rs.length?`<div style="color:#e0533d;margin-top:3px">${esc(rs.join(' + '))}</div>`:'')
  +(users.length?`<div class="k" style="margin-top:3px">accounts: ${esc(users.slice(0,6).join(', '))}`
    +(users.length>6?` +${users.length-6}`:'')+`</div>`:'')
  +`<div style="margin-top:4px">`+[...peers.entries()].sort((a,b)=>b[1]-a[1]).slice(0,12)
    .map(([k,n])=>`<div class="peer">${k[0]==='>'?'&rarr;':'&larr;'} `
      +`<code>${esc(k.slice(1))}</code> <span class="k">x${n}</span></div>`).join('')
  +(peers.size>12?`<div class="k">+${peers.size-12} more</div>`:'')+`</div>`;
 $('dx').onclick=()=>{selNode=null;focusSet=new Set();clearSel();buildTimeline();render();};
}
function applyFilters(){
 const qs=q.trim().toLowerCase();
 VLINKS=LINKS.filter(l=>activeCats.has(l.cat)&&activeSt.has(l.status==='failed'?'failed':'ok')
   && (!qs||(l.user&&l.user.toLowerCase().includes(qs))||l.source.toLowerCase().includes(qs)||l.target.toLowerCase().includes(qs))
   && inWin(l)
   && (!caseOnly||(isCase(l.source)&&isCase(l.target)))
   && (!pubOnly||roleOf[l.source]==='public'||roleOf[l.target]==='public')
   && (!pickedR.size||(l.rs||[]).some(r=>pickedR.has(r))));
 const shown=new Set();VLINKS.forEach(l=>{shown.add(l.source);shown.add(l.target);});
 VNODES=NODES.filter(n=>shown.has(n.id));NODES.forEach(n=>n.vis=shown.has(n.id));
 $('vis').textContent=VLINKS.length+' / '+LINKS.length+' edges, '+VNODES.length+' hosts';
 buildTimeline();render();wake();
}
if(CHAINS.length){
 $('pcount').textContent=CHAINS.length;
 $('plist').innerHTML=CHAINS.map((c,i)=>
  `<div class="tl" data-p="${i}">`+
  `<div class="t">${esc(c.t0)} &rarr; ${esc(c.t1)}</div>`+
  `<div><code>${esc(c.path[0])}</code> &rarr; <b><code>${esc(c.path[1])}</code></b> &rarr; <code>${esc(c.path[2])}</code></div>`+
  `<div>${esc(c.user||'')} <span class="r">pivot chain</span></div></div>`).join('');
 $('plist').querySelectorAll('.tl').forEach(el=>el.onclick=()=>{
  const c=CHAINS[+el.dataset.p];focusSet=new Set(c.links);selNode=null;
  buildTimeline();          // a chain spans 3 hosts -> drop any single-host scope
  $('plist').querySelectorAll('.tl').forEach(x=>x.classList.toggle('sel',x===el));
  $('tlist').querySelectorAll('.tl').forEach(x=>x.classList.remove('sel'));render();});
}else{$('ph').style.display='none';}
function buildTimeline(){
 // With a node selected the sidebar narrows to ITS events. On a real case the
 // full list is hundreds of rows, and once you click a host the question is
 // always "what happened on THIS host", never "what happened anywhere".
 const only=selNode?VLINKS.filter(l=>l.source===selNode||l.target===selNode):VLINKS;
 $('th').textContent=selNode
   ? `Timeline — ${selNode} (${only.length}, UTC)`
   : 'Timeline (chronological, UTC)';
 const rows=only.slice().sort((a,b)=>(a.t0||0)-(b.t0||0));
 $('tlist').innerHTML=rows.map(l=>
  `<div class="tl${focusSet.has(l.i)?' sel':''}" data-i="${l.i}">`+
  `<div class="t">${esc(l.first?l.first.slice(0,19):'-')}</div>`+
  `<div><span class="dot" style="background:${CAT_COL[l.cat]}"></span><code>${esc(l.source)}</code> &rarr; <code>${esc(l.target)}</code></div>`+
  `<div>${esc(l.user||'')} <span style="color:#8a93a3">${esc(catLabel(l))}${l.count>1?' x'+l.count:''}</span>`+
  `${l.reasons.length?` <span class="r">${esc(l.reasons.join('+'))}</span>`:''}</div></div>`).join('')
  || '<div style="padding:8px 10px;color:#8a93a3">no edges match</div>';
 // a row click focuses that ONE edge but keeps any host scope: you clicked inside
 // this host's timeline, so having the list jump back to the whole case would undo
 // the very thing you were reading
 $('tlist').querySelectorAll('.tl').forEach(el=>el.onclick=()=>{focusSet=new Set([+el.dataset.i]);
   $('tlist').querySelectorAll('.tl').forEach(x=>x.classList.toggle('sel',+x.dataset.i===+el.dataset.i));
   $('plist').querySelectorAll('.tl').forEach(x=>x.classList.remove('sel'));render();});
 showDetail();   // the panel follows the same scope/filters as the sidebar
}
const REP=4000*Math.pow(L/1100,1.6), LD=Math.min(300,150*L/1100);
// The simulation sleeps once the layout settles (a big case redrawn at 25fps
// forever would pin a core with the report just sitting open) and wakes on
// anything that moves nodes again: drag, filters, reset.
let sim=null, calm=0;
function wake(){calm=0;if(!sim)sim=setInterval(step,40);}
function step(){
 let ke=0;for(const n of VNODES)ke+=Math.abs(n.vx)+Math.abs(n.vy);
 if(ke<0.06*(VNODES.length||1)&&!drag){if(++calm>25&&sim){clearInterval(sim);sim=null;}}
 else calm=0;
 for(const a of VNODES){for(const b of VNODES){if(a===b)continue;
   let dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy)||1;let f=REP/(d*d);a.vx+=dx/d*f;a.vy+=dy/d*f;}}
 for(const l of VLINKS){if(!l.s||!l.t)continue;let dx=l.t.x-l.s.x,dy=l.t.y-l.s.y,d=Math.hypot(dx,dy)||1;
   let f=(d-LD)*0.008;l.s.vx+=dx/d*f;l.s.vy+=dy/d*f;l.t.vx-=dx/d*f;l.t.vy-=dy/d*f;}
 for(const n of VNODES){if(n===drag)continue;n.vx+=(WLD/2-n.x)*0.0012;n.vy+=(HLD/2-n.y)*0.0012;
   n.x+=n.vx*=0.85;n.y+=n.vy*=0.85;n.x=Math.max(40,Math.min(WLD-40,n.x));n.y=Math.max(46,Math.min(HLD-40,n.y));}
 // hard anti-overlap pass so labels stay separable however dense the case is
 for(let i=0;i<VNODES.length;i++)for(let j=i+1;j<VNODES.length;j++){
   const a=VNODES[i],b=VNODES[j];let dx=a.x-b.x,dy=a.y-b.y,d=Math.hypot(dx,dy)||1;
   const m=a.r+b.r+18-d;if(m>0){const px=dx/d*m/2,py=dy/d*m/2;a.x+=px;a.y+=py;b.x-=px;b.y-=py;}}
 render();
}
function fit(){
 if(!VNODES.length){cam={x:0,y:0,w:W,h:H};fitW=W;setVB();render();return;}
 let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
 for(const n of VNODES){x0=Math.min(x0,n.x);y0=Math.min(y0,n.y);x1=Math.max(x1,n.x);y1=Math.max(y1,n.y);}
 x0-=90;y0-=90;x1+=210;y1+=90;                       // extra right pad: labels stick out that side
 let w=x1-x0,h=y1-y0;const ar=W/H;
 if(w/h<ar){const nw=h*ar;x0-=(nw-w)/2;w=nw;}else{const nh=w/ar;y0-=(nh-h)/2;h=nh;}
 cam={x:x0,y:y0,w:w,h:h};fitW=w;setVB();render();
}
function egeom(l){
 const x1=l.s.x,y1=l.s.y,x2=l.t.x,y2=l.t.y;
 const dx=x2-x1,dy=y2-y1,d=Math.hypot(dx,dy)||1;
 // fan parallel edges apart; the canonical sign keeps A->B and B->A on opposite
 // sides instead of mirroring onto each other
 const sgn=l.source<l.target?1:-1;
 const off=(l.pi-(l.pn-1)/2)*26*sgn;
 const cx=(x1+x2)/2-dy/d*off, cy=(y1+y2)/2+dx/d*off;
 // stop short of the target circle so the arrowhead stays visible
 const r=(N[l.target]?N[l.target].r:12)+5;
 const ex=x2-cx,ey=y2-cy,ed=Math.hypot(ex,ey)||1;
 const tx=x2-ex/ed*r, ty=y2-ey/ed*r;
 return {d:'M'+x1.toFixed(1)+' '+y1.toFixed(1)+'Q'+cx.toFixed(1)+' '+cy.toFixed(1)+' '+tx.toFixed(1)+' '+ty.toFixed(1),
         lx:(x1+2*cx+tx)/4, ly:(y1+2*cy+ty)/4};
}
function drawList(){
 // Aggregated view: one edge per (src, dst, category) with the per-visit LINKS
 // folded in (ids kept so chain/timeline focus still lights the right curve).
 if(!aggOn)return VLINKS;
 const g={};
 for(const l of VLINKS){if(!l.s||!l.t)continue;const k=l.source+'>'+l.target+'|'+l.cat+'|'+l.status;
  let a=g[k];
  // `status` travels with the group or the dash is lost: the draw loop reads it
  // from HERE, not from the raw link, and the key above already keeps the two apart
  if(!a)a=g[k]={source:l.source,target:l.target,cat:l.cat,status:l.status,s:l.s,t:l.t,count:0,
                users:new Set(),ids:[],first:null,last:null};
  a.count+=l.count;if(l.user)a.users.add(l.user);a.ids.push(l.i);
  if(l.first&&(!a.first||l.first<a.first))a.first=l.first;
  if(l.last&&(!a.last||l.last>a.last))a.last=l.last;}
 const out=Object.values(g);
 const grp={};out.forEach(a=>{const k=[a.source,a.target].sort().join('|');(grp[k]=grp[k]||[]).push(a);});
 Object.keys(grp).forEach(k=>grp[k].forEach((a,i)=>{a.pi=i;a.pn=grp[k].length;}));
 return out;
}
function render(){
 const dl=drawList();
 // Constant on-screen sizing: text and stroke widths scale with the camera, so
 // zooming changes what fits, not how fat things are.
 const pxf=Math.max(.35,Math.min(2.6,cam.w/W));
 const focused=l=>l.ids?l.ids.some(i=>focusSet.has(i)):focusSet.has(l.i);
 const hasFocus=focusSet.size>0;
 const fnodes=new Set();if(selNode)fnodes.add(selNode);
 if(hasFocus)for(const l of dl)if(focused(l)){fnodes.add(l.source);fnodes.add(l.target);}
 let s=DEFS;
 for(const l of dl){if(!l.s||!l.t)continue;const g=l._g=egeom(l);
   const w=(1.4+Math.min(l.count,6)*0.35)*pxf, foc=focused(l), dim=hasFocus&&!foc;
   const dash=l.status==='failed'?` stroke-dasharray="${5*pxf} ${3*pxf}"`:'';
   s+=`<path class="edge${foc?' focus':''}${dim?' dim':''}" d="${g.d}" stroke="${CAT_COL[l.cat]}" stroke-width="${(foc?w+1.6*pxf:w).toFixed(2)}" marker-end="url(#arr-${l.cat})"${dash}/>`;}
 if(showLbl||showDates){
  // Label only what can breathe: every focused edge, otherwise only when the
  // current viewport holds few enough edges (zooming in thins the crowd).
  const inView=g=>g.lx>=cam.x&&g.lx<=cam.x+cam.w&&g.ly>=cam.y&&g.ly<=cam.y+cam.h;
  let cand=dl.filter(l=>l.s&&l.t&&inView(l._g));
  if(hasFocus)cand=cand.filter(focused);
  else if(cand.length>80)cand=[];
  for(const l of cand){const g=l._g;
   const u=l.users?(l.users.size===1?l.users.values().next().value:l.users.size+' users'):l.user;
   const lbl=u?u+(l.count>1?' x'+l.count:''):'';
   if(showLbl&&lbl)s+=`<text class="elbl" font-size="${(10*pxf).toFixed(1)}" stroke-width="${(3*pxf).toFixed(1)}" x="${g.lx}" y="${g.ly-2*pxf}" text-anchor="middle">${esc(lbl)}</text>`;
   if(showDates&&l.first)s+=`<text class="dlbl" font-size="${(9*pxf).toFixed(1)}" stroke-width="${(3*pxf).toFixed(1)}" x="${g.lx}" y="${g.ly+(showLbl&&lbl?10*pxf:8*pxf)}" text-anchor="middle">${esc(l.first.slice(5,16))}</text>`;}}
 for(const n of VNODES){const dim=hasFocus&&!fnodes.has(n.id);
   s+=`<g class="node${dim?' dim':''}${n.id===selNode?' sel':''}" data-id="${esc(n.id)}"><circle cx="${n.x}" cy="${n.y}" r="${n.r}" fill="${roleCol[n.role]}"/>`+
      `<text font-size="${(12*pxf).toFixed(1)}" x="${n.x+n.r+3}" y="${n.y+4}">${esc(n.id)}</text></g>`;}
 svg.innerHTML=s;
}
const toWorld=e=>{const r=svg.getBoundingClientRect();
 return {x:cam.x+(e.clientX-r.left)/r.width*cam.w, y:cam.y+(e.clientY-r.top)/r.height*cam.h};};
const clearSel=()=>{$('plist').querySelectorAll('.tl').forEach(x=>x.classList.remove('sel'));
 $('tlist').querySelectorAll('.tl').forEach(x=>x.classList.remove('sel'));};
svg.addEventListener('mousedown',e=>{const g=e.target.closest('.node');moved=0;
 if(g){drag=N[g.dataset.id];wake();}
 else{pan={x:e.clientX,y:e.clientY,cx:cam.x,cy:cam.y};svg.style.cursor='grabbing';}});
window.addEventListener('mouseup',()=>{
 // a press that never travelled is a click: node -> focus its neighbourhood,
 // background -> clear the focus (drag/pan handled in mousemove)
 if(moved<5){
  // selecting/clearing a node re-scopes the sidebar too, so buildTimeline() must
  // run here -- this path never goes through applyFilters()
  if(drag){const id=drag.id;
   if(selNode===id){selNode=null;focusSet=new Set();}
   else{selNode=id;focusSet=new Set(LINKS.filter(l=>l.source===id||l.target===id).map(l=>l.i));}
   clearSel();buildTimeline();render();}
  else if(pan){selNode=null;focusSet=new Set();clearSel();buildTimeline();render();}}
 drag=null;pan=null;svg.style.cursor='grab';});
let _raf=0; const sched=()=>{if(!_raf)_raf=requestAnimationFrame(()=>{_raf=0;render();});};
svg.addEventListener('wheel',e=>{e.preventDefault();
 const p=toWorld(e), f=e.deltaY>0?1.15:1/1.15;
 const nw=Math.min(Math.max(cam.w*f,W/6),WLD*1.6), nh=nw*(cam.h/cam.w);
 cam.x=p.x-(p.x-cam.x)*nw/cam.w; cam.y=p.y-(p.y-cam.y)*nh/cam.h;
 cam.w=nw; cam.h=nh; setVB(); sched();},{passive:false});
svg.addEventListener('dblclick',()=>fit());
window.addEventListener('mousemove',e=>{
 moved+=Math.abs(e.movementX||0)+Math.abs(e.movementY||0);
 if(drag&&moved>=5){const p=toWorld(e);drag.x=p.x;drag.y=p.y;drag.vx=drag.vy=0;}
 else if(pan){const r=svg.getBoundingClientRect();
  cam.x=pan.cx-(e.clientX-pan.x)/r.width*cam.w;cam.y=pan.cy-(e.clientY-pan.y)/r.height*cam.h;setVB();}
 const g=e.target.closest&&e.target.closest('.node');
 if(g){const id=g.dataset.id;const inc=VLINKS.filter(l=>l.source===id||l.target===id).sort((a,b)=>(a.t0||0)-(b.t0||0));
   tip.style.display='block';tip.style.left=(e.clientX+12)+'px';tip.style.top=(e.clientY+12)+'px';
   tip.innerHTML='<b>'+esc(id)+'</b> <span style="color:#8a93a3">('+esc(roleOf[id])+')</span><br>'+inc.map(l=>
     (l.source===id?'&rarr; ':'&larr; ')+esc(l.source===id?l.target:l.source)+' : '+esc(l.user||'')+
     ' <span style="color:#8a93a3">'+esc(catLabel(l))+(l.count>1?' x'+l.count:'')+'</span>'+
     (l.first?' <span style="color:#8a93a3">'+esc(l.first.slice(0,19))+'</span>':'')+
     (l.reasons.length?' <span style="color:#e0533d">['+esc(l.reasons.join('+'))+']</span>':'')).join('<br>');
 } else tip.style.display='none';
});
window.addEventListener('resize',()=>{W=svg.clientWidth||W;H=svg.clientHeight||H;fit();});
setVB();syncT();syncH();applyFilters();
for(let i=0;i<300;i++)step();
fit();
wake();
</script></body></html>
"""
