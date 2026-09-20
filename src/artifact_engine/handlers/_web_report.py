"""Interactive HTML report for `web_metrics` -- one self-contained file.

`render()` embeds the aggregated data as JSON plus a compact world map
(assets/world_map.json: Natural Earth 110m, public domain, projected to
per-country SVG paths) into a single dark-theme page with NO external
requests -- it opens on any air-gapped analysis box.

Cross-filtering: one shared state (search ip/asn, path/query search, status
and method chips, flag/origin chips, country click on the map, day click on
the timeline) drives EVERY panel -- KPIs, timeline, map, table and the
404/auth side lists recompute from the same filtered IP set. Clicking an IP
opens a detail panel with its daily sparkline, captured payloads and auth
failures.

This is a helper of lin_web_metrics, and editing it re-runs that parser on its
own: since 0.7.0 the .done fingerprint hashes the handler's whole first-party
import closure, which reaches this module. It did once hash the handler file
alone -- that is what the `--force` this note used to demand was for -- and the
note outlived the behaviour by six minor versions, telling the analyst to pay for
a full re-parse to pick up a change that invalidates one parser by itself.
Pinned by test_the_web_report_is_inside_its_handlers_fingerprint.
"""

from __future__ import annotations

import json
from pathlib import Path


def render(dest: Path, machine: str, generated: str, days: list[str],
           ip_rows: list[list], p404_rows: list[list], auth_rows: list[list],
           assets: Path, globals_: dict | None = None) -> None:
    world = "{}"
    wm = assets / "world_map.json"
    if wm.is_file():
        try:
            world = wm.read_text(encoding="utf-8")
        except OSError:
            world = "{}"
    data = {
        "machine": machine, "generated": generated, "days": days,
        "ips": ip_rows, "p404": p404_rows[:400], "auth": auth_rows,
        **(globals_ or {"methods": [], "paths": [], "uas": [], "queries": []}),
    }
    payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    html = (_TEMPLATE
            .replace("__DATA__", payload.replace("</", "<\\/"))
            .replace("__WORLD__", world.replace("</", "<\\/")))
    dest.write_text(html, encoding="utf-8")


# Row indexes of DATA.ips (mirrors the web_ip_stats.csv columns + extras).
# 0 ip, 1 country, 2 origin, 3 asn, 4 requests, 5 s2xx, 6 s3xx, 7 s401,
# 8 s403, 9 s404, 10 s4xx, 11 s5xx, 12 mb, 13 paths, 14 odd_methods,
# 15 attack_hits, 16 first, 17 last, 18 flags, 19 {dayIdx: n},
# 20 [[cat, uri]...] samples, 21 [[path, n]...] own top-404,
# 22 {method: n}, 23 [[path, n]...] own top paths, 24 [[ua, n]...] own UAs,
# 25 [[query, n]...] own queries
_TEMPLATE = r"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>web_metrics</title>
<style>
:root{--bg:#14161a;--panel:#1b1f24;--line:#2b3037;--txt:#e2e5e9;--mut:#828a94;
--red:#e05252;--org:#e0913a;--yel:#d4b13d;--pur:#a06ee0;--blu:#4d8fe0;--grn:#43a06c}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--txt);font:13px/1.45 system-ui,Segoe UI,sans-serif;padding:12px}
h1{font-size:15px;font-weight:700}
.sub{color:var(--mut);font-size:11px;margin-bottom:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px}
.lbl{font-size:10px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;margin-bottom:5px}
.grid{display:grid;gap:8px;margin-bottom:8px}
.kpis{grid-template-columns:repeat(5,1fr)}
.kpi b{font-size:20px;font-weight:650}
.row2{grid-template-columns:3fr 2fr}
.rowT{grid-template-columns:3fr 2fr}
.chip{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 10px;
 font-size:11px;color:var(--mut);margin:0 4px 4px 0;cursor:pointer;user-select:none}
.chip.on{border-color:var(--red);color:var(--red);font-weight:600}
.chip.on.o{border-color:var(--blu);color:var(--blu)}
.chip.on.m{border-color:var(--pur);color:var(--pur)}
.chip.on.s{border-color:var(--grn);color:var(--grn)}
button{background:var(--panel);border:1px solid var(--line);border-radius:6px;color:var(--txt);
 padding:4px 12px;font-size:11.5px;cursor:pointer}
button:hover{border-color:var(--mut)}
#reset.hot{border-color:var(--red);color:var(--red);font-weight:600}
.fil{cursor:pointer;border-radius:4px;padding:0 4px}
.fil:hover{background:rgba(255,255,255,.05)}
.fil.fon{outline:1px solid var(--blu);color:var(--blu)}
.trunc{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
input[type=text]{background:var(--bg);border:1px solid var(--line);border-radius:6px;
 color:var(--txt);padding:4px 10px;font-size:12px;width:230px;outline:none}
table{border-collapse:collapse;width:100%;font-size:11.5px}
th{text-align:left;color:var(--mut);font-weight:600;padding:4px 7px;border-bottom:1px solid var(--line);
 font-size:10.5px;cursor:pointer;white-space:nowrap;user-select:none}
td{padding:3px 7px;border-bottom:1px solid var(--line);white-space:nowrap}
tr.ipr{cursor:pointer}
tr.ipr:hover{background:rgba(255,255,255,.04)}
tr.sel{background:rgba(224,82,82,.10)}
.tag{font-size:10px;border-radius:4px;padding:1px 6px;font-weight:600;margin-right:3px}
.t-attack{background:rgba(224,82,82,.16);color:var(--red)}
.t-scan{background:rgba(224,145,58,.16);color:var(--org)}
.t-auth-fail{background:rgba(212,177,61,.16);color:var(--yel)}
.t-odd-method{background:rgba(160,110,224,.16);color:var(--pur)}
.bar{display:inline-flex;height:8px;width:80px;border-radius:2px;overflow:hidden;vertical-align:middle;background:#000}
.bar span{height:100%}
#tl{display:flex;align-items:flex-end;gap:1px;height:60px;cursor:pointer}
#tl div{flex:1;min-width:2px;background:var(--mut);opacity:.4}
#tl div.hot{background:var(--red);opacity:1}
#tl div.day-on{outline:2px solid var(--blu)}
.tpick{position:relative;font-size:10.5px;color:var(--mut)}
#dbtn{background:var(--panel);border:1px solid var(--line);color:var(--txt);border-radius:6px;
 padding:3px 8px;font:inherit;font-size:11px;cursor:pointer}
#dbtn[aria-expanded=true]{border-color:var(--blu)}
#dbtn[disabled]{opacity:.45;cursor:default}
#cal{position:absolute;top:24px;left:0;z-index:9;background:var(--panel);border:1px solid var(--line);
 border-radius:8px;padding:8px;width:236px;box-shadow:0 10px 26px #000a}
#cal .mrow{display:flex;align-items:center;justify-content:space-between;gap:6px;margin-bottom:6px}
#cal .mrow b{font-size:11px;color:var(--txt)}
#cal .mrow button{background:none;border:1px solid var(--line);color:var(--txt);border-radius:5px;
 padding:1px 6px;font:inherit;font-size:11px;cursor:pointer}
#cal .dow,#cal .grid{display:grid;grid-template-columns:repeat(7,1fr);gap:2px}
#cal .dow span{text-align:center;font-size:9.5px;color:var(--mut)}
#cal .day{position:relative;height:28px;border:1px solid transparent;border-radius:5px;
 background:#232830;color:var(--txt);font:inherit;font-size:11px;cursor:pointer;padding:0 0 5px}
#cal .day.none{background:#191d22;color:#4a525c;cursor:default}
#cal .day.pad{background:none;border:0;cursor:default}
#cal .day.on{background:#22456e;border-color:var(--blu)}
#cal .day.pre{border-color:var(--blu)}
#cal .day i{position:absolute;left:3px;right:3px;bottom:3px;height:3px;border-radius:2px;background:var(--blu)}
#cal .day.none i{display:none}
#cal .hint{margin-top:6px;font-size:9.5px;color:var(--mut);line-height:1.35}
svg text{font-family:inherit}
#map path{fill:#232830;stroke:#12141a;stroke-width:.6;cursor:pointer}
#map path.lit{cursor:pointer}
#map path.cc-on{stroke:var(--blu);stroke-width:1.6}
#tip{position:fixed;background:#000;color:#fff;border:1px solid var(--line);border-radius:6px;
 padding:5px 9px;font-size:11px;pointer-events:none;display:none;z-index:9}
#detail{position:sticky;top:8px;max-height:92vh;overflow:auto}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:10.5px;word-break:break-all;white-space:normal}
.mini{font-size:11px;line-height:1.8}
.mini b{float:right}
a.reset{color:var(--blu);font-size:11px;cursor:pointer;margin-left:8px}
.count{color:var(--mut);font-size:11px;margin-left:8px}
</style></head><body>
<h1>web_metrics — triaje de access logs</h1>
<div class="sub" id="sub"></div>

<div class="grid kpis">
 <div class="card kpi"><div class="lbl">Peticiones</div><b id="k_req"></b></div>
 <div class="card kpi"><div class="lbl">IPs origen</div><b id="k_ips"></b></div>
 <div class="card kpi"><div class="lbl">Flaggeadas</div><b id="k_flag" style="color:var(--org)"></b></div>
 <div class="card kpi"><div class="lbl">IPs con payloads</div><b id="k_atk" style="color:var(--red)"></b></div>
 <div class="card kpi"><div class="lbl">MB servidos</div><b id="k_mb"></b></div>
</div>

<div class="grid row2">
 <div class="card" style="align-self:start">
  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
   <div class="lbl" style="margin-bottom:0">Timeline diaria — rojo: IPs flaggeadas · clic = un día</div>
   <span class="tpick"><button id="dbtn" aria-expanded="false" aria-haspopup="dialog"
     title="elige un día, un rango (arrastra o may&uacute;s+clic) o días sueltos (ctrl/cmd+clic)">&#128197; <span id="dlab">todas las fechas</span></button>
    <div id="cal" role="dialog" aria-label="Rango de fechas" hidden>
     <div class="mrow"><button id="cprev" title="mes anterior">&#9664;</button><b id="cmon"></b><button id="cnext" title="mes siguiente">&#9654;</button><button id="call" title="todo el periodo">todas</button></div>
     <div class="dow"><span>L</span><span>M</span><span>X</span><span>J</span><span>V</span><span>S</span><span>D</span></div>
     <div class="grid" id="cgrid"></div>
     <div class="hint">Clic = un día &middot; arrastra o may&uacute;s+clic = rango &middot; ctrl/cmd+clic añade un día suelto. La barra de cada día son sus peticiones.</div>
    </div></span>
   <button id="dplay" title="reproduce los días elegidos uno a uno">&#9654;</button>
  </div>
  <div id="tl"></div><div id="tlx" style="display:flex;justify-content:space-between;font-size:9.5px;color:var(--mut)"></div></div>
 <div class="card"><div class="lbl">404 recon — rutas</div><div class="mini" id="l404"></div></div>
</div>

<div class="grid" style="grid-template-columns:5fr 2fr">
 <div class="card">
  <div style="display:flex;align-items:center;gap:8px">
   <div class="lbl" style="margin-bottom:0">Origen por país · clic = filtrar ·</div>
   <span class="chip on" id="mm_vol">volumen</span><span class="chip" id="mm_flag">flags</span>
   <span class="lbl" style="margin-bottom:0" id="mm_note"></span>
  </div>
  <div style="display:flex;gap:8px;align-items:flex-start">
   <svg id="map" viewBox="0 0 1000 430" style="width:78%"></svg>
   <div class="mini" id="l_cc" style="width:22%"></div>
  </div></div>
 <div class="card"><div class="lbl">401/403 — ip · ruta</div><div class="mini" id="lauth"></div></div>
</div>

<div class="grid" style="grid-template-columns:5fr 2fr 5fr 4fr">
 <div class="card"><div class="lbl">Top rutas pedidas</div><div class="mini" id="l_paths"></div></div>
 <div class="card"><div class="lbl">Métodos · clic = filtrar</div><div class="mini" id="l_meth"></div></div>
 <div class="card"><div class="lbl">User-Agents · clic = filtrar</div><div class="mini" id="l_ua"></div></div>
 <div class="card"><div class="lbl">Top queries</div><div class="mini" id="l_q"></div></div>
</div>

<div class="grid rowT">
 <div class="card">
  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:6px">
   <input type="text" id="q" placeholder="filtrar ip / ASN / país…">
   <input type="text" id="qpath" placeholder="filtrar ruta / query…" style="width:170px"
    title="coincide con las rutas y queries top de cada IP">
   <span class="lbl" style="margin:0">estado</span>
   <span class="chip s" data-st="2">2xx</span><span class="chip s" data-st="3">3xx</span>
   <span class="chip s" data-st="4">4xx</span><span class="chip s" data-st="5">5xx</span>
   <span class="lbl" style="margin:0">método</span><span id="methchips"></span>
   <span class="chip" data-f="attack">attack</span><span class="chip" data-f="scan">scan</span>
   <span class="chip" data-f="auth-fail">auth-fail</span><span class="chip" data-f="odd-method">odd-method</span>
   <span class="chip o" data-o="tor">tor</span><span class="chip o" data-o="hosting">hosting</span>
   <span class="chip o" data-o="foreign">foreign</span><span class="chip o" data-o="private">private</span>
   <button id="reset">✕ quitar filtros</button>
   <button id="copy" title="copia la lista de IPs filtradas (blocklist/IOCs)">copiar IPs</button>
   <button id="csv" title="descarga las filas filtradas como CSV">exportar CSV</button>
   <span class="count" id="cnt"></span>
  </div>
  <table id="tbl"><thead><tr>
   <th data-s="0">ip</th><th data-s="1">cc</th><th data-s="2">origen</th><th data-s="3">asn</th>
   <th data-s="4">reqs</th><th>status</th><th data-s="9">404</th><th data-s="7">401/403</th>
   <th data-s="15">hits</th><th data-s="12">MB</th><th data-s="16">visto</th><th>flags</th>
  </tr></thead><tbody></tbody></table>
 </div>
 <div class="card" id="detail"><div class="lbl">Detalle</div>
  <div class="sub">Clic en una IP (tabla).</div></div>
</div>
<div id="tip"></div>
<!-- CC BY 4.0 requires the credit to travel with the work, i.e. with the report
     handed to the client -- not merely with the repository. The country and ASN
     columns and the map are all resolved from these databases. The URI is plain
     text on purpose: this page must stay free of external references so it opens
     unchanged on an air-gapped box, and CC BY is satisfied by naming the URI. -->
<div class="sub" style="margin-top:14px;border-top:1px solid var(--line);padding-top:8px">
 Geolocalización IP por DB-IP (https://db-ip.com) — CC BY 4.0 ·
 mapa: Natural Earth (dominio público)</div>

<script>
const D=__DATA__, WORLD=__WORLD__;
const IP=0,CC=1,OR=2,ASN=3,REQ=4,S2=5,S3=6,S401=7,S403=8,S404=9,S4=10,S5=11,
      MB=12,NP=13,ODD=14,HITS=15,FIRST=16,LAST=17,FL=18,DAYS=19,SAMP=20,P404=21,
      MTH=22,TP=23,UAS=24,QS=25;
const $=id=>document.getElementById(id), fmt=n=>n.toLocaleString('es');
const cut=(s,n)=>s.length>n?s.slice(0,n-1)+'…':s;
// st.days = the day INDEXES picked on the calendar, ascending; empty = every day.
// A range is just the contiguous case of it, which is how one control covers a
// single day, a range and several separate days at once (v0.7.75).
let st={q:'',path:'',flags:new Set(),orig:new Set(),status:new Set(),methods:new Set(),
        cc:null,days:[],ua:null,sel:null,sort:[REQ,-1],mapMode:'vol'};
let lastF=[], dayPlay=null, playKeep=null;
const LASTD=Math.max(0,D.days.length-1);
function setDays(list){
 st.days=list.slice().sort((a,b)=>a-b);
 let t;
 if(!st.days.length)t='todas las fechas';
 else if(st.days.length===1)t=D.days[st.days[0]];
 else{const cont=st.days[st.days.length-1]-st.days[0]===st.days.length-1;
      t=cont?D.days[st.days[0]]+' \u2192 '+D.days[st.days[st.days.length-1]]+' ('+st.days.length+'d)'
            :st.days.length+' d\u00edas sueltos';}
 $('dlab').textContent=t;
 if(!$('cal').hidden)paintCal();
}
// Stopping hands back the selection playback borrowed. A window left behind would
// be a filter with nothing on screen saying so -- and `copiar IPs` and the CSV
// export what is filtered, so the analyst would file a list that ends where they
// pressed stop.
function stopDay(){if(dayPlay){clearInterval(dayPlay);dayPlay=null;$('dplay').innerHTML='&#9654;';
 if(playKeep){const k=playKeep;playKeep=null;setDays(k);renderAll();}}}

function isFiltered(){return !!(st.q||st.path||st.cc||st.flags.size||st.orig.size
  ||st.status.size||st.methods.size||st.days.length||st.ua);}

function pass(r){
 if(st.cc && r[CC]!==st.cc) return false;
 if(st.orig.size && !st.orig.has(r[OR])) return false;
 if(st.flags.size){const f=r[FL]; let ok=false; st.flags.forEach(x=>{if(f.includes(x))ok=true}); if(!ok) return false;}
 // days picked (empty = no filter): keep an IP with traffic on ANY of them, so a
 // range and a handful of separate days read the same way
 if(st.days.length){let ok=false;
  for(const k of st.days) if(k in r[DAYS]){ok=true;break;}
  if(!ok) return false;}
 // status buckets: keep an IP that served >=1 response in ANY ticked class
 if(st.status.size){let ok=false; st.status.forEach(b=>{
   if(b==='2'&&r[S2]>0)ok=true; else if(b==='3'&&r[S3]>0)ok=true;
   else if(b==='4'&&(r[S401]+r[S403]+r[S404]+r[S4])>0)ok=true; else if(b==='5'&&r[S5]>0)ok=true;});
  if(!ok) return false;}
 if(st.methods.size){const m=r[MTH]||{}; let ok=false; st.methods.forEach(x=>{if(x in m)ok=true}); if(!ok) return false;}
 // path/query search over the IP's embedded top paths, queries and own-404s
 if(st.path){const p=st.path; const inA=a=>a&&a.some(x=>String(x[0]).toLowerCase().includes(p));
  if(!(inA(r[TP])||inA(r[QS])||inA(r[P404]))) return false;}
 if(st.ua && !(r[UAS] && r[UAS].some(x=>x[0]===st.ua))) return false;
 if(st.q){const q=st.q.toLowerCase();
  if(!(r[IP].includes(q) || r[ASN].toLowerCase().includes(q) || r[CC].toLowerCase()===q
     || (r[UAS] && r[UAS].some(x=>x[0].toLowerCase().includes(q))))) return false;}
 return true;}

function renderAll(){
 const F=lastF=D.ips.filter(pass);
 const parts=[];
 if(st.q)parts.push(`busca «${st.q}»`); if(st.path)parts.push('ruta «'+cut(st.path,20)+'»');
 if(st.cc)parts.push('país '+st.cc);
 if(st.days.length)parts.push(st.days.length===1?('día '+D.days[st.days[0]])
   :(st.days[st.days.length-1]-st.days[0]===st.days.length-1
     ?('días '+D.days[st.days[0]]+'→'+D.days[st.days[st.days.length-1]])
     :(st.days.length+' días')));
 st.status.forEach(b=>parts.push(b+'xx')); st.methods.forEach(m=>parts.push(m));
 if(st.ua)parts.push('UA «'+cut(st.ua,24)+'»');
 st.flags.forEach(f=>parts.push(f)); st.orig.forEach(o=>parts.push(o));
 $('cnt').textContent=parts.length?('filtros: '+parts.join(' + ')):'';
 $('reset').className=isFiltered()?'hot':'';
 kpis(F); timeline(F); worldmap(F); table(F); lists(F); lists2(F);
 // keep the toolbar status/method chips in sync with the shared state
 document.querySelectorAll('.chip.s').forEach(c=>c.classList.toggle('on',st.status.has(c.dataset.st)));
 document.querySelectorAll('.chip.m').forEach(c=>c.classList.toggle('on',st.methods.has(c.dataset.m)));
 $('sub').textContent=`${D.machine} · ${D.days[0]||''} → ${D.days[D.days.length-1]||''} · generado ${D.generated} · offline`;
}

function lists2(F){
 const nar=isFiltered();
 // methods: exact under any filter (full per-IP method counters)
 const mm={}; for(const r of F){const d=r[MTH]||{}; for(const k in d) mm[k]=(mm[k]||0)+d[k];}
 const tot=Object.values(mm).reduce((a,b)=>a+b,0)||1;
 $('l_meth').innerHTML=Object.entries(mm).sort((a,b)=>b[1]-a[1]).map(([m,n])=>
  `<div class="fil${st.methods.has(m)?' fon':''}" data-m="${esc(m)}">${esc(m)} <b>${fmt(n)} · ${(n/tot*100).toFixed(1)}%</b></div>`).join('')||'—';
 $('l_meth').querySelectorAll('.fil').forEach(d=>d.onclick=()=>{
  const m=d.dataset.m; st.methods.has(m)?st.methods.delete(m):st.methods.add(m); renderAll();});
 // paths / UAs / queries: global exact, or aggregated from per-IP tops under a filter
 const agg=(idx)=>{const a={}; for(const r of F) if(r[idx]) for(const [k,n] of r[idx]) a[k]=(a[k]||0)+n;
  return Object.entries(a).sort((x,y)=>y[1]-x[1]);};
 const paths=nar?agg(TP).slice(0,12):D.paths.slice(0,12);
 $('l_paths').innerHTML=paths.map(([p,n])=>
  `<div class="trunc" title="${esc(p)}">${esc(cut(p,46))} <b>${fmt(n)}</b></div>`).join('')||'—';
 const uas=nar?agg(UAS).slice(0,10).map(([u,n])=>[u,n,null]):D.uas.slice(0,10);
 $('l_ua').innerHTML=uas.map(([u,n,i])=>
  `<div class="fil trunc${st.ua===u?' fon':''}" title="${esc(u)}" data-u="${esc(u)}">${esc(cut(u,44))} <b>${fmt(n)}${i?` · ${fmt(i)} IPs`:''}</b></div>`).join('')||'—';
 $('l_ua').querySelectorAll('.fil').forEach(d=>d.onclick=()=>{
  st.ua=(st.ua===d.dataset.u?null:d.dataset.u); renderAll();});
 const qs=nar?agg(QS).slice(0,10):D.queries.slice(0,10);
 $('l_q').innerHTML=qs.map(([q,n])=>
  `<div class="mono trunc" title="${esc(q)}">?${esc(cut(q,48))} <b>${fmt(n)}</b></div>`).join('')||'—';
}

function kpis(F){
 $('k_req').textContent=fmt(F.reduce((a,r)=>a+r[REQ],0));
 $('k_ips').textContent=fmt(F.length);
 $('k_flag').textContent=fmt(F.filter(r=>r[FL]).length);
 $('k_atk').textContent=fmt(F.filter(r=>r[HITS]>0).length);
 $('k_mb').textContent=fmt(Math.round(F.reduce((a,r)=>a+r[MB],0)));
}

function timeline(F){
 const tot=new Array(D.days.length).fill(0), hot=new Array(D.days.length).fill(0);
 for(const r of F) for(const k in r[DAYS]){ tot[k]+=r[DAYS][k]; if(r[FL]) hot[k]+=r[DAYS][k]; }
 const mx=Math.max(1,...tot), tl=$('tl'); tl.innerHTML='';
 tot.forEach((v,i)=>{const d=document.createElement('div');
  d.style.height=Math.max(2,Math.sqrt(v/mx)*100)+'%';
  if(hot[i]>v*0.5) d.className='hot';
  if(st.days.includes(i)) d.classList.add('day-on');
  // The bars keep a click of their own: one day, or with shift the range from the
  // first day picked. The calendar is for choosing a date, these for pointing at
  // what you can already see.
  d.onclick=e=>{stopDay();
   if(e.shiftKey&&st.days.length){const a=st.days[0],lo=Math.min(a,i),hi=Math.max(a,i);
    const r=[];for(let k=lo;k<=hi;k++)r.push(k);setDays(r);}
   else setDays(st.days.length===1&&st.days[0]===i?[]:[i]);
   renderAll();};
  d.onmousemove=e=>tip(e,`${esc(D.days[i])}<br>${fmt(v)} reqs · ${fmt(hot[i])} flaggeadas`);
  d.onmouseout=hideTip; tl.appendChild(d);});
 $('tlx').innerHTML=`<span>${esc(D.days[0]||'')}</span><span>${esc(D.days[D.days.length-1]||'')}</span>`;
}

function color(r){
 const f=r[FL];
 if(f.includes('attack'))return 'var(--red)';
 if(f.includes('auth-fail'))return 'var(--yel)';
 if(f.includes('scan'))return 'var(--org)';
 if(f.includes('odd-method'))return 'var(--pur)';
 if(r[OR]==='tor')return 'var(--pur)';
 return 'var(--grn)';}

let mapAgg={}, mapNodes=null, mapCentroids={};
function _centroid(d){            // bbox center of the LARGEST ring of the path
 let best=null, ba=0;
 for(const seg of d.split('M')){
  const nums=seg.match(/-?\d+/g); if(!nums||nums.length<6)continue;
  let x0=1e9,x1=-1e9,y0=1e9,y1=-1e9;
  for(let i=0;i+1<nums.length;i+=2){const x=+nums[i],y=+nums[i+1];
   if(x<x0)x0=x; if(x>x1)x1=x; if(y<y0)y0=y; if(y>y1)y1=y;}
  const a=(x1-x0)*(y1-y0);
  if(a>ba){ba=a;best=[(x0+x1)/2,(y0+y1)/2];}}
 return best;}
const _short=n=>n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(n<1e4?1:0)+'k':''+n;

function worldmap(F){
 const agg={};
 for(const r of F){const c=r[CC]; if(c==='?'||c==='LAN')continue;
  const a=(agg[c]=agg[c]||{n:0,atk:0,ips:0,fn:0});
  a.n+=r[REQ]; a.ips++; if(r[HITS]>0)a.atk++; if(r[FL])a.fn+=r[REQ];}
 mapAgg=agg;
 if(!mapNodes){                       // build once; later renders only restyle
  let s=''; for(const cc in WORLD) s+=`<path d="${WORLD[cc]}" data-cc="${cc}"/>`;
  $('map').innerHTML=s+'<g id="mlbl" style="pointer-events:none"></g>';
  mapNodes=[...$('map').querySelectorAll('path')];
  for(const p of mapNodes) mapCentroids[p.dataset.cc]=_centroid(WORLD[p.dataset.cc]);
  mapNodes.forEach(p=>{
   p.onclick=()=>{st.cc=(st.cc===p.dataset.cc?null:p.dataset.cc); renderAll();};
   p.onmousemove=e=>{const a=mapAgg[p.dataset.cc];
    tip(e,`<b>${p.dataset.cc}</b>${a?`<br>${fmt(a.n)} reqs · ${fmt(a.ips)} IPs<br>${fmt(a.fn)} reqs de IPs flaggeadas · ${a.atk} con payloads`:' · sin tráfico'}`);};
   p.onmouseout=hideTip;});
 }
 // metric: total volume, or requests coming from flagged IPs ("flags" view)
 const flagView=st.mapMode==='flags';
 const metric=a=>flagView?a.fn:a.n;
 const vals=Object.values(agg).map(metric).filter(v=>v>0);
 const lmin=Math.log10(Math.max(1,Math.min(...vals))), lmax=Math.log10(Math.max(2,...vals));
 for(const p of mapNodes){
  const a=agg[p.dataset.cc]; let fill='#232830';
  if(a&&metric(a)>0){
   const t=lmax>lmin?(Math.log10(metric(a))-lmin)/(lmax-lmin):1;   // min-max on logs
   fill=flagView
    ?`rgb(${Math.round(60+t*195)},${Math.round(48+t*34)},${Math.round(52+t*30)})`   // dark -> red
    :`rgb(${Math.round(40+t*60)},${Math.round(60+t*110)},${Math.round(80+t*175)})`; // dark -> blue
  }
  p.setAttribute('fill',fill);
  p.setAttribute('class',(a?'lit':'')+(st.cc===p.dataset.cc?' cc-on':''));
  if(!flagView&&a&&a.atk){p.setAttribute('stroke','var(--red)');p.setAttribute('stroke-width','1.4');}
  else{p.removeAttribute('stroke');p.removeAttribute('stroke-width');}
 }
 // labels on the top countries by the active metric
 const top=Object.entries(agg).filter(([,a])=>metric(a)>0)
  .sort((x,y)=>metric(y[1])-metric(x[1])).slice(0,8);
 $('mlbl').innerHTML=top.map(([cc,a])=>{
  const c=mapCentroids[cc]; if(!c)return '';
  return `<text x="${c[0]}" y="${c[1]}" text-anchor="middle" font-size="17" font-weight="700"
    fill="var(--txt)" stroke="var(--bg)" stroke-width="3" paint-order="stroke">${esc(cc)} ${_short(metric(a))}</text>`;
 }).join('');
 $('mm_note').textContent=flagView?'reqs de IPs flaggeadas':'reqs geolocalizadas (LAN fuera)';
 // clickable country ranking next to the map
 const rk=Object.entries(agg).sort((x,y)=>y[1].n-x[1].n).slice(0,10);
 const rmx=Math.max(1,...rk.map(([,a])=>a.n));
 $('l_cc').innerHTML=rk.map(([cc,a])=>
  `<div class="fil${st.cc===cc?' fon':''}" data-cc="${esc(cc)}" title="${fmt(a.n)} reqs · ${fmt(a.fn)} de flaggeadas · ${a.atk} IPs con payloads">
    ${esc(cc)} <b>${_short(a.n)}${a.fn?` · <span style="color:var(--red)">${_short(a.fn)}</span>`:''}</b>
    <div style="height:3px;background:var(--blu);width:${Math.max(3,a.n/rmx*100).toFixed(0)}%">
     ${a.fn?`<div style="height:3px;background:var(--red);width:${(a.fn/Math.max(1,a.n)*100).toFixed(0)}%"></div>`:''}</div>
   </div>`).join('')||'—';
 $('l_cc').querySelectorAll('.fil').forEach(d=>d.onclick=()=>{
  st.cc=(st.cc===d.dataset.cc?null:d.dataset.cc); renderAll();});
}

function lists(F){
 const set=new Set(F.map(r=>r[IP]));
 const filtered=isFiltered();
 let rows404;
 if(filtered){
  const agg={};
  for(const r of F) if(r[P404]) for(const [p,n] of r[P404]) agg[p]=(agg[p]||0)+n;
  rows404=Object.entries(agg).sort((a,b)=>b[1]-a[1]).slice(0,14)
   .map(([p,n])=>[p,n,null,'']);
  if(!rows404.length) rows404=null;
 } else rows404=D.p404.slice(0,14);
 $('l404').innerHTML=rows404?rows404.map(([p,n,i,s])=>
  `<div title="${esc(p)}">${esc(p.length>34?p.slice(0,33)+'…':p)} <b style="color:${s?'var(--red)':'var(--txt)'}">${fmt(n)}${i?` · ${i} IPs`:''}</b></div>`).join('')
  :'<div style="color:var(--mut)">sin 404 con el filtro (solo IPs flaggeadas llevan muestra)</div>';
 const auth=D.auth.filter(a=>set.has(a[0])).slice(0,14);
 $('lauth').innerHTML=auth.length?auth.map(a=>
  `<div title="${esc(a[1])}"><span class="ipsel" style="color:var(--blu);cursor:pointer" data-ip="${esc(a[0])}">${esc(a[0])}</span> ${esc(a[1].length>22?a[1].slice(0,21)+'…':a[1])} <b>${a[2]+a[3]}</b></div>`).join('')
  :'<div style="color:var(--mut)">—</div>';
 // bind the IP through dataset, never into an inline handler: there it would be
 // JavaScript source, and one apostrophe in a planted log line ends the string.
 $('lauth').querySelectorAll('.ipsel').forEach(s=>s.onclick=()=>select(s.dataset.ip));
}

function table(F){
 const [k,dir]=st.sort;
 const S=[...F].sort((a,b)=>{const x=a[k],y=b[k];return (x<y?-1:x>y?1:0)*dir;});
 const N=Math.min(S.length,350);
 let h='';
 for(let i=0;i<N;i++){const r=S[i],t=Math.max(1,r[REQ]);
  const p2=(r[S2]/t*80).toFixed(0),p3=(r[S3]/t*80).toFixed(0),
        p4=((r[S401]+r[S403]+r[S404]+r[S4])/t*80).toFixed(0),p5=(r[S5]/t*80).toFixed(0);
  h+=`<tr class="ipr${st.sel===r[IP]?' sel':''}" data-ip="${esc(r[IP])}">
   <td><b>${esc(r[IP])}</b></td><td>${esc(r[CC])}</td><td>${esc(r[OR])}</td>
   <td title="${esc(r[ASN])}">${esc(r[ASN].slice(0,26))}</td><td>${fmt(r[REQ])}</td>
   <td><span class="bar"><span style="width:${p2}px;background:var(--grn)"></span><span style="width:${p3}px;background:var(--blu)"></span><span style="width:${p4}px;background:var(--org)"></span><span style="width:${p5}px;background:var(--red)"></span></span></td>
   <td>${fmt(r[S404])}</td><td>${r[S401]+r[S403]||''}</td>
   <td style="color:${r[HITS]?'var(--red)':'var(--mut)'}">${r[HITS]||''}</td>
   <td>${r[MB]>=1?fmt(Math.round(r[MB])):''}</td>
   <td style="color:var(--mut);font-size:10px">${esc(r[FIRST].slice(0,10))}→${esc(r[LAST].slice(5,10))}</td>
   <td>${r[FL].split('+').filter(Boolean).map(f=>`<span class="tag t-${esc(f)}">${esc(f)}</span>`).join('')}</td></tr>`;}
 document.querySelector('#tbl tbody').innerHTML=h;
 document.querySelectorAll('#tbl tbody tr').forEach(tr=>tr.onclick=()=>select(tr.dataset.ip));
 $('cnt').textContent=`${fmt(N)} de ${fmt(F.length)} IPs`+($('cnt').textContent?' · '+$('cnt').textContent:'');
}

function select(ip){
 st.sel=ip; const r=D.ips.find(x=>x[IP]===ip); if(!r)return;
 const days=Object.keys(r[DAYS]).map(Number).sort((a,b)=>a-b);
 const mx=Math.max(...days.map(d=>r[DAYS][d]));
 let spark='<svg viewBox="0 0 220 26" style="width:100%">';
 const span=Math.max(1,D.days.length-1);
 for(const d of days){const x=4+d/span*212,h=Math.max(2,r[DAYS][d]/mx*22);
  spark+=`<rect x="${x.toFixed(1)}" y="${(24-h).toFixed(1)}" width="2.4" height="${h.toFixed(1)}" fill="${color(r)}"/>`;}
 spark+='</svg>';
 const samp=(r[SAMP]||[]).map(([c,u])=>`<div class="mono"><span class="tag t-attack">${c}</span>${esc(u)}</div>`).join('')||'<span style="color:var(--mut)">— (sin payloads capturados)</span>';
 const auth=D.auth.filter(a=>a[0]===ip);
 const p4=(r[P404]||[]).slice(0,6).map(([p,n])=>`<div class="mono">${esc(p)} <b>${n}</b></div>`).join('');
 $('detail').innerHTML=`<div class="lbl" style="color:${color(r)}">Detalle — ${esc(ip)}</div>
  <div class="sub">${esc(r[CC])} · ${esc(r[OR])} · ${esc(r[ASN])||'ASN —'}<br>${esc(r[FIRST])} → ${esc(r[LAST])}</div>
  <div class="mini">reqs <b>${fmt(r[REQ])}</b></div>
  <div class="mini">2xx ${fmt(r[S2])} · 3xx ${fmt(r[S3])} · 401 ${r[S401]} · 403 ${r[S403]} · 404 ${fmt(r[S404])} · 5xx ${r[S5]}</div>
  <div class="mini">rutas distintas <b>${r[NP]}</b> · MB <b>${r[MB]}</b></div>
  <div class="mini">métodos <b>${Object.entries(r[MTH]||{}).sort((a,b)=>b[1]-a[1]).map(([m,n])=>`${esc(m)}:${fmt(n)}`).join(' ')}</b></div>
  ${(r[UAS]||[]).length?`<div class="lbl" style="margin-top:8px">user-agents</div>`+r[UAS].map(([u,n])=>`<div class="mono">${esc(u)} <b>${fmt(n)}</b></div>`).join(''):''}
  ${(r[QS]||[]).length?`<div class="lbl" style="margin-top:8px">queries top</div>`+r[QS].map(([qq,n])=>`<div class="mono">?${esc(qq)} <b>${fmt(n)}</b></div>`).join(''):''}
  ${(r[TP]||[]).length?`<div class="lbl" style="margin-top:8px">rutas top</div>`+r[TP].map(([p,n])=>`<div class="mono">${esc(p)} <b>${fmt(n)}</b></div>`).join(''):''}
  <div class="lbl" style="margin-top:8px">actividad diaria</div>${spark}
  <div class="lbl" style="margin-top:8px">payloads (${r[HITS]})</div>${samp}
  ${p4?`<div class="lbl" style="margin-top:8px">sus 404 top</div>${p4}`:''}
  ${auth.length?`<div class="lbl" style="margin-top:8px">auth failures</div>`+auth.map(a=>`<div class="mono">${esc(a[1])} <b>${a[2]}×401 ${a[3]}×403</b></div>`).join(''):''}
  <div style="margin-top:10px"><a class="reset" id="fip">filtrar todo por esta IP</a></div>`;
 // same reason as the auth list: bind the value, do not interpolate it into an
 // inline handler. `ip` is whatever the log line put in the client-host field.
 $('fip').onclick=()=>{st.q=ip;document.getElementById('q').value=ip;renderAll();};
 renderAll();
}

// EVERY value that reaches the page comes off the wire, i.e. is attacker-controlled:
// not just URLs, user-agents and query strings but the client host too -- the CLF
// parser takes it as `\S+` and only the X-Forwarded-For branch is validated, so a
// planted log line can put markup in the "IP" column. `>` and `'` are escaped even
// where the context does not strictly need them, so that this stays byte-identical
// to the lateral graph's esc(): one rule to remember rather than two subtly
// different ones. Change one, change the other.
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
 .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function tip(e,html){const t=$('tip');t.innerHTML=html;t.style.display='block';
 t.style.left=Math.min(e.clientX+14,window.innerWidth-180)+'px';t.style.top=(e.clientY+12)+'px';}
function hideTip(){$('tip').style.display='none';}

$('mm_vol').onclick=()=>{st.mapMode='vol';
 $('mm_vol').classList.add('on');$('mm_flag').classList.remove('on');renderAll();};
$('mm_flag').onclick=()=>{st.mapMode='flags';
 $('mm_flag').classList.add('on');$('mm_vol').classList.remove('on');renderAll();};
let qTimer;
$('q').addEventListener('input',e=>{clearTimeout(qTimer);
 qTimer=setTimeout(()=>{st.q=e.target.value.trim();renderAll();},120);});
let pTimer;
$('qpath').addEventListener('input',e=>{clearTimeout(pTimer);
 pTimer=setTimeout(()=>{st.path=e.target.value.trim().toLowerCase();renderAll();},120);});
// status-bucket chips (static) and method chips (built from the global list)
document.querySelectorAll('.chip[data-st]').forEach(c=>c.onclick=()=>{
 const b=c.dataset.st; st.status.has(b)?st.status.delete(b):st.status.add(b); renderAll();});
$('methchips').innerHTML=(D.methods||[]).slice(0,10).map(([m])=>
 `<span class="chip m" data-m="${esc(m)}">${esc(m)}</span>`).join('');
document.querySelectorAll('.chip.m').forEach(c=>c.onclick=()=>{
 const m=c.dataset.m; st.methods.has(m)?st.methods.delete(m):st.methods.add(m); renderAll();});
document.querySelectorAll('.chip[data-f]').forEach(c=>c.onclick=()=>{
 const f=c.dataset.f; st.flags.has(f)?st.flags.delete(f):st.flags.add(f);
 c.classList.toggle('on'); renderAll();});
document.querySelectorAll('.chip[data-o]').forEach(c=>c.onclick=()=>{
 const o=c.dataset.o; st.orig.has(o)?st.orig.delete(o):st.orig.add(o);
 c.classList.toggle('on'); renderAll();});
document.querySelectorAll('th[data-s]').forEach(th=>th.onclick=()=>{
 const k=+th.dataset.s; st.sort=[k, st.sort[0]===k?-st.sort[1]:(k===IP||k===CC||k===OR||k===ASN||k===FIRST?1:-1)];
 renderAll();});
$('reset').onclick=()=>{stopDay();
  st={q:'',path:'',flags:new Set(),orig:new Set(),status:new Set(),
  methods:new Set(),cc:null,days:[],ua:null,sel:st.sel,sort:st.sort,mapMode:st.mapMode};
  setDays([]);
 $('q').value='';$('qpath').value='';
 document.querySelectorAll('.chip[data-f],.chip[data-o]').forEach(c=>c.classList.remove('on'));
 renderAll();};   // status/method chip classes are re-synced by renderAll
$('copy').onclick=()=>{const t=lastF.map(r=>r[IP]).join('\n');
 (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject())
  .then(()=>{$('copy').textContent=`copiadas ${lastF.length}`;
   setTimeout(()=>$('copy').textContent='copiar IPs',1500);})
  .catch(()=>window.prompt('IPs filtradas (Ctrl+C):',t));};
$('csv').onclick=()=>{
 const head='ip,country,origin,asn,requests,s2xx,s3xx,s401,s403,s404,s4xx,s5xx,mb_sent,paths,odd_methods,attack_hits,first_seen,last_seen,suspicious';
 const q=v=>{v=String(v);return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
 const csv=head+'\n'+lastF.map(r=>r.slice(0,19).map(q).join(',')).join('\n');
 const a=document.createElement('a');
 a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
 a.download='web_ip_stats_filtered.csv'; a.click(); URL.revokeObjectURL(a.href);};

// --- the calendar, and playback -------------------------------------------- //
// Two sliders over the day list made a range a drag with no dates on it, and two
// separate days could not be asked for at all. The lateral graph got a calendar in
// v0.7.74; this is the same control against a different clock -- these rows are
// aggregated PER DAY and carry no time of day, so it picks days only and there are
// no half-hour ends to offer.
const DIDX={}; D.days.forEach((s,i)=>DIDX[s]=i);
const DAYTOT=new Array(D.days.length).fill(0);
D.ips.forEach(r=>{for(const k in r[DAYS])DAYTOT[k]+=r[DAYS][k];});
const DMAX=Math.max(1,...DAYTOT);
const p2=n=>String(n).padStart(2,'0');
const dkey=(y,m,d)=>y+'-'+p2(m+1)+'-'+p2(d);
const monFromKey=k=>Date.UTC(+k.slice(0,4),+k.slice(5,7)-1,1);
let calMon=null, anchor=null, dragging=false, dragMoved=false, lastOver=null, preview=null;

function drawCal(){
 const d=new Date(calMon), y=d.getUTCFullYear(), m=d.getUTCMonth();
 $('cmon').textContent=y+'-'+p2(m+1);
 $('cprev').disabled=calMon<=monFromKey(D.days[0]);
 $('cnext').disabled=calMon>=monFromKey(D.days[LASTD]);
 const ndays=new Date(Date.UTC(y,m+1,0)).getUTCDate(), pad=(d.getUTCDay()+6)%7;
 let h='';
 for(let i=0;i<pad;i++)h+='<span class="day pad"></span>';
 for(let n=1;n<=ndays;n++){
  const k=dkey(y,m,n), i=DIDX[k], v=i==null?0:DAYTOT[i];
  // A day the logs never covered is dimmed but NOT disabled: a disabled button
  // swallows mouse events, so dragging a range across a quiet day would stop
  // following the pointer right there.
  h+=`<button type="button" class="day${i==null?' none':''}" data-i="${i==null?-1:i}"`
    +`${i==null?' tabindex="-1" aria-disabled="true"':''} title="${k}${i==null?': sin registro':': '+fmt(v)+' peticiones'}">${n}`
    +(i==null?'':`<i style="width:${Math.max(12,Math.round(v/DMAX*100))}%"></i>`)+'</button>';
 }
 $('cgrid').innerHTML=h;
 $('cgrid').querySelectorAll('.day:not(.pad)').forEach(el=>{
  const i=+el.dataset.i;
  el.onmousedown=e=>{if(e.shiftKey||e.ctrlKey||e.metaKey||i<0)return;dragging=true;dragMoved=false;anchor=i;lastOver=i;};
  // Selection on MOUSEUP over the cell, not on click: a drag from one day to
  // another dispatches its click on the GRID (the common ancestor), never on a
  // day, so the flag that suppresses that click was left standing and swallowed
  // the next ctrl- or shift-click. Enter and Space come in through keydown, so
  // the keyboard does not depend on a mouse flag at all.
  el.onmouseup=e=>{if(!dragMoved)pick(e,i);};
  el.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();pick(e,i);}};
 });
 // The pointer is read on the GRID and the cell resolved from it, so re-painting
 // under the cursor cannot lose the drag half-way.
 $('cgrid').onmousemove=e=>{
  if(!dragging)return;
  // A mouse released outside the page never delivers its mouseup here, and a drag
  // that believes it is still held would then follow the bare pointer and change
  // the filter -- and `copiar IPs` and the CSV with it -- without a click.
  if(!(e.buttons&1)){dragging=false;dragMoved=false;preview=null;paintCal();return;}
  const el=e.target.closest('.day:not(.pad)'); if(!el)return;
  const i=+el.dataset.i; if(i<0||i===lastOver)return;
  lastOver=i;dragMoved=true;preview=[anchor,i];stopDay();setDays(range(anchor,i));renderAll();};
 paintCal();
}
function range(a,b){const r=[];for(let k=Math.min(a,b);k<=Math.max(a,b);k++)r.push(k);return r;}
function pick(e,i){
 if(i<0)return;                                  // a day the logs never covered
 stopDay();
 if(e.ctrlKey||e.metaKey){const cur=st.days.slice(), at=cur.indexOf(i);
  at<0?cur.push(i):cur.splice(at,1); anchor=i; setDays(cur);}
 else if(e.shiftKey&&anchor!=null)setDays(range(anchor,i));
 else {anchor=i; setDays([i]);}
 renderAll();
}
function paintCal(){
 const lo=preview?Math.min(preview[0],preview[1]):0, hi=preview?Math.max(preview[0],preview[1]):-1;
 $('cgrid').querySelectorAll('.day:not(.pad)').forEach(el=>{const i=+el.dataset.i;
  const on=i>=0&&st.days.includes(i);
  el.classList.toggle('on',on);el.classList.toggle('pre',i>=lo&&i<=hi);
  el.setAttribute('aria-pressed',String(on));});
}
function openCal(open){
 $('cal').hidden=!open;$('dbtn').setAttribute('aria-expanded',String(open));
 if(open){calMon=monFromKey(D.days[st.days.length?st.days[0]:busiestDay()]);drawCal();}
}
// Opens on the busiest day's month: over a year of logs, the fortnight worth
// reading is not the one the calendar happens to start on.
function busiestDay(){let b=0;DAYTOT.forEach((v,i)=>{if(v>DAYTOT[b])b=i;});return b;}
// The release consumes the drag ONLY when it lands on a day: that click is what
// clears the flag, and a mouse let go outside the grid never sends one -- which
// left the flag standing and swallowed the next day the analyst clicked.
document.addEventListener('mouseup',()=>{if(dragging){dragging=false;dragMoved=false;preview=null;paintCal();}});
document.addEventListener('mousedown',e=>{if(!$('cal').hidden&&!e.target.closest('.tpick'))openCal(false);},true);
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('cal').hidden)openCal(false);});
$('dbtn').onclick=()=>openCal($('cal').hidden);
$('cprev').onclick=()=>{const c=new Date(calMon);calMon=Date.UTC(c.getUTCFullYear(),c.getUTCMonth()-1,1);drawCal();};
$('cnext').onclick=()=>{const c=new Date(calMon);calMon=Date.UTC(c.getUTCFullYear(),c.getUTCMonth()+1,1);drawCal();};
$('call').onclick=()=>{stopDay();setDays([]);renderAll();};
if(!D.days.length){$('dbtn').disabled=true;$('dplay').disabled=true;}
setDays([]);
// Playback walks the days PICKED -- all of them when nothing is picked -- one at a
// time, and hands the selection back when it stops.
$('dplay').onclick=()=>{
 if(dayPlay){stopDay();return;}
 const seq=st.days.length?st.days.slice():D.days.map((_,i)=>i);
 if(!seq.length)return;
 playKeep=st.days.slice();
 let k=0;
 setDays([seq[0]]); renderAll(); $('dplay').innerHTML='&#9632;';
 dayPlay=setInterval(()=>{
  if(++k>=seq.length){stopDay();return;}
  setDays(seq.slice(0,k+1)); renderAll();
 },Math.max(120,Math.round(2600/seq.length)));};

renderAll();
</script></body></html>
"""
