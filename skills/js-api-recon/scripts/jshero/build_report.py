#!/usr/bin/env python3
"""
JShero report generator: a standalone, self-contained HTML dashboard for a run.

Reads a run's outputs (endpoints-all.txt, endpoints-methods.txt, params-all.txt,
extract-summary.json, merge-summary.json, chunk-summary.json + the JS folders) and writes a
single report.html with no external assets: KPI stat cards, category/method charts, per-pass
convergence (for 5x runs), and every endpoint grouped by SECTION (first path segment) and
tagged by FUNCTIONALITY (auth, account, payment, admin, api, search, upload, config, content),
with client-side search and filtering. Styled like a SaaS analytics dashboard.

Usage:
  python build_report.py --run-root "runs/<domain>/<ts>" --domain <domain> [--out report.html]
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

FUNC_TAGS = [
    ("auth", r"(login|logout|sign[-_]?in|sign[-_]?up|oauth|/token|sso|saml|/auth|session|/mfa|/otp|password|credential|verify)"),
    ("account", r"(account|profile|/users?/|/user\b|settings|preferences|/me\b)"),
    ("payment", r"(checkout|billing|invoice|/order|/cart|purchase|/pay\b|payment|subscription|/price|refund|wallet)"),
    ("admin", r"(admin|/manage|console|internal|backoffice|/staff)"),
    ("api", r"(/api|api\.|graphql|/v[0-9]+/|/rest/|/rpc|/gql)"),
    ("search", r"(search|/query|suggest|autocomplete|lookup|typeahead)"),
    ("upload", r"(upload|/media|attachment|/import|/export|/download|/file)"),
    ("config", r"(config|/env|feature|flag|manifest|\.json)"),
    ("content", r"(blog|news|article|/post|/page|/cms|content)"),
]


def read_lines(p):
    if p.exists():
        return [l for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    return []


def read_json(p):
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def tags_for(url):
    u = url.lower()
    return [name for name, pat in FUNC_TAGS if re.search(pat, u)]


def section_of(category, url):
    if category == "full":
        try:
            sp = urlsplit(url if re.match(r"^[a-z]+://", url, re.I) else "https://" + url.lstrip("/"))
            segs = [s for s in (sp.path or "").split("/") if s]
            if segs:
                return segs[0].lower()
            return (sp.hostname or "external").lower()
        except Exception:
            return "external"
    if url.startswith("#"):
        segs = [s for s in url.lstrip("#/").split("/") if s]
        return ("#" + segs[0].lower()) if segs else "spa-routes"
    path = url.split("?")[0].split("#")[0]
    segs = [s for s in path.split("/") if s and s not in (".", "..")]
    if not segs:
        return "root"
    seg = segs[0].lower()
    if "." in seg and len(segs) == 1:
        return "root-files"
    return seg


def count_files(d):
    return sum(1 for _ in d.iterdir() if _.is_file()) if d.is_dir() else 0


def main():
    ap = argparse.ArgumentParser(description="Generate a standalone HTML dashboard for a JShero run.")
    ap.add_argument("--run-root", required=True)
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    root = Path(args.run_root)
    if not root.is_dir():
        print(f"ERROR: run-root not found: {root}", file=sys.stderr)
        return 2
    domain = args.domain
    out = Path(args.out) if args.out else (root / "report.html")

    # methods map: url -> [methods]
    methods = {}
    for line in read_lines(root / "endpoints-methods.txt"):
        if "\t" in line:
            m, u = line.split("\t", 1)
            methods[u.strip()] = [x for x in m.split(",") if x]

    # endpoints -> grouped by section
    sections = {}
    by_cat = {"full": 0, "absolute_or_dotted": 0, "relative_with_slash": 0, "relative_no_slash": 0}
    by_method = {}
    total_eps = 0
    for line in read_lines(root / "endpoints-all.txt"):
        if "\t" not in line:
            continue
        cat, url = line.split("\t", 1)
        cat, url = cat.strip(), url.strip()
        total_eps += 1
        by_cat[cat] = by_cat.get(cat, 0) + 1
        m = methods.get(url, [])
        for mm in m:
            by_method[mm] = by_method.get(mm, 0) + 1
        sec = section_of(cat, url)
        sections.setdefault(sec, []).append({"url": url, "cat": cat, "methods": m, "tags": tags_for(url)})

    params = read_lines(root / "params-all.txt")
    thirdparty = read_lines(root / "endpoints-thirdparty.txt")

    raw_js = count_files(root / "raw-js")
    inline_js = count_files(root / "inline-js")
    historical_js = count_files(root / "historical-js")

    merge = read_json(root / "merge-summary.json")
    chunk = read_json(root / "chunk-summary.json")
    extract = read_json(root / "extract-summary.json")

    convergence = []
    passes = 1
    if merge.get("per_pass_unique_contribution"):
        c = merge["per_pass_unique_contribution"]
        passes = len(c)
        for name in sorted(c.keys()):
            convergence.append({"pass": name, "raw": c[name].get("raw-js", 0), "inline": c[name].get("inline-js", 0)})

    def group_sort(groups):
        return sorted(
            ({"name": k, "count": len(v),
              "tags": sorted({t for e in v for t in e["tags"]}),
              "endpoints": sorted(v, key=lambda e: e["url"])}
             for k, v in groups.items()),
            key=lambda s: (-s["count"], s["name"]),
        )

    # by section (first path segment) — collapse singletons into "other" to avoid a long tail
    named, singletons = {}, []
    for k, v in sections.items():
        (named.__setitem__(k, v) if len(v) >= 2 else singletons.extend(v))
    if singletons:
        named["other"] = singletons
    section_list = group_sort(named)

    # by functionality — one bucket per tag; untagged endpoints go to "other". Buckets may overlap.
    funcs = {}
    for v in sections.values():
        for e in v:
            for t in (e["tags"] or ["other"]):
                funcs.setdefault(t, []).append(e)
    func_list = group_sort(funcs)

    data = {
        "meta": {
            "domain": domain,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "run_id": root.name,
            "passes": passes,
            "is_5x": bool(convergence),
        },
        "stats": {
            "endpoints": total_eps,
            "thirdparty": len(thirdparty),
            "params": len(params),
            "raw_js": raw_js,
            "inline_js": inline_js,
            "historical_js": historical_js,
            "unique_js": raw_js + inline_js + historical_js,
            "sections": len(sections),
            "func_areas": len([f for f in func_list if f["name"] != "other"]),
            "methods": sum(by_method.values()),
            "chunks": chunk.get("chunk_filenames", 0),
            "by_category": by_cat,
            "by_method": by_method,
        },
        "convergence": convergence,
        "groupings": {"functionality": func_list, "section": section_list},
        "params": sorted(params),
    }

    html = HTML_TEMPLATE.replace("__TITLE__", f"JShero — {domain}").replace(
        "__DATA__", json.dumps(data))
    out.write_text(html, encoding="utf-8")
    print(f"Report written: {out}")
    print(f"  {total_eps} endpoints across {len(sections)} sections / {len(func_list)} functional "
          f"areas, {len(params)} params, {raw_js + inline_js + historical_js} JS files, passes={passes}")
    return 0


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --bg:#0b0e14; --panel:#141a24; --panel2:#0f141d; --line:#232c3b; --txt:#e7ecf3;
  --muted:#8a93a6; --accent:#5b8cff; --accent2:#3ddc97; --warn:#ffb454; --danger:#ff6b7d;
  --get:#3ddc97; --post:#5b8cff; --put:#ffb454; --delete:#ff6b7d; --patch:#c792ea;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
a{color:var(--accent);text-decoration:none}
header{position:sticky;top:0;z-index:10;background:linear-gradient(180deg,#121826,#0d1119);border-bottom:1px solid var(--line);padding:16px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px}
.dot{width:11px;height:11px;border-radius:3px;background:var(--accent2);box-shadow:0 0 12px var(--accent2)}
.chip{background:#1b2536;border:1px solid var(--line);border-radius:999px;padding:3px 11px;font-size:12px;color:var(--muted)}
.wrap{max-width:1200px;margin:0 auto;padding:24px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px}
.kpi .n{font-size:30px;font-weight:750;letter-spacing:-.5px}
.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.6px;margin-top:2px}
.kpi .s{color:var(--muted);font-size:12px;margin-top:6px}
.kpi.accent .n{color:var(--accent2)} .kpi.blue .n{color:var(--accent)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:22px}
@media(max-width:820px){.grid2{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}
.card h3{margin:0 0 14px;font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted)}
.donutwrap{display:flex;align-items:center;gap:20px}
.legend{display:flex;flex-direction:column;gap:8px;font-size:13px}
.legend .li{display:flex;align-items:center;gap:8px}
.sw{width:11px;height:11px;border-radius:3px}
.bars{display:flex;flex-direction:column;gap:9px}
.bar{display:grid;grid-template-columns:70px 1fr 42px;align-items:center;gap:10px;font-size:13px}
.bar .track{background:#0e1420;border-radius:6px;height:10px;overflow:hidden}
.bar .fill{height:100%;border-radius:6px}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
input[type=search]{flex:1;min-width:220px;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:10px 13px;color:var(--txt);font-size:14px}
.fchip,.gchip{cursor:pointer;user-select:none;background:#161f2e;border:1px solid var(--line);border-radius:999px;padding:5px 12px;font-size:12px;color:var(--muted)}
.fchip.on,.gchip.on{background:var(--accent);border-color:var(--accent);color:#08101f;font-weight:600}
.section{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:10px;overflow:hidden}
.shead{display:flex;align-items:center;gap:12px;padding:13px 16px;cursor:pointer}
.shead:hover{background:#161d29}
.sname{font-weight:650;font-size:15px}
.scount{background:#1b2536;border-radius:999px;padding:2px 10px;font-size:12px;color:var(--muted)}
.stags{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto}
.tag{font-size:11px;padding:2px 8px;border-radius:6px;background:#12314a;color:#8fd0ff;border:1px solid #1d4d74}
.caret{transition:transform .15s;color:var(--muted)}
.section.open .caret{transform:rotate(90deg)}
.sbody{display:none;border-top:1px solid var(--line)}
.section.open .sbody{display:block}
.ep{display:flex;align-items:center;gap:10px;padding:8px 16px;border-bottom:1px solid #1a2230;font-size:13px}
.ep:last-child{border-bottom:none}
.ep:hover{background:#121826}
.m{font-size:10px;font-weight:700;padding:2px 6px;border-radius:5px;min-width:44px;text-align:center;letter-spacing:.4px}
.m.GET{background:rgba(61,220,151,.15);color:var(--get)} .m.POST{background:rgba(91,140,255,.15);color:var(--post)}
.m.PUT{background:rgba(255,180,84,.15);color:var(--put)} .m.DELETE{background:rgba(255,107,125,.15);color:var(--delete)}
.m.PATCH{background:rgba(199,146,234,.15);color:var(--patch)} .m.NONE{background:#1a2230;color:#5c6678}
.epurl{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cdot{width:8px;height:8px;border-radius:50%;flex:none}
.etags{display:flex;gap:5px}
.etag{font-size:10px;padding:1px 6px;border-radius:5px;background:#132033;color:#7f9cc0}
.paramgrid{display:flex;flex-wrap:wrap;gap:7px}
.pill{background:#131b28;border:1px solid var(--line);border-radius:7px;padding:4px 9px;font-size:12px}
.muted{color:var(--muted)} footer{color:var(--muted);text-align:center;padding:24px;font-size:12px}
.hidden{display:none!important}
</style></head>
<body>
<header>
  <div class="brand"><span class="dot"></span>JShero</div>
  <span class="chip" id="c-domain"></span>
  <span class="chip" id="c-run"></span>
  <span class="chip" id="c-gen"></span>
</header>
<div class="wrap">
  <div class="kpis" id="kpis"></div>
  <div class="grid2">
    <div class="card"><h3>Endpoints by category</h3><div class="donutwrap"><div id="donut"></div><div class="legend" id="donut-legend"></div></div></div>
    <div class="card"><h3>HTTP methods recovered</h3><div class="bars" id="methodbars"></div></div>
  </div>
  <div class="card" id="convcard" style="margin-bottom:22px"><h3>Per-pass unique contribution (5x convergence)</h3><div class="bars" id="convbars"></div></div>
  <div class="controls">
    <input type="search" id="search" placeholder="Search endpoints, sections, tags…">
    <span class="fchip on" data-cat="all">all</span>
    <span class="fchip" data-cat="full">full</span>
    <span class="fchip" data-cat="absolute_or_dotted">absolute</span>
    <span class="fchip" data-cat="relative_with_slash">rel/slash</span>
    <span class="fchip" data-cat="relative_no_slash">file.ext</span>
  </div>
  <div class="controls">
    <span class="muted" style="font-size:12px;margin-right:2px">Group by</span>
    <span class="gchip on" data-group="functionality">functionality</span>
    <span class="gchip" data-group="section">section</span>
  </div>
  <div id="sections"></div>
  <div class="card" style="margin-top:22px"><h3>Parameters (<span id="pcount"></span>)</h3>
    <input type="search" id="psearch" placeholder="Filter parameters…" style="margin-bottom:12px">
    <div class="paramgrid" id="params"></div>
  </div>
</div>
<footer>Generated by JShero · endpoints grouped by section, tagged by functionality</footer>
<script>
const DATA = __DATA__;
const CATCOLOR = {full:'#5b8cff', absolute_or_dotted:'#3ddc97', relative_with_slash:'#ffb454', relative_no_slash:'#c792ea'};
const CATLABEL = {full:'Full URLs', absolute_or_dotted:'Absolute / dotted', relative_with_slash:'Relative w/ slash', relative_no_slash:'file.ext'};
const $=(s,e=document)=>e.querySelector(s), el=(t,c,h)=>{const n=document.createElement(t); if(c)n.className=c; if(h!=null)n.innerHTML=h; return n};
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

$('#c-domain').textContent=DATA.meta.domain;
$('#c-run').textContent='run '+DATA.meta.run_id;
$('#c-gen').textContent=DATA.meta.generated;

const S=DATA.stats;
const kpis=[
  ['endpoints',S.endpoints,'accent',S.func_areas+' functional areas'],
  ['parameters',S.params,'blue',''],
  ['third-party',S.thirdparty,'','in endpoints-thirdparty.txt'],
  ['unique JS',S.unique_js,'',S.raw_js+' raw · '+S.inline_js+' inline · '+S.historical_js+' hist'],
  ['with method',S.methods,'',Object.keys(S.by_method).length+' verbs'],
  ['webpack chunks',S.chunks,'',''],
  ['passes',DATA.meta.passes,'',DATA.meta.is_5x?'5x merged':'single'],
];
kpis.forEach(([l,n,cls,s])=>{const k=el('div','kpi '+cls); k.append(el('div','n',Number(n).toLocaleString()),el('div','l',l)); if(s)k.append(el('div','s',s)); $('#kpis').append(k)});

// donut
(function(){const cats=Object.entries(S.by_category).filter(([,v])=>v>0); const tot=cats.reduce((a,[,v])=>a+v,0)||1;
 const R=54,C=2*Math.PI*R; let off=0; const NS='http://www.w3.org/2000/svg';
 const svg=document.createElementNS(NS,'svg'); svg.setAttribute('width',140);svg.setAttribute('height',140);svg.setAttribute('viewBox','0 0 140 140');
 const bg=document.createElementNS(NS,'circle');[['cx',70],['cy',70],['r',R],['fill','none'],['stroke','#0e1420'],['stroke-width',16]].forEach(([k,v])=>bg.setAttribute(k,v));svg.append(bg);
 cats.forEach(([c,v])=>{const seg=document.createElementNS(NS,'circle');const len=C*v/tot;
   [['cx',70],['cy',70],['r',R],['fill','none'],['stroke',CATCOLOR[c]||'#888'],['stroke-width',16],['stroke-dasharray',len+' '+(C-len)],['stroke-dashoffset',-off],['transform','rotate(-90 70 70)']].forEach(([k,x])=>seg.setAttribute(k,x));
   svg.append(seg); off+=len;});
 const t=document.createElementNS(NS,'text');t.setAttribute('x',70);t.setAttribute('y',75);t.setAttribute('text-anchor','middle');t.setAttribute('fill','#e7ecf3');t.setAttribute('font-size','22');t.setAttribute('font-weight','700');t.textContent=tot;svg.append(t);
 $('#donut').append(svg);
 cats.forEach(([c,v])=>{const li=el('div','li'); const sw=el('span','sw'); sw.style.background=CATCOLOR[c]||'#888'; li.append(sw, el('span','',esc(CATLABEL[c]||c)+' '), el('span','muted','· '+v)); $('#donut-legend').append(li)});
})();

// method bars
(function(){const ents=Object.entries(S.by_method).sort((a,b)=>b[1]-a[1]); const max=Math.max(1,...ents.map(([,v])=>v));
 if(!ents.length){$('#methodbars').innerHTML='<div class="muted">No HTTP method recovered (minified bundles rename fetch/axios/XHR). See docs.</div>';return;}
 ents.forEach(([m,v])=>{const b=el('div','bar'); const track=el('div','track'); const fill=el('div','fill'); fill.style.width=(100*v/max)+'%'; fill.style.background=getComputedStyle(document.documentElement).getPropertyValue('--'+m.toLowerCase())||'#5b8cff';
   b.append(el('span','mono',m),track,el('span','muted',v)); track.append(fill); $('#methodbars').append(b)});
})();

// convergence
(function(){if(!DATA.convergence.length){$('#convcard').classList.add('hidden');return;}
 const max=Math.max(1,...DATA.convergence.map(c=>c.raw+c.inline));
 DATA.convergence.forEach(c=>{const b=el('div','bar'); const track=el('div','track'); const fill=el('div','fill'); const val=c.raw+c.inline; fill.style.width=(100*val/max)+'%'; fill.style.background='var(--accent)';
   b.append(el('span','mono',c.pass),track,el('span','muted','+'+val)); track.append(fill); $('#convbars').append(b)});
})();

// sections
let catFilter='all', q='', grouping='functionality';
const secWrap=$('#sections');
function methodBadges(m){ if(!m.length) return '<span class="m NONE">—</span>'; return m.map(x=>'<span class="m '+esc(x)+'">'+esc(x)+'</span>').join(''); }
function render(){
  secWrap.innerHTML='';
  const ql=q.toLowerCase();
  let shown=0;
  DATA.groupings[grouping].forEach((sec,idx)=>{
    const eps=sec.endpoints.filter(e=>(catFilter==='all'||e.cat===catFilter) && (!ql|| e.url.toLowerCase().includes(ql) || sec.name.includes(ql) || e.tags.some(t=>t.includes(ql))));
    if(!eps.length) return;
    shown++;
    const s=el('div','section'+(ql?' open':''));
    const head=el('div','shead');
    head.append(el('span','caret','▶'), el('span','sname mono',esc(sec.name)), el('span','scount',eps.length+(eps.length!==sec.count?'/'+sec.count:'')));
    const tags=el('span','stags'); sec.tags.forEach(t=>tags.append(el('span','tag',esc(t)))); head.append(tags);
    head.onclick=()=>s.classList.toggle('open');
    const body=el('div','sbody');
    eps.forEach(e=>{const row=el('div','ep');
      row.insertAdjacentHTML('beforeend', methodBadges(e.methods));
      const cd=el('span','cdot'); cd.style.background=CATCOLOR[e.cat]||'#888'; cd.title=e.cat; row.append(cd);
      const u=el('span','epurl mono'); u.textContent=e.url; u.title=e.url; row.append(u);
      const et=el('span','etags'); e.tags.forEach(t=>et.append(el('span','etag',esc(t)))); row.append(et);
      body.append(row);
    });
    s.append(head,body); secWrap.append(s);
  });
  if(!shown) secWrap.innerHTML='<div class="card muted">No endpoints match.</div>';
}
$('#search').oninput=e=>{q=e.target.value;render()};
document.querySelectorAll('.fchip').forEach(c=>c.onclick=()=>{document.querySelectorAll('.fchip').forEach(x=>x.classList.remove('on'));c.classList.add('on');catFilter=c.dataset.cat;render()});
document.querySelectorAll('.gchip').forEach(c=>c.onclick=()=>{document.querySelectorAll('.gchip').forEach(x=>x.classList.remove('on'));c.classList.add('on');grouping=c.dataset.group;render()});
render();

// params
$('#pcount').textContent=DATA.params.length;
function renderParams(f=''){const box=$('#params');box.innerHTML='';DATA.params.filter(p=>!f||p.toLowerCase().includes(f.toLowerCase())).forEach(p=>box.append(el('span','pill mono',esc(p))));}
$('#psearch').oninput=e=>renderParams(e.target.value);
renderParams();
</script>
</body></html>"""


if __name__ == "__main__":
    sys.exit(main())
