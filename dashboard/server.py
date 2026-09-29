"""Zero-dependency incident dashboard (review P2).

Serves a single-page dashboard and a JSON feed of audit records, using only the Python
standard library (no Flask/FastAPI) so it runs anywhere the monitor runs. Read-only: it
never modifies the audit log, and binds to localhost by default.

    python -m dashboard --audit ~/.goodai-sentinel/audit.jsonl --port 8787
    # then open http://127.0.0.1:8787
"""
from __future__ import annotations
import argparse, json, html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

AUDIT_PATH = "sentinel_audit.jsonl"

def _read_records(limit=500, severity=None):
    p = Path(AUDIT_PATH)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except Exception:
            continue
        sev = None
        f = rec.get("finding")
        if isinstance(f, dict):
            sev = f.get("severity")
        sev = sev or rec.get("severity") or ("deny" if rec.get("verdict") == "deny" else "info")
        rec["_sev"] = sev
        if severity and sev != severity:
            continue
        out.append(rec)
    return out[-limit:][::-1]           # newest first

def _summary(records):
    counts = {}
    for r in records:
        counts[r["_sev"]] = counts.get(r["_sev"], 0) + 1
    return counts

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass         # quiet
    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif u.path == "/api/records":
            sev = (q.get("severity") or [None])[0]
            limit = int((q.get("limit") or ["500"])[0])
            recs = _read_records(limit=limit, severity=sev)
            self._send(200, json.dumps({"records": recs, "summary": _summary(recs)}))
        elif u.path == "/api/health":
            recs = _read_records(limit=100000)
            self._send(200, json.dumps({"total": len(recs), "summary": _summary(recs),
                                        "audit_path": AUDIT_PATH}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>GoodAI Sentinel — Incidents</title>
<style>
:root{--bg:#0b0e14;--card:#151a23;--fg:#e6e6e6;--mut:#8a94a6;--line:#232a36}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px;flex-wrap:wrap}
h1{font-size:18px;margin:0}.dot{width:10px;height:10px;border-radius:50%;background:#3fb950}
.cards{display:flex;gap:10px;flex-wrap:wrap;padding:16px 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:110px}
.card .n{font-size:24px;font-weight:700}.card .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.critical{color:#f85149}.high{color:#f0883e}.medium{color:#d29922}.deny{color:#f85149}.info,.low{color:#8a94a6}
.filters{padding:0 20px 8px;display:flex;gap:8px;flex-wrap:wrap}
button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 12px;cursor:pointer}
button.active{border-color:#3fb950;color:#3fb950}
table{width:100%;border-collapse:collapse}td,th{padding:8px 20px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
td.t{color:var(--mut);white-space:nowrap}code{color:#a5d6ff;word-break:break-all}
.empty{padding:40px 20px;color:var(--mut);text-align:center}
</style></head><body>
<header><span class=dot></span><h1>🛡️ GoodAI Sentinel — Incidents</h1>
<span id=meta style="color:var(--mut);font-size:12px"></span></header>
<div class=cards id=cards></div>
<div class=filters id=filters></div>
<table><thead><tr><th>Time</th><th>Severity</th><th>Rule / Event</th><th>Detail</th></tr></thead>
<tbody id=rows></tbody></table>
<div class=empty id=empty style=display:none>No records yet — the monitor writes here when something happens.</div>
<script>
let filter=null;
const sevOrder=["critical","high","deny","medium","low","info"];
function esc(s){return (s??"").toString().replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]))}
function fmt(ts){if(!ts)return"";const d=new Date(ts*1000);return d.toLocaleString()}
function detail(r){
  const f=r.finding||{};
  if(f.reason)return esc(f.reason);
  if(r.action||r.target)return "<code>"+esc((r.action||"")+" "+(r.target||""))+"</code>";
  if(r.event)return esc(r.event);
  const c={...r};delete c._sev;return "<code>"+esc(JSON.stringify(c).slice(0,160))+"</code>";
}
function rule(r){const f=r.finding||{};return esc(f.rule||r.event||r.verdict||"—")}
async function load(){
  const u=filter?`/api/records?severity=${filter}`:"/api/records";
  const d=await (await fetch(u)).json();
  const cards=document.getElementById("cards");cards.innerHTML="";
  const s=d.summary||{};
  const total=Object.values(s).reduce((a,b)=>a+b,0);
  document.getElementById("meta").textContent=`${total} recent records`;
  for(const k of sevOrder){if(s[k]){cards.insertAdjacentHTML("beforeend",
    `<div class=card><div class="n ${k}">${s[k]}</div><div class=l>${k}</div></div>`)}}
  const fbox=document.getElementById("filters");fbox.innerHTML=
    `<button class="${!filter?'active':''}" onclick="filter=null;load()">All</button>`+
    sevOrder.filter(k=>s[k]).map(k=>`<button class="${filter===k?'active':''}" onclick="filter='${k}';load()">${k}</button>`).join("");
  const rows=document.getElementById("rows");rows.innerHTML="";
  const recs=d.records||[];
  document.getElementById("empty").style.display=recs.length?"none":"block";
  for(const r of recs){rows.insertAdjacentHTML("beforeend",
    `<tr><td class=t>${fmt(r.ts)}</td><td class="${r._sev}">${esc(r._sev)}</td><td>${rule(r)}</td><td>${detail(r)}</td></tr>`)}
}
load();setInterval(load,3000);
</script></body></html>"""

def main(argv=None):
    global AUDIT_PATH
    p = argparse.ArgumentParser("dashboard", description="GoodAI Sentinel incident dashboard (read-only)")
    p.add_argument("--audit", default="sentinel_audit.jsonl")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--host", default="127.0.0.1")
    a = p.parse_args(argv)
    AUDIT_PATH = a.audit
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"Dashboard: http://{a.host}:{a.port}  (audit: {a.audit})  Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
