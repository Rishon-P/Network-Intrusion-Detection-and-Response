#!/usr/bin/env python3
"""
Live dashboard for the SDN IDS project (reads what the Ryu controller writes).

The controller appends JSON lines to results/events.jsonl. This server tails
that file and pushes every new event to the browser over a WebSocket, so the
dashboard shows REAL detections and REAL OpenFlow drop rules (nothing simulated).

    pip install fastapi uvicorn
    python3 dashboard/dashboard.py
    open http://127.0.0.1:8000

Environment: EVENTS_FILE (default <project>/results/events.jsonl), PORT (default 8000)
"""
import asyncio
import json
import os
from contextlib import asynccontextmanager
from typing import List

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENTS_FILE = os.environ.get("EVENTS_FILE", os.path.join(ROOT, "results", "events.jsonl"))
MAX_HISTORY = 400

history = []                     # recent events, replayed to new browsers
clients = []                     # type: List[WebSocket]


async def broadcast(event):
    dead = []
    for ws in list(clients):
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in clients:
            clients.remove(ws)


async def tail_events():
    pos = 0
    while True:
        try:
            if os.path.exists(EVENTS_FILE):
                size = os.path.getsize(EVENTS_FILE)
                if size < pos:                      # controller restarted -> file truncated
                    pos = 0
                    history.clear()
                    await broadcast({"type": "reset"})
                if size > pos:
                    with open(EVENTS_FILE, "rb") as f:
                        f.seek(pos)
                        chunk = f.read()
                    last_nl = chunk.rfind(b"\n")
                    if last_nl >= 0:
                        pos += last_nl + 1
                        for line in chunk[:last_nl].splitlines():
                            try:
                                ev = json.loads(line)
                            except ValueError:
                                continue
                            history.append(ev)
                            del history[:-MAX_HISTORY]
                            await broadcast(ev)
        except Exception as exc:                    # never let the tail task die
            print("[tail] %r" % exc)
        await asyncio.sleep(0.2)


@asynccontextmanager
async def lifespan(app):
    task = asyncio.create_task(tail_events())
    print("[dashboard] tailing %s" % EVENTS_FILE)
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


@app.get("/health")
def health():
    return {"status": "ok", "events_file": EVENTS_FILE,
            "events_file_exists": os.path.exists(EVENTS_FILE), "buffered_events": len(history)}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    for ev in list(history):                        # replay so a refresh keeps the picture
        await ws.send_json(ev)
    clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if ws in clients:
            clients.remove(ws)


PAGE = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SDN Intrusion Detection - Live Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",Helvetica,Arial,sans-serif;
       background:#000;color:#f5f5f7;letter-spacing:-0.01em}
  .card{background:rgba(28,28,30,.75);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,.08);
        box-shadow:0 8px 32px rgba(0,0,0,.37)}
  ::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-thumb{background:rgba(255,255,255,.2);border-radius:9999px}
</style>
</head>
<body class="p-6 antialiased">
<div class="max-w-[1500px] mx-auto space-y-5">

  <header class="card px-6 py-4 rounded-2xl flex flex-wrap gap-4 justify-between items-center">
    <div>
      <div class="flex items-center gap-2.5"><span class="text-2xl">🛡️</span>
        <h1 class="text-xl font-semibold">SDN Network Intrusion Detection &amp; Response</h1></div>
      <p class="text-white/50 text-xs mt-0.5">Live data from the Ryu controller · mode:
        <span id="mode" class="font-mono text-white/80">-</span></p>
    </div>
    <div id="status" class="text-xs font-medium px-3.5 py-1.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">Connecting…</div>
  </header>

  <div class="grid grid-cols-2 lg:grid-cols-6 gap-4">
    <div class="card p-4 rounded-2xl"><div class="text-[11px] text-white/50 uppercase tracking-wider">New connections</div><div id="m-conn" class="text-3xl font-semibold mt-1">0</div></div>
    <div class="card p-4 rounded-2xl"><div class="text-[11px] text-white/50 uppercase tracking-wider">Alerts</div><div id="m-alerts" class="text-3xl font-semibold text-amber-400 mt-1">0</div></div>
    <div class="card p-4 rounded-2xl"><div class="text-[11px] text-white/50 uppercase tracking-wider">Active drop rules</div><div id="m-blocked" class="text-3xl font-semibold text-rose-400 mt-1">0</div></div>
    <div class="card p-4 rounded-2xl"><div class="text-[11px] text-white/50 uppercase tracking-wider">Packets dropped by switch</div><div id="m-drops" class="text-3xl font-semibold text-rose-400 mt-1">0</div></div>
    <div class="card p-4 rounded-2xl"><div class="text-[11px] text-white/50 uppercase tracking-wider">Avg detection</div><div id="m-det" class="text-3xl font-semibold text-emerald-400 mt-1">-</div></div>
    <div class="card p-4 rounded-2xl"><div class="text-[11px] text-white/50 uppercase tracking-wider">Avg response</div><div id="m-resp" class="text-3xl font-semibold text-emerald-400 mt-1">-</div></div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-12 gap-5">
    <div class="lg:col-span-7 space-y-5">
      <section class="card p-5 rounded-2xl">
        <div class="flex justify-between items-center mb-2">
          <h2 class="text-sm font-semibold">📈 Connection rate per source (new TCP connections / s)</h2>
          <span class="text-[10px] text-white/40 font-mono">dashed line = flood threshold</span></div>
        <canvas id="chart" height="170" class="w-full"></canvas>
        <div id="legend" class="flex gap-4 mt-2 text-[11px] font-mono text-white/60 flex-wrap"></div>
      </section>
      <section class="card p-5 rounded-2xl">
        <h2 class="text-sm font-semibold mb-2">📊 Live event log</h2>
        <div id="logs" class="bg-black/50 p-3.5 rounded-xl h-[300px] overflow-y-auto font-mono text-[11px] space-y-1 border border-white/5">
          <div class="text-white/30 italic">Waiting for events from the controller…</div></div>
      </section>
    </div>
    <div class="lg:col-span-5 space-y-5">
      <section class="card p-5 rounded-2xl">
        <h2 class="text-sm font-semibold text-rose-400 mb-2">⚡ Installed OpenFlow DROP rules</h2>
        <div id="blocktable" class="bg-black/50 p-3 rounded-xl min-h-[90px] max-h-[220px] overflow-y-auto font-mono text-xs space-y-1.5 border border-white/5">
          <span class="text-white/30 italic">No active DROP rules…</span></div>
      </section>
      <section class="card p-5 rounded-2xl">
        <div class="flex justify-between items-center mb-2"><h2 class="text-sm font-semibold">💻 Sources</h2>
          <span id="flows" class="text-[10px] text-white/40 font-mono">0 active flows</span></div>
        <div id="nodes" class="grid grid-cols-2 gap-3"></div>
      </section>
    </div>
  </div>
</div>

<script>
const NAMES = {'10.0.0.1':'h1 · Server','10.0.0.2':'h2 · Benign client','10.0.0.3':'h3 · Benign client','10.0.0.4':'h4 · Attacker'};
const COLORS = ['#0a84ff','#30d158','#ffd60a','#ff453a','#bf5af2','#64d2ff'];
const S = {conns:0, alerts:0, blocked:[], dropsNow:{}, dropsDone:0, det:[], resp:[], rates:{}, hist:{}, thr:30, flows:0};
const $ = id => document.getElementById(id);
const logs = $('logs');

function log(text, cls){
  const d = document.createElement('div'); d.className = cls || 'text-white/80';
  const t = new Date().toLocaleTimeString([], {hour12:false});
  d.textContent = '[' + t + '] ' + text; logs.appendChild(d);
  while (logs.children.length > 250) logs.removeChild(logs.firstChild);
  logs.scrollTop = logs.scrollHeight;
}
const avg = a => a.length ? (a.reduce((x,y)=>x+y,0)/a.length) : null;
const fmt = (v,u) => v===null ? '-' : v.toFixed(1)+' '+u;

function handle(ev){
  switch (ev.type){
    case 'reset': S.conns=0;S.alerts=0;S.blocked=[];S.dropsNow={};S.dropsDone=0;S.det=[];S.resp=[];S.rates={};S.hist={};
                  logs.replaceChildren(); log('Controller restarted - counters reset','text-blue-400'); break;
    case 'controller_start': $('mode').textContent = ev.mode; log('Controller started in mode "'+ev.mode+'"','text-blue-400'); break;
    case 'switch_connected': log('Switch s1 connected (dpid '+ev.dpid+')','text-blue-400'); break;
    case 'alert': S.alerts++; S.det.push(ev.detection_ms);
      log('[IDS ALERT] '+(ev.kind==='syn_flood'?'Connection flood':'Port scan')+' from '+ev.ip+' ('+ev.value+' > '+ev.threshold+') detected after '+ev.detection_ms.toFixed(1)+' ms','text-rose-400 font-semibold'); break;
    case 'block_sent': log('[SDN] DROP rule sent for '+ev.ip+' (expires in '+ev.timeout+' s)','text-amber-400'); break;
    case 'block_confirmed': S.resp.push(ev.response_ms);
      log('[SDN] DROP rule for '+ev.ip+' confirmed by switch: response '+ev.response_ms.toFixed(1)+' ms (install '+ev.install_ms.toFixed(1)+' ms)','text-emerald-400'); break;
    case 'block_removed': S.dropsDone += ev.dropped_packets; delete S.dropsNow[ev.ip];
      log('[SDN] DROP rule for '+ev.ip+' removed ('+ev.reason+'), it dropped '+ev.dropped_packets+' packets','text-white/60'); break;
    case 'stats': S.conns = ev.counters.new_connections; S.blocked = ev.blocked||[]; S.rates = ev.syn_rate||{}; S.thr = ev.rate_threshold||S.thr;
      const ips = new Set([...Object.keys(S.rates), ...Object.keys(S.hist)]);
      ips.forEach(ip => { (S.hist[ip] = S.hist[ip] || []).push(S.rates[ip]||0); if (S.hist[ip].length>60) S.hist[ip].shift(); });
      break;
    case 'flow_stats': S.flows = ev.active_flows; S.dropsNow = {}; (ev.drop_rules||[]).forEach(r => S.dropsNow[r.ip]=r.packets); break;
  }
  render();
}

function render(){
  $('m-conn').textContent = S.conns; $('m-alerts').textContent = S.alerts;
  $('m-blocked').textContent = S.blocked.length;
  $('m-drops').textContent = S.dropsDone + Object.values(S.dropsNow).reduce((a,b)=>a+b,0);
  $('m-det').textContent = fmt(avg(S.det),'ms'); $('m-resp').textContent = fmt(avg(S.resp),'ms');
  $('flows').textContent = S.flows + ' active flows';

  const bt = $('blocktable'); bt.replaceChildren();
  if (!S.blocked.length){ bt.innerHTML = '<span class="text-white/30 italic">No active DROP rules…</span>'; }
  S.blocked.forEach(ip => {
    const row = document.createElement('div');
    row.className = 'p-2 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-300 flex justify-between items-center gap-2';
    const a = document.createElement('span'); a.textContent = 'match: ipv4_src=' + ip + ' · ' + (S.dropsNow[ip]||0) + ' pkts dropped';
    const b = document.createElement('span'); b.className='bg-rose-500 text-white px-2 py-0.5 rounded-full font-bold text-[9px] tracking-wider'; b.textContent='ACTION: DROP';
    row.append(a,b); bt.appendChild(row);
  });

  const nodes = $('nodes'); nodes.replaceChildren();
  const ips = new Set([...Object.keys(NAMES).filter(i=>i!=='10.0.0.1'), ...Object.keys(S.hist), ...S.blocked]);
  [...ips].sort().forEach(ip => {
    const blocked = S.blocked.includes(ip), rate = S.rates[ip]||0;
    const c = document.createElement('div'); c.className='card p-3 rounded-2xl';
    c.innerHTML = '<div class="text-xs font-semibold">'+(NAMES[ip]||'Host')+'</div><div class="text-[11px] font-mono text-white/50">'+ip+
      '</div><div class="flex justify-between items-center mt-2"><span class="font-mono text-xs">'+rate+' conn/s</span><span class="text-[9px] px-2 py-0.5 rounded-full font-bold '+
      (blocked?'bg-rose-500 text-white':'bg-emerald-500/20 text-emerald-300')+'">'+(blocked?'BLOCKED':'ALLOWED')+'</span></div>';
    nodes.appendChild(c);
  });
  drawChart();
}

function drawChart(){
  const cv = $('chart'), dpr = window.devicePixelRatio||1;
  const w = cv.clientWidth, h = 170; cv.width = w*dpr; cv.height = h*dpr;
  const g = cv.getContext('2d'); g.scale(dpr,dpr); g.clearRect(0,0,w,h);
  const ips = Object.keys(S.hist); let max = Math.max(S.thr*1.3, 10);
  ips.forEach(ip => S.hist[ip].forEach(v => { if (v>max) max=v; }));
  const px = 34, py = 10, W = w-px-8, H = h-py-18;
  g.strokeStyle='rgba(255,255,255,.08)'; g.fillStyle='rgba(255,255,255,.4)'; g.font='10px monospace';
  for (let i=0;i<=4;i++){ const y = py + H - H*i/4; g.beginPath(); g.moveTo(px,y); g.lineTo(px+W,y); g.stroke(); g.fillText(Math.round(max*i/4), 2, y+3); }
  const ty = py + H - H*S.thr/max; g.setLineDash([5,4]); g.strokeStyle='#ff453a'; g.beginPath(); g.moveTo(px,ty); g.lineTo(px+W,ty); g.stroke(); g.setLineDash([]);
  const leg = $('legend'); leg.replaceChildren();
  ips.sort().forEach((ip,k) => {
    const col = COLORS[k % COLORS.length], d = S.hist[ip]; g.strokeStyle = col; g.lineWidth = 2; g.beginPath();
    d.forEach((v,i) => { const x = px + W*i/59, y = py + H - H*v/max; i? g.lineTo(x,y) : g.moveTo(x,y); }); g.stroke();
    const s = document.createElement('span'); s.innerHTML = '<span style="color:'+col+'">●</span> '+ip; leg.appendChild(s);
  });
  g.lineWidth = 1;
}

function connect(){
  const ws = new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws');
  ws.onopen = () => { $('status').textContent='● Live'; $('status').className='text-xs font-medium px-3.5 py-1.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'; };
  ws.onmessage = e => { try { handle(JSON.parse(e.data)); } catch(err){ console.error(err); } };
  ws.onclose = () => { $('status').textContent='Disconnected - reconnecting…'; $('status').className='text-xs font-medium px-3.5 py-1.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20'; setTimeout(connect,1500); };
}
connect(); render();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print("Dashboard: http://127.0.0.1:%d/" % port)
    uvicorn.run(app, host="127.0.0.1", port=port)
