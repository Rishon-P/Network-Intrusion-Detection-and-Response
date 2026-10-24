import asyncio
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

# ============================================================
# 1. SDN CONTROLLER (SIMULATED FLOW TABLE)
# ============================================================
class AdvancedSDNController:
    def __init__(self):
        self.flow_table: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()

    def install_drop_rule(self, source_ip: str) -> float:
        """Install a simulated DROP rule and return insertion latency in ms."""
        start_time = time.perf_counter()
        time.sleep(0.0015)
        with self.lock:
            self.flow_table[source_ip] = {
                "action": "DROP",
                "installed_at": time.time(),
            }
        return (time.perf_counter() - start_time) * 1000

    def check_flow(self, source_ip: str) -> str:
        with self.lock:
            rule = self.flow_table.get(source_ip)
            return "DROP" if rule and rule.get("action") == "DROP" else "ALLOW"

    def blocked_ips(self) -> list[str]:
        with self.lock:
            return list(self.flow_table.keys())


sdn_controller = AdvancedSDNController()

# ============================================================
# 2. IDS CORE & METRICS
# ============================================================
connection_history = defaultdict(lambda: deque(maxlen=50))
port_history = defaultdict(set)
live_logs = deque(maxlen=50)
metrics_lock = threading.Lock()
metrics = {
    "total_packets": 0,
    "blocked_packets": 0,
    "detections": 0,
    "response_latencies": [],
}

RATE_THRESHOLD = 8
PORT_THRESHOLD = 4

# Thread-safe dynamic sender registry
senders_lock = threading.Lock()
DYNAMIC_SENDERS = [
    {"id": 1, "name": "Client Alpha", "ip": "192.168.1.101"},
    {"id": 2, "name": "Client Beta", "ip": "192.168.1.102"},
    {"id": 3, "name": "Client Gamma", "ip": "192.168.1.103"},
    {"id": 4, "name": "Client Delta", "ip": "192.168.1.104"},
    {"id": 5, "name": "Client Epsilon", "ip": "192.168.1.105"},
    {"id": 6, "name": "Client Zeta", "ip": "192.168.1.106"},
    {"id": 7, "name": "Client Eta", "ip": "192.168.1.107"},
    {"id": 8, "name": "Client Theta", "ip": "192.168.1.108"},
    {"id": 9, "name": "Client Iota", "ip": "192.168.1.109"},
    {"id": 10, "name": "Client Kappa", "ip": "192.168.1.110"},
]

# ============================================================
# 3. WEBSOCKET MANAGER
# ============================================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self.lock:
            self.active_connections.append(websocket)
        await websocket.send_json(make_snapshot("Dashboard connected successfully"))

    async def disconnect(self, websocket: WebSocket):
        async with self.lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        async with self.lock:
            connections = list(self.active_connections)
        stale = []
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as exc:
                print(f"[WebSocket] Send failed; removing connection: {exc}")
                stale.append(connection)
        if stale:
            async with self.lock:
                for connection in stale:
                    if connection in self.active_connections:
                        self.active_connections.remove(connection)


manager = ConnectionManager()
main_loop: asyncio.AbstractEventLoop | None = None


def make_snapshot(message: str = "Current dashboard state") -> dict:
    with metrics_lock:
        latencies = list(metrics["response_latencies"])
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        metric_snapshot = {
            "total": metrics["total_packets"],
            "blocked": metrics["blocked_packets"],
            "detections": metrics["detections"],
            "avg_latency": round(avg_latency, 2),
        }
    return {
        "time": time.strftime("%H:%M:%S"),
        "msg": message,
        "alert": False,
        "blocked_ips": sdn_controller.blocked_ips(),
        "metrics": metric_snapshot,
        "snapshot": True,
    }


def log_event(message: str, alert: bool = False):
    timestamp = time.strftime("%H:%M:%S")
    with metrics_lock:
        latencies = list(metrics["response_latencies"])
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        metric_snapshot = {
            "total": metrics["total_packets"],
            "blocked": metrics["blocked_packets"],
            "detections": metrics["detections"],
            "avg_latency": round(avg_latency, 2),
        }
    entry = {
        "time": timestamp,
        "msg": message,
        "alert": alert,
        "blocked_ips": sdn_controller.blocked_ips(),
        "metrics": metric_snapshot,
    }
    live_logs.append(entry)
    print(f"[{timestamp}] {message}")

    loop = main_loop
    if loop is not None and loop.is_running():
        try:
            asyncio.run_coroutine_threadsafe(manager.broadcast(entry), loop)
        except RuntimeError as exc:
            print(f"[WebSocket] Could not schedule broadcast: {exc}")
    else:
        print("[WebSocket] Event loop is not ready; dashboard will receive the next event.")


def process_packet(source_ip: str, port: int = 80) -> str:
    now = time.time()
    with metrics_lock:
        metrics["total_packets"] += 1

    if sdn_controller.check_flow(source_ip) == "DROP":
        with metrics_lock:
            metrics["blocked_packets"] += 1
        log_event(f"[SDN FIREWALL] Dropped packet from blacklisted source {source_ip}", alert=True)
        return "BLOCKED"

    connection_history[source_ip].append(now)
    port_history[source_ip].add(port)
    recent_connections = [t for t in connection_history[source_ip] if now - t <= 1.0]

    if len(recent_connections) > RATE_THRESHOLD:
        latency = sdn_controller.install_drop_rule(source_ip)
        with metrics_lock:
            metrics["detections"] += 1
            metrics["response_latencies"].append(latency)
        log_event(
            f"[IDS ALERT] SYN Flood anomaly from {source_ip} "
            f"({len(recent_connections)} conns/s)! SDN Mitigated in {latency:.2f} ms",
            alert=True,
        )
        return "BLOCKED"

    if len(port_history[source_ip]) > PORT_THRESHOLD:
        latency = sdn_controller.install_drop_rule(source_ip)
        with metrics_lock:
            metrics["detections"] += 1
            metrics["response_latencies"].append(latency)
        log_event(
            f"[IDS ALERT] Port Scan anomaly from {source_ip} "
            f"({len(port_history[source_ip])} ports)! SDN Mitigated in {latency:.2f} ms",
            alert=True,
        )
        return "BLOCKED"

    log_event(f"[ALLOW] TCP Flow accepted from {source_ip} on Dest Port {port}")
    return "ALLOWED"


# ============================================================
# 4. FASTAPI LIFECYCLE
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_running_loop()
    print("[Startup] WebSocket event loop initialized")
    yield
    main_loop = None
    print("[Shutdown] Server stopped")


app = FastAPI(lifespan=lifespan)


# ============================================================
# 5. DASHBOARD UI (APPLE HIG DESIGN LANGUAGE & RUNTIME ADD CLIENT)
# ============================================================
@app.get("/", response_class=HTMLResponse)
def get_unified_dashboard():
    with senders_lock:
        current_senders = list(DYNAMIC_SENDERS)

    cards_html = ""
    for sender in current_senders:
        ip = sender["ip"]
        cards_html += f"""
        <div class="apple-card p-3.5 rounded-2xl flex flex-col justify-between space-y-2.5 transition-all duration-200">
          <div>
            <div class="flex justify-between items-center mb-0.5">
              <span class="font-semibold text-white text-xs tracking-tight truncate max-w-[110px]" title="{sender['name']}">{sender['name']}</span>
              <span class="text-[9px] px-2 py-0.5 rounded-full bg-white/10 text-white/70 font-mono tracking-wide">#{sender['id']}</span>
            </div>
            <div class="text-[11px] font-mono text-white/50">{ip}</div>
          </div>
          <div class="space-y-1.5 text-xs">
            <button onclick="triggerAction('{ip}', 'single')" class="w-full apple-btn-secondary py-1 rounded-xl font-medium transition text-[11px]">Send Normal</button>
            <div class="flex gap-1 items-center">
              <input id="flood-count-{ip}" type="number" value="12" min="1" max="100" class="w-12 bg-black/40 text-center border border-white/10 rounded-xl py-0.5 text-white font-mono text-xs focus:outline-none focus:border-blue-500">
              <button onclick="triggerAction('{ip}', 'flood')" class="flex-1 apple-btn-warning py-1 rounded-xl font-medium transition text-[11px]">SYN Flood</button>
            </div>
            <div class="flex gap-1 items-center">
              <input id="scan-count-{ip}" type="number" value="5" min="1" max="50" class="w-12 bg-black/40 text-center border border-white/10 rounded-xl py-0.5 text-white font-mono text-xs focus:outline-none focus:border-blue-500">
              <button onclick="triggerAction('{ip}', 'scan')" class="flex-1 apple-btn-danger py-1 rounded-xl font-medium transition text-[11px]">Port Scan</button>
            </div>
          </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SDN-Assisted IDMS Scalable Matrix</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Icons", "Helvetica Neue", Helvetica, Arial, sans-serif;
      background-color: #000000;
      color: #f5f5f7;
      letter-spacing: -0.01em;
    }}
    .apple-card {{
      background: rgba(28, 28, 30, 0.75);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.08);
      box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    }}
    .apple-card:hover {{
      border-color: rgba(255, 255, 255, 0.15);
    }}
    .apple-btn-secondary {{
      background: rgba(255, 255, 255, 0.08);
      color: #f5f5f7;
      border: 1px solid rgba(255, 255, 255, 0.04);
    }}
    .apple-btn-secondary:hover {{
      background: rgba(255, 255, 255, 0.15);
    }}
    .apple-btn-primary {{
      background: rgba(0, 113, 227, 0.85);
      color: #ffffff;
      border: 1px solid rgba(0, 113, 227, 0.5);
    }}
    .apple-btn-primary:hover {{
      background: rgba(0, 113, 227, 1);
    }}
    .apple-btn-warning {{
      background: rgba(255, 159, 10, 0.2);
      color: #ffd60a;
      border: 1px solid rgba(255, 159, 10, 0.3);
    }}
    .apple-btn-warning:hover {{
      background: rgba(255, 159, 10, 0.3);
    }}
    .apple-btn-danger {{
      background: rgba(255, 69, 58, 0.2);
      color: #ff453a;
      border: 1px solid rgba(255, 69, 58, 0.3);
    }}
    .apple-btn-danger:hover {{
      background: rgba(255, 69, 58, 0.3);
    }}
    ::-webkit-scrollbar {{
      width: 6px;
      height: 6px;
    }}
    ::-webkit-scrollbar-track {{
      background: transparent;
    }}
    ::-webkit-scrollbar-thumb {{
      background: rgba(255, 255, 255, 0.2);
      border-radius: 9999px;
    }}
    ::-webkit-scrollbar-thumb:hover {{
      background: rgba(255, 255, 255, 0.35);
    }}
  </style>
</head>
<body class="p-6 antialiased selection:bg-blue-500 selection:text-white">
  <div class="max-w-[1600px] mx-auto space-y-6">

    <!-- Header / Navigation Bar -->
    <header class="apple-card px-6 py-4 rounded-2xl flex flex-wrap gap-4 justify-between items-center">
      <div>
        <div class="flex items-center space-x-2.5">
          <span class="text-2xl">🛡️</span>
          <h1 class="text-xl font-semibold text-white tracking-tight">SDN &amp; IDMS Scalable Matrix</h1>
        </div>
        <p class="text-white/50 text-xs mt-0.5">Real-time telemetry, automated threat mitigation &amp; dynamic runtime client control</p>
      </div>

      <div class="flex items-center gap-3 flex-wrap">
        <!-- Add Client Inline Form -->
        <div class="flex items-center gap-2 bg-black/40 px-3 py-1.5 rounded-xl border border-white/10 text-xs">
          <span class="text-white/60 font-medium">Add Node:</span>
          <input id="new-client-name" type="text" placeholder="Name (e.g. Omega)" class="w-28 bg-black/50 px-2 py-1 rounded-lg border border-white/10 text-white text-xs focus:outline-none focus:border-blue-500">
          <input id="new-client-ip" type="text" placeholder="IP (e.g. 192.168.1.150)" class="w-32 bg-black/50 px-2 py-1 rounded-lg border border-white/10 text-white font-mono text-xs focus:outline-none focus:border-blue-500">
          <button onclick="addClient()" class="apple-btn-primary px-3 py-1 rounded-lg font-medium transition text-xs">+ Add</button>
        </div>

        <div id="socket-status" class="text-xs font-medium px-3.5 py-1.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span> Connecting…
        </div>
      </div>
    </header>

    <!-- Metrics Grid -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
      <div class="apple-card p-4 rounded-2xl">
        <div class="text-[11px] font-medium text-white/50 uppercase tracking-wider">Total Packets</div>
        <div id="m-total" class="text-3xl font-semibold text-white mt-1">0</div>
      </div>
      <div class="apple-card p-4 rounded-2xl">
        <div class="text-[11px] font-medium text-white/50 uppercase tracking-wider">Anomalies Detected</div>
        <div id="m-detections" class="text-3xl font-semibold text-amber-400 mt-1">0</div>
      </div>
      <div class="apple-card p-4 rounded-2xl">
        <div class="text-[11px] font-medium text-white/50 uppercase tracking-wider">Dropped by SDN</div>
        <div id="m-blocked" class="text-3xl font-semibold text-rose-400 mt-1">0</div>
      </div>
      <div class="apple-card p-4 rounded-2xl">
        <div class="text-[11px] font-medium text-white/50 uppercase tracking-wider">Avg Mitigation Latency</div>
        <div id="m-latency" class="text-3xl font-semibold text-emerald-400 mt-1">0.00 ms</div>
      </div>
    </div>

    <!-- Main Content Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">

      <!-- Left Column: Telemetry & Flow Drop Table -->
      <div class="lg:col-span-7 space-y-6">
        <section class="apple-card p-5 rounded-2xl">
          <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-semibold text-white tracking-tight">📊 Live Telemetry Stream</h2>
            <span class="text-[10px] text-white/40 font-mono">SECURE FEED</span>
          </div>
          <div id="logs" class="bg-black/50 p-3.5 rounded-xl h-[420px] overflow-y-auto font-mono text-[11px] space-y-1.5 border border-white/5">
            <div class="text-white/30 italic">Waiting for telemetry feed…</div>
          </div>
        </section>

        <section class="apple-card p-5 rounded-2xl">
          <div class="flex items-center justify-between mb-3">
            <h2 class="text-sm font-semibold text-rose-400 tracking-tight">⚡ Active SDN Flow Drop Table</h2>
            <span class="text-[10px] text-rose-400/60 font-mono">FIREWALL RULES</span>
          </div>
          <div id="blocktable" class="bg-black/50 p-3 rounded-xl h-32 overflow-y-auto font-mono text-xs space-y-1.5 border border-white/5">
            <span class="text-white/30 italic">No active DROP rules installed…</span>
          </div>
        </section>
      </div>

      <!-- Right Column: Dynamic Client Simulator Matrix -->
      <div class="lg:col-span-5">
        <section class="apple-card p-5 rounded-2xl h-full flex flex-col">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-sm font-semibold text-white tracking-tight">💻 Dynamic Sender Nodes</h2>
            <span id="client-count-badge" class="text-[10px] text-white/40 font-mono">{len(current_senders)} ACTIVE CLIENTS</span>
          </div>
          <div class="grid grid-cols-2 gap-3 overflow-y-auto pr-1 max-h-[700px]">
            {cards_html}
          </div>
        </section>
      </div>

    </div>
  </div>

<script>
  const logsDiv = document.getElementById('logs');
  const blockTableDiv = document.getElementById('blocktable');
  const socketStatus = document.getElementById('socket-status');
  let ws;
  let reconnectTimer;

  function connectWebSocket() {{
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(protocol + '//' + window.location.host + '/ws');
    ws.onopen = () => {{
      socketStatus.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400"></span> Live Socket Connected';
      socketStatus.className = 'text-xs font-medium px-3.5 py-1.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-2';
    }};
    ws.onmessage = (event) => {{
      try {{ updateDashboard(JSON.parse(event.data)); }}
      catch (error) {{ console.error('Invalid WebSocket message:', error, event.data); }}
    }};
    ws.onerror = (event) => console.error('WebSocket error:', event);
    ws.onclose = () => {{
      socketStatus.innerHTML = '<span class="w-2 h-2 rounded-full bg-rose-400 animate-ping"></span> Disconnected — reconnecting…';
      socketStatus.className = 'text-xs font-medium px-3.5 py-1.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 flex items-center gap-2';
      clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(connectWebSocket, 1500);
    }};
  }}

  async function addClient() {{
    const nameInput = document.getElementById('new-client-name');
    const ipInput = document.getElementById('new-client-ip');
    const name = nameInput.value.trim();
    const ip = ipInput.value.trim();

    if (!name || !ip) {{
      alert('Please provide both a client name and IP address.');
      return;
    }}

    try {{
      const params = new URLSearchParams({{name, ip}});
      const response = await fetch('/add-client?' + params.toString(), {{method: 'POST'}});
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || response.statusText);

      // Clear inputs and reload to render the new node card instantly
      nameInput.value = '';
      ipInput.value = '';
      window.location.reload();
    }} catch (error) {{
      console.error('Could not add client:', error);
      alert('Could not add client: ' + error.message);
    }}
  }}

  function updateDashboard(data) {{
    if (data.metrics) {{
      document.getElementById('m-total').textContent = data.metrics.total ?? 0;
      document.getElementById('m-detections').textContent = data.metrics.detections ?? 0;
      document.getElementById('m-blocked').textContent = data.metrics.blocked ?? 0;
      document.getElementById('m-latency').textContent = (data.metrics.avg_latency ?? 0).toFixed ? data.metrics.avg_latency.toFixed(2) + ' ms' : data.metrics.avg_latency + ' ms';
    }}

    if (data.msg && !data.snapshot) {{
      const line = document.createElement('div');
      line.className = data.alert ? 'text-rose-400 font-semibold' : 'text-white/80';
      line.textContent = '[' + (data.time || '--:--:--') + '] ' + data.msg;
      logsDiv.appendChild(line);
      while (logsDiv.children.length > 200) logsDiv.removeChild(logsDiv.firstChild);
      logsDiv.scrollTop = logsDiv.scrollHeight;
    }} else if (data.snapshot && data.msg) {{
      const line = document.createElement('div');
      line.className = 'text-blue-400';
      line.textContent = '[' + (data.time || '--:--:--') + '] ' + data.msg;
      logsDiv.appendChild(line);
    }}

    const blocked = Array.isArray(data.blocked_ips) ? data.blocked_ips : [];
    if (blocked.length) {{
      blockTableDiv.replaceChildren();
      blocked.forEach(ip => {{
        const row = document.createElement('div');
        row.className = 'p-2 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-300 flex justify-between items-center text-xs gap-2';
        const match = document.createElement('span');
        match.textContent = 'Match: src_ip = ' + ip;
        const action = document.createElement('span');
        action.className = 'bg-rose-500 text-white px-2 py-0.5 rounded-full font-bold text-[9px] tracking-wider';
        action.textContent = 'ACTION: DROP';
        row.append(match, action);
        blockTableDiv.appendChild(row);
      }});
    }} else {{
      blockTableDiv.innerHTML = '<span class="text-white/30 italic">No active DROP rules installed…</span>';
    }}
  }}

  async function triggerAction(ip, type) {{
    let count = 1;
    if (type === 'flood') count = document.getElementById('flood-count-' + ip).value;
    else if (type === 'scan') count = document.getElementById('scan-count-' + ip).value;
    try {{
      const params = new URLSearchParams({{ip, type, count}});
      const response = await fetch('/send-action?' + params.toString(), {{method: 'POST'}});
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || response.statusText);
      if (result.status === 'blocked' && result.msg) console.info(result.msg);
    }} catch (error) {{
      console.error('Could not trigger simulation:', error);
      alert('Could not trigger simulation. Check that the server is running and see the browser console.');
    }}
  }}

  connectWebSocket();
</script>
</body>
</html>"""


# ============================================================
# 6. API ENDPOINTS
# ============================================================
@app.post("/add-client")
def add_client(name: str, ip: str):
    name = name.strip()
    ip = ip.strip()
    if not name or not ip:
        return {"status": "error", "msg": "Name and IP are required"}, 400

    with senders_lock:
        # Check if IP already exists
        if any(s["ip"] == ip for s in DYNAMIC_SENDERS):
            return {"status": "error", "msg": "A client with this IP address already exists."}, 400

        new_id = len(DYNAMIC_SENDERS) + 1
        DYNAMIC_SENDERS.append({"id": new_id, "name": name, "ip": ip})

    log_event(f"[CONFIG] New sender node '{name}' ({ip}) added at runtime.")
    return {"status": "success", "msg": f"Client {name} added successfully"}


@app.post("/send-action")
def handle_action(ip: str, type: str, count: int = 1):
    if type not in {"single", "flood", "scan"}:
        return {"status": "error", "msg": "Unknown action type"}
    count = max(1, min(int(count), 100 if type == "flood" else 50 if type == "scan" else 1))

    if sdn_controller.check_flow(ip) == "DROP":
        with metrics_lock:
            metrics["total_packets"] += 1
            metrics["blocked_packets"] += 1
        log_event(f"[SDN FIREWALL] Dropped packet from blacklisted source {ip}", alert=True)
        return {"status": "blocked", "msg": "IP is blocked"}

    if type == "single":
        result = process_packet(ip, port=80)
    elif type == "flood":
        result = "ALLOWED"
        for _ in range(count):
            result = process_packet(ip, port=80)
            if result == "BLOCKED":
                break
            time.sleep(0.002)
    else:  # scan
        result = "ALLOWED"
        for i in range(count):
            result = process_packet(ip, port=20 + i)
            if result == "BLOCKED":
                break
            time.sleep(0.002)
    return {"status": result}


@app.get("/health")
def health():
    return {"status": "ok", "websocket_loop_ready": main_loop is not None and main_loop.is_running()}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as exc:
        print(f"[WebSocket] Connection ended: {exc}")
        await manager.disconnect(websocket)


if __name__ == "__main__":
    print("=== Advanced SDN-IDMS Runtime Scalable Server Online ===")
    print("Dashboard URL: http://127.0.0.1:8000/")
    uvicorn.run(app, host="127.0.0.1", port=8000)