#!/usr/bin/env python3
"""

echo '# Topology setup and cleanup are managed here.' >> topology/topo.py
Mininet topology for the SDN Intrusion Detection project.

            +------ h1  10.0.0.1  (TCP server)
            |------ h2-h3       (benign clients)
   s1 ------|------ h4-h10      (dashboard-controlled senders)
 (OpenFlow1.3)
     |
   c0 = remote Ryu controller at 127.0.0.1:6653

Manual use (from the project root):
    sudo python3 topology/topo.py
"""
import json
import os
import subprocess
import sys
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTION_API_HOST = "127.0.0.1"
ACTION_API_PORT = 8765


class DashboardActionHandler(BaseHTTPRequestHandler):
    """Local-only bridge that launches controlled traffic from a Mininet sender."""

    def __init__(self, *args, net, **kwargs):
        self.net = net
        super().__init__(*args, **kwargs)

    def _reply(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/health":
            self._reply(404, {"error": "not found"})
            return
        with self.net.dashboard_action_lock:
            process = self.net.dashboard_action_process
            running = process is not None and process.poll() is None
        senders = [{"name": host.name, "ip": host.IP()}
                   for host in self.net.hosts if host.name != "h1"]
        self._reply(200, {"status": "ready", "senders": senders,
                          "target": "10.0.0.1", "busy": running})

    def do_POST(self):
        if self.path != "/action":
            self._reply(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 1024:
                raise ValueError("invalid request size")
            payload = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self._reply(400, {"error": "expected a small JSON request"})
            return
        if not isinstance(payload, dict):
            self._reply(400, {"error": "request body must be a JSON object"})
            return

        mode = payload.get("mode")
        if mode not in ("flood", "scan"):
            self._reply(400, {"error": "mode must be flood or scan"})
            return
        sender_name = payload.get("sender", "h4")
        sender = next((host for host in self.net.hosts if host.name == sender_name
                       and host.name != "h1"), None)
        if sender is None:
            self._reply(400, {"error": "sender is not available in this topology"})
            return

        attacker = os.path.join(ROOT, "apps", "attacker.py")
        if mode == "flood":
            args = ["--mode", "flood", "--rate", "200", "--duration", "5"]
        else:
            args = ["--mode", "scan", "--ports", "1-200", "--delay", "0.01", "--timeout", "0.1"]
        command = [sys.executable, attacker, "--host", "10.0.0.1"] + args
        try:
            with self.net.dashboard_action_lock:
                active = self.net.dashboard_action_process
                if active is not None and active.poll() is None:
                    self._reply(409, {"error": "A dashboard traffic action is already running"})
                    return
                process = sender.popen(
                    command, cwd=ROOT, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.net.dashboard_action_process = process
        except Exception as exc:
            self._reply(503, {"error": "could not start traffic in Mininet: %s" % exc})
            return
        self._reply(202, {"status": "started", "mode": mode,
                          "source": "%s (%s)" % (sender.name, sender.IP()),
                          "target": "h1 (10.0.0.1)",
                          "pid": process.pid})

    def log_message(self, fmt, *args):
        # Keep routine browser polling out of the Mininet terminal.
        pass


def start_dashboard_action_api(net):
    net.dashboard_action_lock = threading.Lock()
    net.dashboard_action_process = None
    handler = partial(DashboardActionHandler, net=net)
    server = ThreadingHTTPServer((ACTION_API_HOST, ACTION_API_PORT), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    info("*** Dashboard traffic controls ready at http://%s:%d\n" %
         (ACTION_API_HOST, ACTION_API_PORT))
    return server


def build_net(controller_ip="127.0.0.1", controller_port=6653):
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True)
    net.addController("c0", controller=RemoteController,
                      ip=controller_ip, port=controller_port)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    h1 = net.addHost("h1", ip="10.0.0.1/24")   # server
    hosts = [h1]
    for i in range(2, 11):
        role = "benign client" if i in (2, 3) else "dashboard sender"
        hosts.append(net.addHost("h%d" % i, ip="10.0.0.%d/24" % i))
        info("*** Added h%d as %s\n" % (i, role))
    for h in hosts:
        net.addLink(h, s1)
    return net


def wait_for_switch(net, timeout=10):
    """Wait until the switch has connected to the controller."""
    if hasattr(net, "waitConnected"):
        try:
            net.waitConnected(timeout=timeout)
        except TypeError:
            net.waitConnected()


if __name__ == "__main__":
    setLogLevel("info")
    net = build_net()
    net.start()
    wait_for_switch(net)
    info("*** Topology ready: h1=server, h2-h10=senders (h2/h3 are benign clients)\n")
    action_api = start_dashboard_action_api(net)
    try:
        CLI(net)
    finally:
        action_api.shutdown()
        action_api.server_close()
        net.stop()
