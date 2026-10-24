"""
Shared helpers for the automated tests and experiments (needs root + Mininet).

A `Lab` starts, in this order:
    1. the Ryu controller (as a subprocess, in the mode you choose),
    2. the Mininet topology (h1 server, h2/h3 benign, h4 attacker),
    3. the TCP server on h1,
and tears everything down again on exit.
"""
import csv
import json
import os
import signal
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "topology"))

APPS = os.path.join(ROOT, "apps")
PY = sys.executable            # python used inside the hosts (system python3 under sudo)
SERVER_IP = "10.0.0.1"
SERVER_PORT = 8080
ATTACKER_IP = "10.0.0.4"


def require_root():
    if os.geteuid() != 0:
        sys.exit("This script needs root (Mininet). Run it with: sudo python3 %s ..." % sys.argv[0])


# ----------------------------------------------------------------------
# small file helpers
# ----------------------------------------------------------------------
def read_events(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def percentile(values, p):
    if not values:
        return None
    v = sorted(values)
    return v[min(len(v) - 1, int(round(p / 100.0 * (len(v) - 1))))]


def mean(values):
    return sum(values) / len(values) if values else None


# ----------------------------------------------------------------------
class Lab:
    def __init__(self, ryu_manager, mode="ids", env=None, out_dir=None,
                 server_opts=None, quiet=True):
        self.ryu = ryu_manager
        self.mode = mode
        self.env_overrides = env or {}
        self.out_dir = out_dir or os.path.join(ROOT, "results", "adhoc")
        self.server_opts = server_opts or []
        self.procs = []
        self.net = None
        self.ctrl = None

    # -- context manager ------------------------------------------------
    def __enter__(self):
        try:
            self.start()
        except BaseException:
            self.stop()
            raise
        return self

    def __exit__(self, *exc):
        self.stop()

    # -- paths ------------------------------------------------------------
    @property
    def events_file(self):
        return os.path.join(self.out_dir, "events.jsonl")

    @property
    def server_log(self):
        return os.path.join(self.out_dir, "server_log.csv")

    def path(self, name):
        return os.path.join(self.out_dir, name)

    # -- lifecycle --------------------------------------------------------
    def start(self):
        from topo import build_net, wait_for_switch
        os.makedirs(self.out_dir, exist_ok=True)
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        env = os.environ.copy()
        env.update({"IDS_MODE": self.mode, "EVENTS_FILE": self.events_file})
        env.update({k: str(v) for k, v in self.env_overrides.items()})
        self.ctrl_log = open(self.path("controller.log"), "w")
        self.ctrl = subprocess.Popen(
            [self.ryu, "--ofp-tcp-listen-port", "6653",
             os.path.join(ROOT, "controller", "ids_ryu.py")],
            env=env, stdout=self.ctrl_log, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        self._wait_for_port("127.0.0.1", 6653, 20)

        self.net = build_net()
        self.net.start()
        wait_for_switch(self.net)
        self.h1, self.h2, self.h3, self.h4 = (self.net.get(n) for n in ("h1", "h2", "h3", "h4"))
        self.s1 = self.net.get("s1")

        for h in (self.h2, self.h3, self.h4):        # prime ARP / MAC learning
            h.cmd("ping -c1 -W1 %s" % SERVER_IP)

        slog = open(self.path("server.out"), "w")
        self.server = self.h1.popen(
            [PY, os.path.join(APPS, "server.py"), "--host", SERVER_IP,
             "--port", str(SERVER_PORT), "--log", self.server_log] + self.server_opts,
            stdout=slog, stderr=subprocess.STDOUT)
        self.procs.append(self.server)
        time.sleep(1.0)
        ok = self.h2.cmd("%s %s --host %s --count 1 --interval 0" %
                         (PY, os.path.join(APPS, "client.py"), SERVER_IP))
        if '"failed": 0' not in ok:
            raise RuntimeError("server on h1 is not reachable from h2: %s" % ok)
        time.sleep(1.0)

    def stop(self):
        for p in self.procs:
            try:
                p.terminate()
            except Exception:
                pass
        if self.net is not None:
            try:
                self.net.stop()
            except Exception:
                pass
            self.net = None
        if self.ctrl is not None:
            try:
                os.killpg(os.getpgid(self.ctrl.pid), signal.SIGTERM)
                self.ctrl.wait(timeout=5)
            except Exception:
                pass
            self.ctrl = None
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @staticmethod
    def _wait_for_port(host, port, timeout):
        end = time.time() + timeout
        while time.time() < end:
            try:
                socket.create_connection((host, port), timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.3)
        raise RuntimeError("Ryu controller did not start listening on %s:%d" % (host, port))

    # -- traffic helpers --------------------------------------------------
    def run_client(self, host, name, duration=None, count=None, interval=0.2):
        """Start a benign client in the background. Returns (Popen, csv_path)."""
        out = self.path("client_%s.csv" % name)
        cmd = [PY, os.path.join(APPS, "client.py"), "--host", SERVER_IP, "--name", name,
               "--interval", str(interval), "--out", out]
        if duration is not None:
            cmd += ["--duration", str(duration)]
        if count is not None:
            cmd += ["--count", str(count)]
        so = open(self.path("client_%s.out" % name), "w")
        p = host.popen(cmd, stdout=so, stderr=subprocess.STDOUT)
        self.procs.append(p)
        return p, out

    def run_attacker(self, host, name, **kw):
        """Start the attacker in the background. Returns (Popen, summary_json_path)."""
        out = self.path("attacker_%s.json" % name)
        cmd = [PY, os.path.join(APPS, "attacker.py"), "--host", SERVER_IP, "--out", out]
        for k, v in kw.items():
            cmd += ["--" + k.replace("_", "-"), str(v)]
        so = open(self.path("attacker_%s.out" % name), "w")
        p = host.popen(cmd, stdout=so, stderr=subprocess.STDOUT)
        self.procs.append(p)
        return p, out

    # -- observation helpers ---------------------------------------------
    def events(self):
        return read_events(self.events_file)

    def alerts(self, ip=None):
        return [e for e in self.events() if e["type"] == "alert" and (ip is None or e["ip"] == ip)]

    def dump_flows(self):
        return subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
                              capture_output=True, text=True).stdout

    def has_drop_rule(self, ip):
        for line in self.dump_flows().splitlines():
            if "nw_src=%s" % ip in line and "actions=drop" in line:
                return True
        return False

    def wait_for(self, predicate, timeout, step=0.2):
        end = time.time() + timeout
        while time.time() < end:
            if predicate():
                return True
            time.sleep(step)
        return predicate()

    def server_rows(self, src_ip=None):
        rows = read_csv(self.server_log)
        return [r for r in rows if src_ip is None or r["src_ip"] == src_ip]
