#!/usr/bin/env python3
"""
Offline test of the Ryu controller WITHOUT Mininet / Open vSwitch.

A tiny fake OpenFlow 1.3 switch connects to the controller, sends hand-built
packet-in messages (a normal client, an attacker, a scanner) and checks what the
controller does: alerts, DROP flow_mod, barrier, flow statistics, flow removal.
It is a quick way to debug controller/ids_ryu.py before using the full lab.

    source ~/ryu-env/bin/activate
    python3 tests/test_controller_offline.py
"""
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from ryu.lib.packet import arp, ethernet, ipv4, packet, tcp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 16653
MAC = {1: "00:00:00:00:00:01", 2: "00:00:00:00:00:02", 3: "00:00:00:00:00:03", 4: "00:00:00:00:00:04"}
IP = {i: "10.0.0.%d" % i for i in range(1, 5)}

T_HELLO, T_ECHO_REQ, T_FEAT_REQ, T_PKT_OUT, T_FLOW_MOD, T_BARRIER_REQ, T_MP_REQ = 0, 2, 5, 13, 14, 20, 18


def hdr(msg_type, length, xid):
    return struct.pack("!BBHI", 4, msg_type, length, xid)


def oxm_in_port(port):
    return struct.pack("!HBBI", 0x8000, 0 << 1, 4, port)


def match_bytes(oxm):
    length = 4 + len(oxm)
    pad = (8 - length % 8) % 8
    return struct.pack("!HH", 1, length) + oxm + b"\x00" * pad


def frame_tcp(src, dst, sport, dport, flags):
    p = packet.Packet()
    p.add_protocol(ethernet.ethernet(ethertype=0x0800, dst=MAC[dst], src=MAC[src]))
    p.add_protocol(ipv4.ipv4(proto=6, src=IP[src], dst=IP[dst]))
    p.add_protocol(tcp.tcp(src_port=sport, dst_port=dport, bits=flags, seq=1))
    p.serialize()
    return p.data


def frame_arp(src):
    p = packet.Packet()
    p.add_protocol(ethernet.ethernet(ethertype=0x0806, dst="ff:ff:ff:ff:ff:ff", src=MAC[src]))
    p.add_protocol(arp.arp(opcode=1, src_mac=MAC[src], src_ip=IP[src], dst_mac="00:00:00:00:00:00", dst_ip=IP[1]))
    p.serialize()
    return p.data


class FakeSwitch(object):
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", PORT), timeout=10)
        self.xid = 1000
        self.received = []          # (type, xid, bytes)
        self.drop_rules = {}        # ip -> packets
        self.lock = threading.Lock()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.send(hdr(T_HELLO, 8, 1))

    def send(self, data):
        self.sock.sendall(data)

    def _read(self):
        buf = b""
        while True:
            try:
                chunk = self.sock.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while len(buf) >= 8:
                _, mtype, length, xid = struct.unpack("!BBHI", buf[:8])
                if len(buf) < length:
                    break
                msg, buf = buf[:length], buf[length:]
                with self.lock:
                    self.received.append((mtype, xid, msg))
                self._auto_reply(mtype, xid, msg)

    def _auto_reply(self, mtype, xid, msg):
        if mtype == T_FEAT_REQ:
            self.send(hdr(6, 32, xid) + struct.pack("!QIBB2xII", 1, 0, 1, 0, 0, 0))
        elif mtype == T_ECHO_REQ:
            self.send(hdr(3, len(msg), xid) + msg[8:])
        elif mtype == T_BARRIER_REQ:
            self.send(hdr(21, 8, xid))
        elif mtype == T_FLOW_MOD:
            cookie, cmask, table, cmd, idle, hard, prio, buf_id, out_p, out_g, flags = \
                struct.unpack("!QQBBHHHIIIH", msg[8:46])
            if prio == 100 and cmd == 0:
                i = msg.find(b"\x80\x00\x16\x04")
                ip = socket.inet_ntoa(msg[i + 4:i + 8])
                self.drop_rules[ip] = {"hard": hard, "flags": flags}
        elif mtype == T_MP_REQ:
            mp_type = struct.unpack("!H", msg[8:10])[0]
            if mp_type == 13:          # port description: empty reply moves Ryu to MAIN_DISPATCHER
                self.send(hdr(19, 16, xid) + struct.pack("!HH4x", 13, 0))
            elif mp_type == 1:         # flow statistics
                self.send(self._flow_stats_reply(xid))

    def _flow_stats_reply(self, xid):
        entries = b""
        for ip, info in self.drop_rules.items():
            oxm = struct.pack("!HBBH", 0x8000, 5 << 1, 2, 0x0800) + \
                  b"\x80\x00\x16\x04" + socket.inet_aton(ip)
            m = match_bytes(oxm)
            length = 48 + len(m)
            entries += struct.pack("!HBxIIHHHH4xQQQ", length, 0, 5, 0, 100, 0, info["hard"], info["flags"],
                                   0, 777, 77700) + m
        body = struct.pack("!HH4x", 1, 0) + entries
        return hdr(19, 8 + len(body), xid) + body

    def packet_in(self, in_port, data):
        m = match_bytes(oxm_in_port(in_port))
        body = struct.pack("!IHBBQ", 0xffffffff, len(data), 0, 0, 0) + m + b"\x00\x00" + data
        self.xid += 1
        self.send(hdr(10, 8 + len(body), self.xid) + body)

    def flow_removed(self, ip, packets):
        oxm = struct.pack("!HBBH", 0x8000, 5 << 1, 2, 0x0800) + b"\x80\x00\x16\x04" + socket.inet_aton(ip)
        m = match_bytes(oxm)
        body = struct.pack("!QHBBIIHHQQ", 0, 100, 1, 0, 3, 0, 0, 60, packets, packets * 60) + m
        self.xid += 1
        self.send(hdr(11, 8 + len(body), self.xid) + body)

    def flow_mods(self):
        with self.lock:
            rows = []
            for t, x, m in self.received:
                if t == T_FLOW_MOD:
                    cookie, cmask, table, cmd, idle, hard, prio, _, _, _, flags = struct.unpack("!QQBBHHHIIIH", m[8:46])
                    rows.append({"cmd": cmd, "prio": prio, "idle": idle, "hard": hard, "flags": flags})
            return rows

    def count(self, mtype):
        with self.lock:
            return sum(1 for t, _, _ in self.received if t == mtype)


def events(path):
    out = []
    if os.path.exists(path):
        for line in open(path):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print("  [%s] %s %s" % ("PASS" if cond else "FAIL", name, detail))


def main():
    tmp = tempfile.mkdtemp()
    ev_path = os.path.join(tmp, "events.jsonl")
    env = dict(os.environ, IDS_MODE="ids", EVENTS_FILE=ev_path, STATS_INTERVAL="0.5", BLOCK_TIMEOUT="60")
    ryu = os.path.join(os.path.dirname(sys.executable), "ryu-manager")
    ctrl = subprocess.Popen([ryu, "--ofp-tcp-listen-port", str(PORT), os.path.join(ROOT, "controller", "ids_ryu.py")],
                            env=env, stdout=open(os.path.join(tmp, "ctrl.log"), "w"), stderr=subprocess.STDOUT,
                            preexec_fn=os.setsid)
    try:
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.3)
        sw = FakeSwitch()
        time.sleep(1.5)
        print("Handshake")
        check("controller asked for features", sw.count(T_FEAT_REQ) >= 1)
        check("switch_connected event logged", any(e["type"] == "switch_connected" for e in events(ev_path)))
        check("table-miss flow installed", any(f["prio"] == 0 for f in sw.flow_mods()))

        print("Learning + normal client")
        sw.packet_in(1, frame_arp(1)); sw.packet_in(2, frame_arp(2))
        sw.packet_in(1, frame_tcp(1, 2, 8080, 40000, tcp.TCP_SYN | tcp.TCP_ACK))   # server reply learns h1
        sw.packet_in(2, frame_tcp(2, 1, 40000, 8080, tcp.TCP_SYN))                  # benign SYN
        time.sleep(0.5)
        check("per-connection flow installed (prio 10)", any(f["prio"] == 10 and f["idle"] == 5 for f in sw.flow_mods()))
        check("packet_out forwarded", sw.count(T_PKT_OUT) >= 3)
        check("no alert for normal client", not any(e["type"] == "alert" for e in events(ev_path)))

        print("Connection flood from h4")
        t0 = time.time()
        for i in range(60):
            sw.packet_in(4, frame_tcp(4, 1, 50000 + i, 8080, tcp.TCP_SYN))
        time.sleep(1.0)
        ev = events(ev_path)
        alerts = [e for e in ev if e["type"] == "alert" and e["ip"] == IP[4]]
        check("syn_flood alert for 10.0.0.4", alerts and alerts[0]["kind"] == "syn_flood",
              "(value=%s, detection_ms=%s)" % (alerts[0]["value"] if alerts else None, alerts[0]["detection_ms"] if alerts else None))
        drops = [f for f in sw.flow_mods() if f["prio"] == 100]
        check("exactly one DROP flow_mod (prio 100, hard timeout 60, SEND_FLOW_REM)",
              len(drops) == 1 and drops[0]["hard"] == 60 and drops[0]["flags"] & 1, str(drops))
        check("drop rule is for 10.0.0.4", IP[4] in sw.drop_rules)
        check("barrier sent and confirmed", any(e["type"] == "block_confirmed" and e["ip"] == IP[4] for e in ev))
        conf = [e for e in ev if e["type"] == "block_confirmed"]
        check("response_ms measured", conf and conf[0]["response_ms"] >= 0, "(%s ms)" % (conf[0]["response_ms"] if conf else None))
        syn_after = len([1 for e in ev if e["type"] == "alert" and e["ip"] == IP[4]])
        check("only one alert (later SYNs ignored while blocked)", syn_after == 1)

        print("Benign client still served after the block")
        before = sw.count(T_PKT_OUT)
        sw.packet_in(2, frame_tcp(2, 1, 40001, 8080, tcp.TCP_SYN))
        time.sleep(0.4)
        check("h2 SYN forwarded", sw.count(T_PKT_OUT) > before)

        print("Port scan from h3")
        for k, port in enumerate(range(1, 16)):
            sw.packet_in(3, frame_tcp(3, 1, 45000 + k, port, tcp.TCP_SYN))
            time.sleep(0.05)
        time.sleep(0.8)
        ev = events(ev_path)
        scans = [e for e in ev if e["type"] == "alert" and e["ip"] == IP[3]]
        check("port_scan alert for 10.0.0.3", scans and scans[0]["kind"] == "port_scan", "(ports=%s)" % (scans[0]["value"] if scans else None))
        check("10.0.0.3 dropped too", IP[3] in sw.drop_rules)

        print("Flow statistics")
        time.sleep(1.5)
        ev = events(ev_path)
        fs = [e for e in ev if e["type"] == "flow_stats" and e["drop_rules"]]
        check("flow_stats events with drop rules", bool(fs), "(%s)" % (fs[-1]["drop_rules"] if fs else None))
        st = [e for e in ev if e["type"] == "stats"]
        check("stats events carry counters", st and st[-1]["counters"]["new_connections"] >= 60 and set(st[-1]["blocked"]) == {IP[4], IP[3]},
              "(%s)" % (st[-1]["counters"] if st else None))

        print("Rule expiry")
        sw.flow_removed(IP[4], 1234)
        time.sleep(0.6)
        ev = events(ev_path)
        rem = [e for e in ev if e["type"] == "block_removed"]
        check("block_removed event with dropped packets", rem and rem[0]["dropped_packets"] == 1234 and rem[0]["reason"] == "hard_timeout", str(rem[:1]))
        sw.packet_in(4, frame_tcp(4, 1, 51000, 8080, tcp.TCP_SYN))
        time.sleep(0.4)
        ev = events(ev_path)
        stt = [e for e in ev if e["type"] == "stats"][-1]
        check("h4 no longer in blocked list after expiry", IP[4] not in stt["blocked"])
    finally:
        os.killpg(os.getpgid(ctrl.pid), signal.SIGTERM)
        log = open(os.path.join(tmp, "ctrl.log")).read()
        if os.environ.get("SHOW_LOG"):
            print("\n--- controller log ---\n" + log[-4000:])
        if "Traceback" in log:
            print("\n--- controller traceback ---\n" + log[log.index("Traceback") - 200:][:3000])
            CHECKS.append(("controller log has no traceback", False))

    failed = [n for n, ok in CHECKS if not ok]
    print("\n%d/%d checks passed" % (len(CHECKS) - len(failed), len(CHECKS)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
