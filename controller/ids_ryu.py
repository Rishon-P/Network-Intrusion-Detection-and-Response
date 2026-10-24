"""
Ryu (OpenFlow 1.3) controller for the SDN Network Intrusion Detection project.

What it does
------------
* Acts as a learning switch (ARP/ICMP/TCP are forwarded normally).
* TCP traffic gets a *per-connection* flow (exact 5-tuple, short idle timeout).
  Because every new connection has no matching flow, its first packet (the SYN)
  is sent to the controller, so the controller sees every connection attempt.
* Detects predefined abnormal behaviour (see detector.py):
      - SYN flood  : too many new connections per second from one source
      - Port scan  : too many distinct destination ports from one source
* Responds dynamically by installing a high-priority DROP flow for the
  offending source IP (with a hard timeout so the block expires).
* Collects flow statistics every STATS_INTERVAL seconds (OFPFlowStatsRequest).
* Measures detection time and response time (using an OpenFlow barrier).
* Writes everything as JSON lines to EVENTS_FILE; the dashboard tails it.

Run (inside the Ryu virtualenv):
    ryu-manager controller/ids_ryu.py

Optional environment variables
------------------------------
IDS_MODE         ids | static | baseline   (default ids)
                   ids      = detect + block immediately (the proposed approach)
                   static   = detect, but block only after STATIC_DELAY seconds
                              (emulates a human operator reacting to an alert)
                   baseline = plain learning switch, no detection at all
RATE_WINDOW      seconds, default 1.0
RATE_THRESHOLD   SYNs per window, default 30
PORT_WINDOW      seconds, default 5.0
PORT_THRESHOLD   distinct ports per window, default 10
BLOCK_TIMEOUT    lifetime of the DROP rule in seconds, default 60
STATIC_DELAY     seconds, default 5
FLOW_IDLE        idle timeout of per-connection flows, default 5
STATS_INTERVAL   seconds between flow-stats polls, default 1
WHITELIST        comma separated IPs that are never blocked, default 10.0.0.1
EVENTS_FILE      default <project>/results/events.jsonl
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from detector import Detector  # noqa: E402

from ryu.base import app_manager  # noqa: E402
from ryu.controller import ofp_event  # noqa: E402
from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,  # noqa: E402
                                    MAIN_DISPATCHER, set_ev_cls)
from ryu.lib import hub  # noqa: E402
from ryu.lib.packet import ether_types, ethernet, in_proto, ipv4, packet, tcp  # noqa: E402
from ryu.ofproto import ofproto_v1_3  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRIO_TABLE_MISS = 0
PRIO_ICMP = 5
PRIO_CONN = 10
PRIO_DROP = 100


class IDSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IDSController, self).__init__(*args, **kwargs)
        env = os.environ.get
        self.mode = env("IDS_MODE", "ids")
        self.block_timeout = int(env("BLOCK_TIMEOUT", "60"))
        self.static_delay = float(env("STATIC_DELAY", "5"))
        self.flow_idle = int(env("FLOW_IDLE", "5"))
        self.stats_interval = float(env("STATS_INTERVAL", "1"))
        self.whitelist = set(x.strip() for x in env("WHITELIST", "10.0.0.1").split(",") if x.strip())

        self.detector = Detector(
            rate_window=float(env("RATE_WINDOW", "1.0")),
            rate_threshold=int(env("RATE_THRESHOLD", "30")),
            port_window=float(env("PORT_WINDOW", "5.0")),
            port_threshold=int(env("PORT_THRESHOLD", "10")))

        self.mac_to_port = {}        # dpid -> {mac: port}
        self.datapaths = {}          # dpid -> datapath
        self.blocked = {}            # ip -> info dict (drop rule installed)
        self.pending = set()         # ips with an alert whose block is not installed yet
        self.pending_barrier = {}    # xid -> (ip, detect_ts, sent_ts)
        self._stats_acc = {}         # dpid -> list of flow stats (multipart reply)
        self.counters = {"tcp_packet_in": 0, "new_connections": 0,
                         "detections": 0, "blocks": 0}

        events_path = env("EVENTS_FILE", os.path.join(ROOT, "results", "events.jsonl"))
        os.makedirs(os.path.dirname(events_path), exist_ok=True)
        self.event_log = open(events_path, "w")

        self.emit("controller_start", config={
            "rate_window": self.detector.rate_window,
            "rate_threshold": self.detector.rate_threshold,
            "port_window": self.detector.port_window,
            "port_threshold": self.detector.port_threshold,
            "block_timeout": self.block_timeout,
            "static_delay": self.static_delay,
            "flow_idle": self.flow_idle})
        self.stats_thread = hub.spawn(self._stats_loop)

    # ------------------------------------------------------------------
    # Event log
    # ------------------------------------------------------------------
    def emit(self, etype, **fields):
        ev = {"ts": time.time(), "type": etype, "mode": self.mode}
        ev.update(fields)
        self.event_log.write(json.dumps(ev) + "\n")
        self.event_log.flush()
        if etype not in ("stats", "flow_stats"):
            self.logger.info("%s %s", etype, {k: v for k, v in fields.items() if k != "config"})

    # ------------------------------------------------------------------
    # OpenFlow helpers
    # ------------------------------------------------------------------
    def add_flow(self, dp, priority, match, actions, idle=0, hard=0, flags=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = []
        if actions:
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        # empty instruction list == DROP
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle,
                                hard_timeout=hard, flags=flags)
        dp.send_msg(mod)

    def packet_out(self, dp, msg, in_port, out_port):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        out = parser.OFPPacketOut(datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=[parser.OFPActionOutput(out_port)],
                                  data=msg.data)
        dp.send_msg(out)

    # ------------------------------------------------------------------
    # Switch connection handling
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        # wipe old flows (clean start after controller restarts)
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      match=parser.OFPMatch()))
        # table-miss: send unknown packets to the controller
        self.add_flow(dp, PRIO_TABLE_MISS, parser.OFPMatch(),
                      [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        self.emit("switch_connected", dpid=dp.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def on_state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    # ------------------------------------------------------------------
    # Packet-in: forwarding + detection
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)

        ip = pkt.get_protocol(ipv4.ipv4)
        tp = pkt.get_protocol(tcp.tcp)

        if ip is not None and tp is not None:
            self.counters["tcp_packet_in"] += 1
            is_syn = bool(tp.bits & tcp.TCP_SYN) and not (tp.bits & tcp.TCP_ACK)

            if is_syn:
                self.counters["new_connections"] += 1
                if ip.src in self.blocked:
                    return        # drop rule is being installed; do not forward
                if (self.mode != "baseline" and ip.src not in self.whitelist
                        and ip.src not in self.pending):
                    alert = self.detector.observe_syn(ip.src, tp.dst_port)
                    if alert:
                        self.handle_alert(dp, alert)
                        if self.mode == "ids":
                            return    # attacker's packet is not forwarded

            if out_port != ofp.OFPP_FLOOD:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ip_proto=in_proto.IPPROTO_TCP,
                                        ipv4_src=ip.src, ipv4_dst=ip.dst,
                                        tcp_src=tp.src_port, tcp_dst=tp.dst_port)
                self.add_flow(dp, PRIO_CONN, match,
                              [parser.OFPActionOutput(out_port)], idle=self.flow_idle)
            self.packet_out(dp, msg, in_port, out_port)
            return

        if ip is not None and ip.proto == in_proto.IPPROTO_ICMP and out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=in_proto.IPPROTO_ICMP,
                                    ipv4_src=ip.src, ipv4_dst=ip.dst)
            self.add_flow(dp, PRIO_ICMP, match,
                          [parser.OFPActionOutput(out_port)], idle=10)

        # ARP and everything else: just forward this packet
        self.packet_out(dp, msg, in_port, out_port)

    # ------------------------------------------------------------------
    # Alert -> response
    # ------------------------------------------------------------------
    def handle_alert(self, dp, alert):
        now = time.time()
        self.counters["detections"] += 1
        self.emit("alert", detect_ts=now,
                  detection_ms=round((now - alert["first_seen"]) * 1000, 3), **alert)
        if self.mode == "ids":
            self.block(dp, alert["ip"], alert, now)
        elif self.mode == "static":
            self.pending.add(alert["ip"])
            hub.spawn(self._delayed_block, dp, alert["ip"], alert, now)

    def _delayed_block(self, dp, ip, alert, detect_ts):
        hub.sleep(self.static_delay)
        self.block(dp, ip, alert, detect_ts)

    def block(self, dp, ip, alert, detect_ts):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip)
        self.add_flow(dp, PRIO_DROP, match, [], hard=self.block_timeout,
                      flags=ofp.OFPFF_SEND_FLOW_REM)
        barrier = parser.OFPBarrierRequest(dp)
        sent = time.time()
        dp.send_msg(barrier)
        self.pending_barrier[barrier.xid] = (ip, detect_ts, sent)
        self.blocked[ip] = {"installed_ts": sent, "kind": alert["kind"]}
        self.pending.discard(ip)
        self.counters["blocks"] += 1
        self.emit("block_sent", ip=ip, kind=alert["kind"], timeout=self.block_timeout)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def on_barrier_reply(self, ev):
        info = self.pending_barrier.pop(ev.msg.xid, None)
        if info is None:
            return
        ip, detect_ts, sent_ts = info
        now = time.time()
        self.emit("block_confirmed", ip=ip,
                  install_ms=round((now - sent_ts) * 1000, 3),
                  response_ms=round((now - detect_ts) * 1000, 3))

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def on_flow_removed(self, ev):
        msg = ev.msg
        if msg.priority != PRIO_DROP:
            return
        try:
            ip = msg.match["ipv4_src"]
        except KeyError:
            return
        reason = {0: "idle_timeout", 1: "hard_timeout", 2: "delete"}.get(msg.reason, str(msg.reason))
        self.blocked.pop(ip, None)
        self.detector.reset(ip)
        self.emit("block_removed", ip=ip, reason=reason,
                  dropped_packets=msg.packet_count, dropped_bytes=msg.byte_count,
                  duration_s=msg.duration_sec)

    # ------------------------------------------------------------------
    # Flow statistics + connection-rate monitoring
    # ------------------------------------------------------------------
    def _stats_loop(self):
        while True:
            hub.sleep(self.stats_interval)
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            self.emit("stats",
                      syn_rate=self.detector.rates(),
                      counters=dict(self.counters),
                      blocked=sorted(self.blocked),
                      rate_threshold=self.detector.rate_threshold,
                      port_threshold=self.detector.port_threshold)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def on_flow_stats(self, ev):
        dp = ev.msg.datapath
        acc = self._stats_acc.setdefault(dp.id, [])
        acc.extend(ev.msg.body)
        if ev.msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return                      # more parts of this reply follow
        flows = self._stats_acc.pop(dp.id, [])

        active = pkts = nbytes = 0
        drops = []
        for f in flows:
            if f.priority == PRIO_TABLE_MISS:
                continue
            if f.priority == PRIO_DROP:
                try:
                    drops.append({"ip": f.match["ipv4_src"],
                                  "packets": f.packet_count, "bytes": f.byte_count})
                except KeyError:
                    pass
            else:
                active += 1
                pkts += f.packet_count
                nbytes += f.byte_count
        self.emit("flow_stats", dpid=dp.id, active_flows=active,
                  flow_packets=pkts, flow_bytes=nbytes, drop_rules=drops)
