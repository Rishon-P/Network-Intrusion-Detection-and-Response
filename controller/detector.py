"""
Detection logic for the SDN IDS project (pure Python, no Ryu dependency).

Keeping this separate from the controller lets us unit-test the rules
(tests/test_detector.py) without Mininet or Ryu.

Two predefined abnormal behaviours are detected, both from *new connection
attempts* (TCP SYN without ACK) seen by the controller:

  1. syn_flood : more than RATE_THRESHOLD new connections from one source
                 inside the last RATE_WINDOW seconds.
  2. port_scan : more than PORT_THRESHOLD distinct destination ports probed
                 by one source inside the last PORT_WINDOW seconds.
"""
import time
from collections import deque


class Detector:
    def __init__(self, rate_window=1.0, rate_threshold=30,
                 port_window=5.0, port_threshold=10, quiet_gap=2.0):
        self.rate_window = float(rate_window)
        self.rate_threshold = int(rate_threshold)
        self.port_window = float(port_window)
        self.port_threshold = int(port_threshold)
        self.quiet_gap = float(quiet_gap)   # silence that starts a new "episode"
        self._syns = {}        # ip -> deque[(ts, dst_port)]
        self._last_seen = {}   # ip -> ts of last SYN
        self._episode = {}     # ip -> ts of first SYN of the current episode

    # ------------------------------------------------------------------
    def observe_syn(self, ip, dport, now=None):
        """Record one new-connection attempt.

        Returns None when the traffic looks normal, otherwise an alert dict:
        {kind, ip, value, threshold, first_seen}
        """
        now = time.time() if now is None else now

        last = self._last_seen.get(ip)
        if last is None or now - last > self.quiet_gap:
            self._episode[ip] = now          # new burst of activity starts here
        self._last_seen[ip] = now

        dq = self._syns.setdefault(ip, deque())
        dq.append((now, dport))
        horizon = max(self.rate_window, self.port_window)
        while dq and now - dq[0][0] > horizon:
            dq.popleft()

        rate = sum(1 for t, _ in dq if now - t <= self.rate_window)
        if rate > self.rate_threshold:
            return {"kind": "syn_flood", "ip": ip, "value": rate,
                    "threshold": self.rate_threshold,
                    "first_seen": self._episode[ip]}

        ports = {p for t, p in dq if now - t <= self.port_window}
        if len(ports) > self.port_threshold:
            return {"kind": "port_scan", "ip": ip, "value": len(ports),
                    "threshold": self.port_threshold,
                    "first_seen": self._episode[ip]}
        return None

    # ------------------------------------------------------------------
    def rates(self, now=None):
        """{ip: new connections in the last RATE_WINDOW seconds} (non-zero only)."""
        now = time.time() if now is None else now
        out = {}
        for ip, dq in self._syns.items():
            n = sum(1 for t, _ in dq if now - t <= self.rate_window)
            if n:
                out[ip] = n
        return out

    def reset(self, ip):
        """Forget everything about a source (used when its block expires)."""
        self._syns.pop(ip, None)
        self._last_seen.pop(ip, None)
        self._episode.pop(ip, None)
