"""Unit tests for the detection rules (no Mininet / Ryu needed).

Run from the project root:
    python3 -m unittest tests.test_detector -v
or
    python3 tests/test_detector.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "controller"))
from detector import Detector  # noqa: E402


class DetectorTests(unittest.TestCase):
    def test_normal_client_is_never_flagged(self):
        d = Detector()
        t = 1000.0
        for i in range(200):                       # 5 connections/s for 40 s, one port
            self.assertIsNone(d.observe_syn("10.0.0.2", 8080, now=t))
            t += 0.2

    def test_burst_below_threshold_is_allowed(self):
        d = Detector(rate_threshold=30)
        t = 50.0
        for i in range(30):                        # exactly 30 in < 1 s: not "more than" 30
            self.assertIsNone(d.observe_syn("10.0.0.3", 8080, now=t + i * 0.02))

    def test_syn_flood_detected_on_first_syn_over_threshold(self):
        d = Detector(rate_threshold=30)
        alert = None
        for i in range(100):
            alert = d.observe_syn("10.0.0.4", 8080, now=10.0 + i * 0.005)
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["kind"], "syn_flood")
        self.assertEqual(alert["ip"], "10.0.0.4")
        self.assertEqual(i, 30)                    # the 31st SYN trips the rule
        self.assertEqual(alert["first_seen"], 10.0)

    def test_fast_port_scan_detected(self):
        d = Detector(port_threshold=10)
        alert = None
        for i, port in enumerate(range(1, 50)):
            alert = d.observe_syn("10.0.0.4", port, now=5.0 + i * 0.1)   # 10 ports/s
            if alert:
                break
        self.assertIsNotNone(alert)
        self.assertEqual(alert["kind"], "port_scan")
        self.assertEqual(alert["value"], 11)

    def test_slow_scan_evades_short_window_but_not_long_window(self):
        short = Detector(port_window=5.0, port_threshold=10)
        long_ = Detector(port_window=30.0, port_threshold=10)
        a_short = a_long = None
        for i, port in enumerate(range(1000, 1020)):    # one port per second
            a_short = a_short or short.observe_syn("10.0.0.4", port, now=100.0 + i)
            a_long = a_long or long_.observe_syn("10.0.0.4", port, now=100.0 + i)
        self.assertIsNone(a_short)                  # evaded
        self.assertIsNotNone(a_long)                # caught by the longer window
        self.assertEqual(a_long["kind"], "port_scan")

    def test_sources_are_independent(self):
        d = Detector(rate_threshold=5)
        for i in range(10):
            d.observe_syn("10.0.0.4", 80, now=1.0 + i * 0.01)
        self.assertIsNone(d.observe_syn("10.0.0.2", 80, now=1.2))

    def test_reset_forgets_a_source(self):
        d = Detector(rate_threshold=5)
        for i in range(10):
            d.observe_syn("10.0.0.4", 80, now=1.0 + i * 0.01)
        d.reset("10.0.0.4")
        self.assertIsNone(d.observe_syn("10.0.0.4", 80, now=2.0))
        self.assertEqual(d.rates(now=2.0), {"10.0.0.4": 1})

    def test_new_episode_after_quiet_gap(self):
        d = Detector(rate_threshold=1000, quiet_gap=2.0)
        d.observe_syn("10.0.0.4", 80, now=1.0)
        d.observe_syn("10.0.0.4", 80, now=1.5)
        d.observe_syn("10.0.0.4", 80, now=10.0)             # long silence -> new episode
        self.assertEqual(d._episode["10.0.0.4"], 10.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
