#!/usr/bin/env python3
"""
Automated functional test cases (Mininet + Ryu + TCP apps).

    sudo python3 tests/run_tests.py --ryu /home/<you>/ryu-env/bin/ryu-manager
    sudo python3 tests/run_tests.py --ryu ... --only T2 T3

Every test starts a fresh lab, so tests cannot influence each other.
A PASS/FAIL table is printed and saved to results/test_report.json.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import (ATTACKER_IP, ROOT, Lab, read_csv, read_json, require_root)  # noqa: E402

H2, H3, H4 = "10.0.0.2", "10.0.0.3", "10.0.0.4"


def success_ratio(csv_path, t_from=None, t_to=None):
    rows = read_csv(csv_path)
    if t_from is not None:
        rows = [r for r in rows if float(r["ts"]) >= t_from]
    if t_to is not None:
        rows = [r for r in rows if float(r["ts"]) <= t_to]
    if not rows:
        return None
    return sum(int(r["ok"]) for r in rows) / float(len(rows))


# ----------------------------------------------------------------------
# Each test returns (passed: bool, details: str)
# ----------------------------------------------------------------------
def t1_normal_traffic(a):
    """T1  Normal traffic is allowed and raises no alert."""
    with Lab(a.ryu, "ids", out_dir=a.path("T1")) as lab:
        p, csv_path = lab.run_client(lab.h2, "h2", count=30, interval=0.1)
        p.wait()
        ratio = success_ratio(csv_path)
        alerts = lab.alerts()
        return (ratio == 1.0 and not alerts,
                "success=%.0f%% alerts=%d" % (100 * (ratio or 0), len(alerts)))


def t2_flood_blocked(a):
    """T2  Connection flood is detected and the source is blocked by an SDN drop rule."""
    with Lab(a.ryu, "ids", out_dir=a.path("T2")) as lab:
        p, summ = lab.run_attacker(lab.h4, "h4", mode="flood", rate=200, duration=5)
        p.wait()
        time.sleep(1.5)
        alerts = lab.alerts(H4)
        rule = lab.has_drop_rule(H4)
        s = read_json(summ) or {}
        ok = bool(alerts) and alerts[0]["kind"] == "syn_flood" and rule \
            and s.get("cutoff_s") is not None and s["cutoff_s"] < 3.0
        return ok, "alert=%s drop_rule=%s attacker_cutoff=%ss detection_ms=%s" % (
            alerts[0]["kind"] if alerts else None, rule, s.get("cutoff_s"),
            alerts[0]["detection_ms"] if alerts else None)


def t3_port_scan_blocked(a):
    """T3  Port scan is detected and blocked."""
    with Lab(a.ryu, "ids", out_dir=a.path("T3")) as lab:
        p, summ = lab.run_attacker(lab.h4, "h4", mode="scan", ports="1-200", delay=0.01, timeout=0.1)
        p.wait()
        alerts = lab.alerts(H4)
        rule = lab.has_drop_rule(H4)
        s = read_json(summ) or {}
        ok = bool(alerts) and alerts[0]["kind"] == "port_scan" and rule \
            and s.get("reached", 999) < 60
        return ok, "alert=%s drop_rule=%s ports_that_reached_host=%s/200" % (
            alerts[0]["kind"] if alerts else None, rule, s.get("reached"))


def t4_benign_unaffected(a):
    """T4  Benign clients keep working while the attacker is attacking and blocked."""
    with Lab(a.ryu, "ids", out_dir=a.path("T4")) as lab:
        t0 = time.time()
        pc, csv_path = lab.run_client(lab.h2, "h2", duration=10, interval=0.2)
        time.sleep(2)
        pa, _ = lab.run_attacker(lab.h4, "h4", mode="flood", rate=200, duration=5)
        pa.wait()
        pc.wait()
        ratio = success_ratio(csv_path)
        bad = lab.alerts(H2)
        return (ratio is not None and ratio >= 0.95 and not bad,
                "h2 success=%.1f%% false_alerts_on_h2=%d" % (100 * (ratio or 0), len(bad)))


def t5_block_expires(a):
    """T5  The DROP rule expires (hard timeout) and the host can connect again."""
    with Lab(a.ryu, "ids", env={"BLOCK_TIMEOUT": 8}, out_dir=a.path("T5")) as lab:
        p, _ = lab.run_attacker(lab.h4, "h4", mode="flood", rate=200, duration=3)
        p.wait()
        blocked = lab.wait_for(lambda: lab.has_drop_rule(H4), 3)
        removed = lab.wait_for(lambda: any(e["type"] == "block_removed" and e["ip"] == H4
                                           for e in lab.events()), 15)
        pc, csv_path = lab.run_client(lab.h4, "h4", count=5, interval=0.1)
        pc.wait()
        ratio = success_ratio(csv_path)
        return (blocked and removed and ratio == 1.0,
                "blocked=%s expired=%s reconnect_success=%.0f%%" % (blocked, removed, 100 * (ratio or 0)))


def t6_no_false_positive_on_small_burst(a):
    """T6  A legitimate short burst (15 connections in < 1 s) is NOT flagged."""
    with Lab(a.ryu, "ids", out_dir=a.path("T6")) as lab:
        p, csv_path = lab.run_client(lab.h3, "h3", count=15, interval=0.02)
        p.wait()
        time.sleep(1)
        alerts = lab.alerts(H3)
        ratio = success_ratio(csv_path)
        return (not alerts and ratio == 1.0,
                "alerts=%d success=%.0f%%" % (len(alerts), 100 * (ratio or 0)))


def t7_two_attackers(a):
    """T7  Two simultaneous attackers are both blocked; the benign client is unaffected."""
    with Lab(a.ryu, "ids", out_dir=a.path("T7")) as lab:
        pc, csv_path = lab.run_client(lab.h2, "h2", duration=10, interval=0.2)
        time.sleep(2)
        p4, _ = lab.run_attacker(lab.h4, "h4", mode="flood", rate=150, duration=4)
        p3, _ = lab.run_attacker(lab.h3, "h3", mode="scan", ports="1-200", delay=0.01, timeout=0.1)
        # check while the 60 s blocks are still active (not after the attacks end)
        r4 = r3 = False
        lab.wait_for(lambda: lab.has_drop_rule(H4) and lab.has_drop_rule(H3), 8)
        r4, r3 = lab.has_drop_rule(H4), lab.has_drop_rule(H3)
        got4 = bool(lab.alerts(H4))
        got3 = bool(lab.alerts(H3))
        p4.wait()
        pc.wait()
        p3.terminate()
        ratio = success_ratio(csv_path)
        return (got4 and got3 and r4 and r3 and (ratio or 0) >= 0.95,
                "h4: alert=%s rule=%s | h3: alert=%s rule=%s | h2 success=%.1f%%" % (
                    got4, r4, got3, r3, 100 * (ratio or 0)))


def t8_slow_scan_evasion(a):
    """T8  (Limitation study) slow scan: evades the 5 s window, caught by a 30 s window."""
    res = {}
    for label, env in (("5s_window", {}), ("30s_window", {"PORT_WINDOW": 30})):
        with Lab(a.ryu, "ids", env=env, out_dir=a.path("T8_" + label)) as lab:
            p, _ = lab.run_attacker(lab.h4, "h4", mode="scan", ports="1000-1019", delay=1.0)
            p.wait()
            time.sleep(1)
            res[label] = bool(lab.alerts(H4))
    ok = (res["5s_window"] is False) and (res["30s_window"] is True)
    return ok, "detected with 5s window=%s, with 30s window=%s (expected False/True)" % (
        res["5s_window"], res["30s_window"])


TESTS = [("T1", t1_normal_traffic), ("T2", t2_flood_blocked), ("T3", t3_port_scan_blocked),
         ("T4", t4_benign_unaffected), ("T5", t5_block_expires),
         ("T6", t6_no_false_positive_on_small_burst), ("T7", t7_two_attackers),
         ("T8", t8_slow_scan_evasion)]


def main():
    require_root()
    ap = argparse.ArgumentParser()
    ap.add_argument("--ryu", required=True, help="full path of ryu-manager (inside your venv)")
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "tests"))
    ap.add_argument("--only", nargs="*", help="run only these test ids, e.g. T2 T3")
    a = ap.parse_args()
    a.path = lambda name: os.path.join(a.out, name)
    os.makedirs(a.out, exist_ok=True)

    report = []
    for tid, fn in TESTS:
        if a.only and tid not in a.only:
            continue
        print("\n=== %s" % fn.__doc__.strip(), flush=True)
        try:
            ok, details = fn(a)
        except Exception as exc:                       # keep going if one test crashes
            ok, details = False, "EXCEPTION: %r" % exc
        print("    %s  %s" % ("PASS" if ok else "FAIL", details), flush=True)
        report.append({"id": tid, "name": fn.__doc__.strip(), "passed": ok, "details": details})

    with open(os.path.join(a.out, "test_report.json"), "w") as f:
        json.dump(report, f, indent=2)
    print("\n%-4s %-6s %s" % ("ID", "RESULT", "DETAILS"))
    for r in report:
        print("%-4s %-6s %s" % (r["id"], "PASS" if r["passed"] else "FAIL", r["details"]))
    print("\nSaved: %s" % os.path.join(a.out, "test_report.json"))
    return 0 if all(r["passed"] for r in report) else 1


if __name__ == "__main__":
    sys.exit(main())
