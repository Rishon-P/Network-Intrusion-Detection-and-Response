#!/usr/bin/env python3
"""
Performance evaluation: proposed dynamic SDN IDS vs. baselines.

Modes compared
    baseline : plain learning switch, no detection (what happens without the IDS)
    static   : alert is raised but the block is applied only after STATIC_DELAY s
               (emulates a human operator / static manual response)
    ids      : proposed approach, DROP rule installed immediately on detection

Conditions
    flood at several attack rates, and a fast port scan.
    Each (mode, condition) is repeated --reps times.

Every trial: h2 and h3 send benign requests for --total seconds; the attacker
(h4) starts after --attack-start seconds.

Output
    results/experiments/summary.csv        one row per trial
    results/experiments/trials/<tag>/...   raw logs of every trial

    sudo python3 tests/run_experiments.py --ryu /home/<you>/ryu-env/bin/ryu-manager
    sudo python3 tests/run_experiments.py --ryu ... --reps 1 --rates 100 --modes baseline ids   (quick)
"""
import argparse
import csv
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import (ATTACKER_IP, ROOT, Lab, mean, percentile, read_csv,  # noqa: E402
                 read_events, read_json, require_root)

COLUMNS = ["mode", "attack", "rate", "rep",
           "detected", "detection_ms", "detect_after_attack_start_ms",
           "response_ms", "install_ms",
           "attack_attempts", "attack_reached_host", "attacker_cutoff_s",
           "server_conns_from_attacker", "drop_rule_packets",
           "benign_rtt_before_ms", "benign_rtt_during_ms", "benign_p95_during_ms",
           "benign_success_during_pct", "false_positives"]


def analyze(lab, mode, attack, rate, rep, att_json, clients, t_attack_start):
    ev = lab.events()
    att = read_json(att_json) or {}
    a_start = att.get("start_ts", t_attack_start)
    a_end = att.get("end_ts", a_start)

    alerts = [e for e in ev if e["type"] == "alert" and e["ip"] == ATTACKER_IP]
    fps = [e for e in ev if e["type"] == "alert" and e["ip"] != ATTACKER_IP]
    conf = [e for e in ev if e["type"] == "block_confirmed" and e["ip"] == ATTACKER_IP]

    drops = 0
    for e in ev:
        if e["type"] == "flow_stats":
            for r in e.get("drop_rules", []):
                if r["ip"] == ATTACKER_IP:
                    drops = max(drops, r["packets"])
        if e["type"] == "block_removed" and e["ip"] == ATTACKER_IP:
            drops = max(drops, e["dropped_packets"])

    before, during, ok_during, n_during = [], [], 0, 0
    for _, csv_path in clients:
        for r in read_csv(csv_path):
            ts, ok, rtt = float(r["ts"]), int(r["ok"]), float(r["rtt_ms"])
            if ts < a_start - 0.2:
                if ok:
                    before.append(rtt)
            elif ts <= a_end + 1.0:
                n_during += 1
                if ok:
                    ok_during += 1
                    during.append(rtt)

    server_conns = len(lab.server_rows(ATTACKER_IP))
    rnd = lambda v: None if v is None else round(v, 2)
    return {
        "mode": mode, "attack": attack, "rate": rate or "", "rep": rep,
        "detected": int(bool(alerts)),
        "detection_ms": rnd(alerts[0]["detection_ms"]) if alerts else "",
        "detect_after_attack_start_ms": rnd((alerts[0]["ts"] - a_start) * 1000) if alerts else "",
        "response_ms": rnd(conf[0]["response_ms"]) if conf else "",
        "install_ms": rnd(conf[0]["install_ms"]) if conf else "",
        "attack_attempts": att.get("attempts", ""),
        "attack_reached_host": att.get("reached", ""),
        "attacker_cutoff_s": att.get("cutoff_s", ""),
        "server_conns_from_attacker": server_conns,
        "drop_rule_packets": drops,
        "benign_rtt_before_ms": rnd(mean(before)),
        "benign_rtt_during_ms": rnd(mean(during)),
        "benign_p95_during_ms": rnd(percentile(during, 95)),
        "benign_success_during_pct": rnd(100.0 * ok_during / n_during) if n_during else "",
        "false_positives": len(fps),
    }


def run_trial(a, mode, attack, rate, rep):
    tag = "%s_%s%s_r%d" % (mode, attack, rate or "", rep)
    out = os.path.join(a.out, "trials", tag)
    env = {"BLOCK_TIMEOUT": 60, "STATIC_DELAY": a.static_delay}
    with Lab(a.ryu, mode, env=env, out_dir=out) as lab:
        t0 = time.time()
        clients = [lab.run_client(lab.h2, "h2", duration=a.total, interval=0.2),
                   lab.run_client(lab.h3, "h3", duration=a.total, interval=0.2)]
        time.sleep(a.attack_start)
        t_attack = time.time()
        if attack == "flood":
            p, att_json = lab.run_attacker(lab.h4, "h4", mode="flood", rate=rate,
                                           duration=a.attack_duration)
        else:
            p, att_json = lab.run_attacker(lab.h4, "h4", mode="scan", ports="1-200", delay=0.01, timeout=0.1)
        p.wait()
        for c, _ in clients:
            c.wait()
        time.sleep(2.0)                                # let the last stats arrive
        return analyze(lab, mode, attack, rate, rep, att_json, clients, t_attack)


def main():
    require_root()
    ap = argparse.ArgumentParser()
    ap.add_argument("--ryu", required=True)
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "experiments"))
    ap.add_argument("--modes", nargs="+", default=["baseline", "static", "ids"])
    ap.add_argument("--rates", nargs="+", type=int, default=[50, 100, 200, 400])
    ap.add_argument("--scan", action="store_true", default=True, help="also run the port-scan condition")
    ap.add_argument("--no-scan", dest="scan", action="store_false")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--total", type=float, default=20, help="seconds of benign traffic per trial")
    ap.add_argument("--attack-start", type=float, default=5)
    ap.add_argument("--attack-duration", type=float, default=8)
    ap.add_argument("--static-delay", type=float, default=5)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    conditions = [("flood", r) for r in a.rates]
    if a.scan:
        conditions.append(("scan", None))

    summary_path = os.path.join(a.out, "summary.csv")
    new_file = not os.path.exists(summary_path)
    total_trials = len(a.modes) * len(conditions) * a.reps
    n = 0
    with open(summary_path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        if new_file:
            w.writeheader()
        for attack, rate in conditions:
            for mode in a.modes:
                for rep in range(1, a.reps + 1):
                    n += 1
                    print("[%d/%d] mode=%s attack=%s rate=%s rep=%d" % (
                        n, total_trials, mode, attack, rate, rep), flush=True)
                    try:
                        row = run_trial(a, mode, attack, rate, rep)
                    except Exception as exc:
                        print("   trial failed: %r" % exc, flush=True)
                        continue
                    w.writerow(row)
                    f.flush()
                    print("   detected=%s detection_ms=%s response_ms=%s attack_conns_at_server=%s "
                          "benign_rtt_during=%s benign_success=%s%%" % (
                              row["detected"], row["detection_ms"], row["response_ms"],
                              row["server_conns_from_attacker"], row["benign_rtt_during_ms"],
                              row["benign_success_during_pct"]), flush=True)
    print("\nDone. Summary: %s" % summary_path)
    print("Make the graphs with:  python3 tests/plot_results.py")


if __name__ == "__main__":
    sys.exit(main())
