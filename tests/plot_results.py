#!/usr/bin/env python3
"""
Turn results/experiments/summary.csv into graphs (PNG) and a Markdown table.

    python3 tests/plot_results.py
    (needs matplotlib:  pip install matplotlib)
"""
import csv
import os
import statistics
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXP = os.path.join(ROOT, "results", "experiments")
FIG = os.path.join(ROOT, "results", "figures")
MODES = ["baseline", "static", "ids"]
COLORS = {"baseline": "#d1495b", "static": "#edae49", "ids": "#2a9d8f"}
LABELS = {"baseline": "No IDS (baseline)", "static": "Static / delayed block", "ids": "Dynamic SDN IDS"}


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def load():
    with open(os.path.join(EXP, "summary.csv")) as f:
        return list(csv.DictReader(f))


def agg(rows, mode, attack, rate, col):
    vals = [num(r[col]) for r in rows
            if r["mode"] == mode and r["attack"] == attack and (r["rate"] or "") == (str(rate) if rate else "")]
    vals = [v for v in vals if v is not None]
    if not vals:
        return None, None
    return statistics.mean(vals), (statistics.stdev(vals) if len(vals) > 1 else 0.0)


def grouped_bars(rows, rates, col, title, ylabel, fname, modes=MODES, log=False, ylim=None,
                 legend_loc="best", ncol=1):
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    width = 0.8 / len(modes)
    for i, m in enumerate(modes):
        means, errs = [], []
        for r in rates:
            mu, sd = agg(rows, m, "flood", r, col)
            means.append(mu or 0)
            errs.append(sd or 0)
        xs = [k + i * width for k in range(len(rates))]
        ax.bar(xs, means, width, yerr=errs, capsize=3, label=LABELS[m], color=COLORS[m])
    ax.set_xticks([k + width * (len(modes) - 1) / 2 for k in range(len(rates))])
    ax.set_xticklabels(["%d/s" % r for r in rates])
    ax.set_xlabel("Attack rate (connections per second)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if log:
        ax.set_yscale("log")
    if ylim:
        ax.set_ylim(*ylim)
    ax.legend(frameon=False, loc=legend_loc, ncol=ncol)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, fname), dpi=160)
    plt.close(fig)


def main():
    if not os.path.exists(os.path.join(EXP, "summary.csv")):
        sys.exit("No summary.csv yet. Run tests/run_experiments.py first.")
    os.makedirs(FIG, exist_ok=True)
    rows = load()
    rates = sorted({int(r["rate"]) for r in rows if r["attack"] == "flood" and r["rate"]})

    grouped_bars(rows, rates, "server_conns_from_attacker",
                 "Attack connections that reached the server", "connections (count)", "attack_conns_at_server.png")
    grouped_bars(rows, rates, "benign_rtt_during_ms",
                 "Benign client latency during the attack", "mean RTT (ms)", "benign_latency.png")
    grouped_bars(rows, rates, "benign_success_during_pct",
                 "Benign request success during the attack", "success (%)", "benign_success.png",
                 ylim=(0, 125), legend_loc="upper center", ncol=3)
    grouped_bars(rows, rates, "response_ms",
                 "Time from detection to rule installed (confirmed by barrier)", "ms (log scale)", "response_time.png",
                 modes=["static", "ids"], log=True, ylim=(0.1, 60000), legend_loc="upper right")
    grouped_bars(rows, rates, "detection_ms",
                 "Detection time (first connection of the attack to alert)", "ms", "detection_time.png",
                 modes=["ids"])

    # Markdown table for the report
    lines = ["| Attack | Mode | Detected | Detection (ms) | Response (ms) | Attack conns at server | "
             "Attack probes reaching host | Benign RTT during (ms) | Benign success (%) | False positives |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    conds = [("flood", r) for r in rates] + ([("scan", None)] if any(r["attack"] == "scan" for r in rows) else [])
    for attack, rate in conds:
        for m in MODES:
            cells = []
            for col in ["detected", "detection_ms", "response_ms", "server_conns_from_attacker",
                        "attack_reached_host", "benign_rtt_during_ms", "benign_success_during_pct", "false_positives"]:
                mu, _ = agg(rows, m, attack, rate, col)
                cells.append("-" if mu is None else ("%.1f" % mu))
            name = "flood %d/s" % rate if attack == "flood" else "port scan"
            lines.append("| %s | %s | %s |" % (name, LABELS[m], " | ".join(cells)))
    with open(os.path.join(FIG, "results_table.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("Figures and table written to %s" % FIG)


if __name__ == "__main__":
    main()
