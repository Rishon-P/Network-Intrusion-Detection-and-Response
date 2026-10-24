#!/usr/bin/env python3
"""
Controlled security-test traffic generator for the IDS project.

!! Use ONLY inside your own Mininet lab (10.0.0.0/24) against your own server. !!

Modes
-----
flood : open --rate full TCP connections per second to one port for --duration
        seconds and close each one immediately (a "connection flood", the
        socket-level analogue of a SYN flood).
scan  : controlled TCP connect() port scan of --ports (e.g. 1-200), one probe
        every --delay seconds. A tiny delay is a fast scan; a large delay is
        a slow, evasive scan.

Every probe is classified as
    open     TCP handshake completed
    refused  host answered with RST (closed port) -> traffic reached the host
    timeout  no answer at all -> packets were dropped on the way (blocked)
    error    anything else

A JSON summary is printed and (optionally) saved with --out. "cutoff_s" is the
time between the start of the attack and the last probe that still reached the
host: with the IDS active it is small, without it it is about the full duration.

Examples
--------
    python3 apps/attacker.py --host 10.0.0.1 --mode flood --rate 200 --duration 5
    python3 apps/attacker.py --host 10.0.0.1 --mode scan --ports 1-200 --delay 0.01
    python3 apps/attacker.py --host 10.0.0.1 --mode scan --ports 1000-1014 --delay 1.0
"""
import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor


def probe(host, port, timeout):
    """One TCP connection attempt. Returns (start_ts, result)."""
    ts = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return ts, "open"
    except ConnectionRefusedError:
        return ts, "refused"
    except socket.timeout:
        return ts, "timeout"
    except OSError:
        return ts, "error"
    finally:
        s.close()


def run_flood(host, port, rate, duration, timeout):
    results = []
    interval = 1.0 / rate
    workers = min(600, max(50, int(rate * timeout * 2)))
    t_next = time.monotonic()
    end = t_next + duration
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = []
        while t_next < end:
            wait = t_next - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            futs.append(ex.submit(probe, host, port, timeout))
            t_next += interval
        results = [f.result() for f in futs]
    return results


def run_scan(host, ports, delay, timeout):
    results = []
    for p in ports:
        results.append(probe(host, p, timeout))
        if delay > 0:
            time.sleep(delay)
    return results


def parse_ports(spec):
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return list(range(int(lo), int(hi) + 1))
    return [int(x) for x in spec.split(",")]


def main():
    ap = argparse.ArgumentParser(description="Controlled attack traffic (lab use only)")
    ap.add_argument("--host", default="10.0.0.1")
    ap.add_argument("--port", type=int, default=8080, help="target port for flood mode")
    ap.add_argument("--mode", choices=["flood", "scan"], required=True)
    ap.add_argument("--rate", type=float, default=100, help="flood: connections per second")
    ap.add_argument("--duration", type=float, default=5, help="flood: seconds")
    ap.add_argument("--ports", default="1-200", help="scan: range '1-200' or list '22,80,8080'")
    ap.add_argument("--delay", type=float, default=0.01, help="scan: seconds between probes")
    ap.add_argument("--timeout", type=float, default=0.5, help="per-probe connect timeout")
    ap.add_argument("--out", default=None, help="write JSON summary here")
    a = ap.parse_args()

    start = time.time()
    if a.mode == "flood":
        res = run_flood(a.host, a.port, a.rate, a.duration, a.timeout)
    else:
        res = run_scan(a.host, parse_ports(a.ports), a.delay, a.timeout)
    end = time.time()

    counts = {"open": 0, "refused": 0, "timeout": 0, "error": 0}
    reached_ts = []
    for ts, r in res:
        counts[r] += 1
        if r in ("open", "refused"):
            reached_ts.append(ts)
    summary = {
        "mode": a.mode, "target": a.host, "start_ts": start, "end_ts": end,
        "attempts": len(res), "reached": counts["open"] + counts["refused"],
        "cutoff_s": round(max(reached_ts) - start, 3) if reached_ts else None,
        "rate": a.rate if a.mode == "flood" else None,
        "delay": a.delay if a.mode == "scan" else None,
    }
    summary.update(counts)
    print(json.dumps(summary), flush=True)
    if a.out:
        with open(a.out, "w") as f:
            json.dump(summary, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
