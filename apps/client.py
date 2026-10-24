#!/usr/bin/env python3
"""
Benign TCP client for the IDS project.

Opens a new connection for every request (like a simple HTTP/1.0 client), sends
"ECHO <msg>" and measures the round-trip time. Results go to a CSV
(ts,seq,ok,rtt_ms) and a JSON summary is printed at the end.

Exit code is 0 only if every request succeeded.

Examples
--------
    # 30 seconds of normal traffic, about 5 requests per second
    python3 apps/client.py --host 10.0.0.1 --duration 30 --interval 0.2 --out results/h2.csv

    # exactly 20 requests
    python3 apps/client.py --host 10.0.0.1 --count 20
"""
import argparse
import json
import random
import socket
import sys
import time


def request(host, port, text, timeout):
    t0 = time.perf_counter()
    ok = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(("ECHO %s\n" % text).encode())
            ok = s.recv(1024).startswith(b"OK")
    except OSError:
        ok = False
    return ok, (time.perf_counter() - t0) * 1000.0


def percentile(values, p):
    if not values:
        return None
    v = sorted(values)
    k = min(len(v) - 1, int(round(p / 100.0 * (len(v) - 1))))
    return v[k]


def main():
    ap = argparse.ArgumentParser(description="Benign TCP client")
    ap.add_argument("--host", default="10.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--interval", type=float, default=0.2,
                    help="mean seconds between requests (randomised +-50%%)")
    ap.add_argument("--duration", type=float, default=None, help="run for N seconds")
    ap.add_argument("--count", type=int, default=None, help="send exactly N requests")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--out", default=None, help="CSV file for per-request results")
    ap.add_argument("--name", default="client")
    a = ap.parse_args()
    if a.duration is None and a.count is None:
        a.count = 10

    out = open(a.out, "w", buffering=1) if a.out else None
    if out:
        out.write("ts,seq,ok,rtt_ms\n")

    end = time.time() + a.duration if a.duration else None
    seq = 0
    oks, rtts = 0, []
    while True:
        if a.count is not None and seq >= a.count:
            break
        if end is not None and time.time() >= end:
            break
        seq += 1
        ts = time.time()
        ok, rtt = request(a.host, a.port, "%s-%d" % (a.name, seq), a.timeout)
        if ok:
            oks += 1
            rtts.append(rtt)
        if out:
            out.write("%.6f,%d,%d,%.3f\n" % (ts, seq, int(ok), rtt))
        time.sleep(a.interval * random.uniform(0.5, 1.5))

    summary = {"name": a.name, "sent": seq, "ok": oks, "failed": seq - oks,
               "avg_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
               "p95_ms": round(percentile(rtts, 95), 2) if rtts else None}
    print(json.dumps(summary), flush=True)
    return 0 if seq == oks else 1


if __name__ == "__main__":
    sys.exit(main())
