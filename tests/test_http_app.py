#!/usr/bin/env python3
"""
Loopback test of the HTTP mode of the TCP apps (no Mininet, no Ryu needed).

Starts apps/server.py --protocol http on 127.0.0.1, then checks:
  * every route and error code of the server (200, 404, 405, 400),
  * apps/client.py --protocol http works and measures latency,
  * apps/attacker.py --mode http-flood really sends HTTP requests and is
    logged by the server as many connections from one source,
  * the default tcp mode still works (nothing was broken).

    python3 tests/test_http_app.py
"""
import json
import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
HTTP_PORT, TCP_PORT = 18081, 18082
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print("  [%s] %s %s" % ("PASS" if cond else "FAIL", name, detail))


def raw_http(port, request, timeout=3):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(request)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return data


def start_server(port, protocol, log):
    p = subprocess.Popen([PY, os.path.join(ROOT, "apps", "server.py"), "--host", "127.0.0.1",
                          "--port", str(port), "--protocol", protocol, "--service-time", "0.01",
                          "--workers", "4", "--log", log],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return p
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("server did not start")


def main():
    tmp = os.path.join(ROOT, "results", "_http_selftest")
    os.makedirs(tmp, exist_ok=True)
    http_log, tcp_log = os.path.join(tmp, "http.csv"), os.path.join(tmp, "tcp.csv")
    srv_http = start_server(HTTP_PORT, "http", http_log)
    srv_tcp = start_server(TCP_PORT, "tcp", tcp_log)
    try:
        print("HTTP server routes")
        r = raw_http(HTTP_PORT, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        check("GET / -> 200", r.startswith(b"HTTP/1.1 200 OK") and b"Campus portal" in r)
        check("Content-Length matches body",
              int(r.split(b"Content-Length: ")[1].split(b"\r\n")[0]) == len(r.split(b"\r\n\r\n", 1)[1]))
        r = raw_http(HTTP_PORT, b"GET /login?user=a&pw=b HTTP/1.1\r\nHost: x\r\n\r\n")
        check("GET /login?... -> 200 (query string ignored for routing)", r.startswith(b"HTTP/1.1 200"))
        r = raw_http(HTTP_PORT, b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n")
        check("GET /status -> 200 JSON", b'"status": "up"' in r)
        r = raw_http(HTTP_PORT, b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
        check("unknown path -> 404", r.startswith(b"HTTP/1.1 404"))
        r = raw_http(HTTP_PORT, b"POST / HTTP/1.1\r\nHost: x\r\n\r\n")
        check("POST -> 405", r.startswith(b"HTTP/1.1 405"))
        r = raw_http(HTTP_PORT, b"HELLO\r\n\r\n")
        check("garbage -> 400", r.startswith(b"HTTP/1.1 400"))
        r = raw_http(HTTP_PORT, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        check("connection is closed after the response (no keep-alive)", r.endswith(b"</h1>"))

        print("HTTP client")
        out = subprocess.run([PY, os.path.join(ROOT, "apps", "client.py"), "--protocol", "http",
                              "--host", "127.0.0.1", "--port", str(HTTP_PORT), "--count", "5",
                              "--interval", "0.02"], capture_output=True, text=True)
        s = json.loads(out.stdout.strip().splitlines()[-1])
        check("5 of 5 HTTP requests succeed", s["ok"] == 5 and s["failed"] == 0 and out.returncode == 0, str(s))
        out = subprocess.run([PY, os.path.join(ROOT, "apps", "client.py"), "--protocol", "http",
                              "--host", "127.0.0.1", "--port", str(TCP_PORT), "--count", "2",
                              "--interval", "0.02", "--timeout", "1"], capture_output=True, text=True)
        check("http client against a tcp-mode server fails cleanly (exit code 1)", out.returncode == 1)

        print("HTTP flood attacker")
        before = len(open(http_log).read().splitlines())
        out = subprocess.run([PY, os.path.join(ROOT, "apps", "attacker.py"), "--mode", "http-flood",
                              "--host", "127.0.0.1", "--port", str(HTTP_PORT), "--rate", "100",
                              "--duration", "2"], capture_output=True, text=True)
        s = json.loads(out.stdout.strip().splitlines()[-1])
        time.sleep(0.5)
        rows = open(http_log).read().splitlines()[before:]
        check("attacker reports about rate x duration attempts", 190 <= s["attempts"] <= 210, "attempts=%s" % s["attempts"])
        check("all attempts reached the server", s["open"] == s["attempts"], "open=%s" % s["open"])
        check("server log shows the flood as many connections from 127.0.0.1",
              len([r for r in rows if r.split(",")[1] == "127.0.0.1"]) >= 190, "%d log rows" % len(rows))

        print("Original tcp mode still works")
        out = subprocess.run([PY, os.path.join(ROOT, "apps", "client.py"), "--host", "127.0.0.1",
                              "--port", str(TCP_PORT), "--count", "3", "--interval", "0.02"],
                             capture_output=True, text=True)
        s = json.loads(out.stdout.strip().splitlines()[-1])
        check("tcp client against tcp server: 3 of 3", s["ok"] == 3, str(s))
        out = subprocess.run([PY, os.path.join(ROOT, "apps", "attacker.py"), "--mode", "flood",
                              "--host", "127.0.0.1", "--port", str(TCP_PORT), "--rate", "50", "--duration", "1"],
                             capture_output=True, text=True)
        s = json.loads(out.stdout.strip().splitlines()[-1])
        check("tcp flood mode unchanged", 45 <= s["attempts"] <= 55, "attempts=%s" % s["attempts"])
    finally:
        for p in (srv_http, srv_tcp):
            p.terminate()
        for f in os.listdir(tmp):
            os.remove(os.path.join(tmp, f))
        os.rmdir(tmp)
    print("\n%d/%d checks passed" % (sum(CHECKS), len(CHECKS)))
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
