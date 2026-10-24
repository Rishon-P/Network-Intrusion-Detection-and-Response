#!/usr/bin/env python3
"""
TCP server (low-level sockets) = the service protected by the SDN IDS.

Design
------
* One acceptor thread calls accept() and puts connections in a bounded queue.
* A fixed pool of worker threads takes connections from the queue.
* Every connection costs --service-time seconds of worker time (a model of real
  per-connection work such as authentication). Capacity is therefore about
  workers / service-time connections per second. When a flood exceeds that,
  the queue fills, latency rises for everybody and new connections are
  rejected. This is what makes the damage of an attack measurable.

Application protocol (text, one command per line)
-------------------------------------------------
  PING          -> PONG
  ECHO <text>   -> OK <text>
  TIME          -> OK <epoch seconds>
  QUIT          -> BYE   (and the connection is closed)

Every accepted/rejected connection is appended to --log (CSV: ts,src_ip,event)
so the experiments can count how many attack connections reached the server.

Usage:
    python3 apps/server.py --host 10.0.0.1 --port 8080 --log results/server_log.csv
"""
import argparse
import queue
import socket
import sys
import threading
import time


class Server:
    def __init__(self, host, port, workers, service_time, queue_size, log_path):
        self.host = host
        self.port = port
        self.service_time = service_time
        self.workers = workers
        self.q = queue.Queue(maxsize=queue_size)
        self.stop = threading.Event()
        self.log_lock = threading.Lock()
        self.log = None
        if log_path:
            self.log = open(log_path, "w", buffering=1)
            self.log.write("ts,src_ip,event\n")
        self.stats = {"accepted": 0, "rejected": 0, "served": 0}

    def _log(self, src, event):
        if self.log:
            with self.log_lock:
                self.log.write("%.6f,%s,%s\n" % (time.time(), src, event))

    # ------------------------------------------------------------------
    def serve_forever(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(512)
        srv.settimeout(0.5)
        for _ in range(self.workers):
            threading.Thread(target=self.worker, daemon=True).start()
        print("[server] listening on %s:%d (workers=%d, service_time=%.3fs)"
              % (self.host, self.port, self.workers, self.service_time), flush=True)
        try:
            while not self.stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                try:
                    self.q.put_nowait((conn, addr))
                    self.stats["accepted"] += 1
                    self._log(addr[0], "accepted")
                except queue.Full:            # overload: shed the connection
                    self.stats["rejected"] += 1
                    self._log(addr[0], "rejected")
                    conn.close()
        except KeyboardInterrupt:
            pass
        finally:
            srv.close()
            print("[server] stopped, stats=%s" % self.stats, flush=True)

    # ------------------------------------------------------------------
    def worker(self):
        while not self.stop.is_set():
            try:
                conn, addr = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.handle(conn)
            except (OSError, ValueError):
                pass
            finally:
                conn.close()

    def handle(self, conn):
        time.sleep(self.service_time)         # modelled per-connection work
        conn.settimeout(2.0)
        buf = b""
        for _ in range(20):                    # at most 20 requests per connection
            while b"\n" not in buf:
                chunk = conn.recv(1024)
                if not chunk:
                    return                     # client closed
                buf += chunk
                if len(buf) > 4096:
                    return
            line, _, buf = buf.partition(b"\n")
            cmd = line.decode("utf-8", "replace").strip()
            reply, close = self.respond(cmd)
            conn.sendall((reply + "\n").encode())
            self.stats["served"] += 1
            if close:
                return

    @staticmethod
    def respond(cmd):
        up = cmd.upper()
        if up == "PING":
            return "PONG", False
        if up.startswith("ECHO"):
            return "OK " + cmd[4:].strip(), False
        if up == "TIME":
            return "OK %.3f" % time.time(), False
        if up == "QUIT":
            return "BYE", True
        return "ERR unknown command", False


def main():
    ap = argparse.ArgumentParser(description="Threaded TCP server (IDS project)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--workers", type=int, default=4, help="worker threads")
    ap.add_argument("--service-time", type=float, default=0.03,
                    help="seconds of work per connection (capacity ~ workers/service-time per second)")
    ap.add_argument("--queue-size", type=int, default=200, help="pending-connection queue length")
    ap.add_argument("--log", default=None, help="CSV log of accepted/rejected connections")
    a = ap.parse_args()
    Server(a.host, a.port, a.workers, a.service_time, a.queue_size, a.log).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
