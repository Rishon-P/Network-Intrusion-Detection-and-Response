# Demo 2 – Protecting a web service: HTTP flood detection and response

Second demonstration of the **Network Intrusion Detection and Response** project (TCP, SDN, Mininet, Ryu).
Demo 1 used a plain TCP service. **Demo 2 uses real HTTP/1.1**, so the same SDN IDS is shown protecting a website.

Related files: [`COMMANDS2.md`](COMMANDS2.md) (every command, with explanations) ·
[`docs/HTTP_FEATURE_GUIDE.md`](docs/HTTP_FEATURE_GUIDE.md) (full explanation of this feature) · [`README.md`](README.md) (whole project)

---

## 1. What this demo shows

| Step | What happens |
|---|---|
| 1 | h1 runs a small **web server** (routes `/`, `/login`, `/status`; status codes 200, 400, 404, 405). |
| 2 | h2 behaves like a **browser**: a normal `GET` request about 5 times per second. |
| 3 | h4 launches an **HTTP login flood**: 200 `GET /login?user=admin&pw=guess` requests per second for 5 seconds. |
| 4 | The Ryu controller counts new connections per source, detects the flood after 30 connections, and installs an OpenFlow **DROP rule** for h4 (confirmed in about 1 ms). |
| 5 | h4 is cut off at the switch. h2 keeps receiving `200 OK` with no failures. |
| 6 | After 60 seconds the block expires automatically. |

## 2. What is new compared with Demo 1

| | Demo 1 (TCP) | Demo 2 (HTTP) |
|---|---|---|
| Server | custom text protocol (`ECHO`) | HTTP web server: `apps/server.py --protocol http` |
| Normal client | sends `ECHO` | browser-like `GET`: `apps/client.py --protocol http` |
| Attack | connection flood | HTTP login flood: `apps/attacker.py --mode http-flood` |
| IDS controller | – | **unchanged** |

**Why the controller did not change:** with `Connection: close`, every HTTP request opens a new TCP connection, which starts with a
SYN. The controller already counts new connections per source address, so the web flood is detected by its connection rate.

## 3. Architecture

```
 h2  normal browser  ----GET /------------\
                                           \
 h4  HTTP flood      ----GET /login?...----> s1 (Open vSwitch, OpenFlow 1.3) ----> h1  web server
     200 requests/s                         |
                                            | Packet-In for every new connection (SYN)
                                            v
                                   Ryu controller: counts new connections per source
                                   > 30 in 1 s  ->  Flow-Mod DROP (60 s)  +  Barrier Reply (response time)
                                            |
                                  events.jsonl -> live dashboard (http://127.0.0.1:8000)
```

## 4. How to run (short version)

Open three terminals in the project folder (details and explanations in `COMMANDS2.md`).

```bash
# Terminal 1 – controller
source ~/ryu-env/bin/activate && ryu-manager controller/ids_ryu.py
# Terminal 2 – dashboard (open http://127.0.0.1:8000)
source ~/ryu-env/bin/activate && python3 dashboard/dashboard.py
# Terminal 3 – network
sudo mn -c && sudo python3 topology/topo.py
```

At the `mininet>` prompt:

```text
pingall
h1 python3 apps/server.py --host 10.0.0.1 --protocol http --log results/server_log.csv &
h2 python3 apps/client.py --host 10.0.0.1 --protocol http --duration 600 --out results/h2.csv &
h4 python3 apps/attacker.py --host 10.0.0.1 --mode http-flood --rate 200 --duration 5
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep drop
h2 python3 apps/client.py --host 10.0.0.1 --protocol http --count 5
```

Or, after the first three commands, click **Run HTTP flood from h4** on the dashboard instead of the fourth command.

Clean up: `exit`, Ctrl+C in terminals 1 and 2, then `sudo mn -c`.

## 5. What you should see

| Where | Expected |
|---|---|
| Dashboard graph | h2 stays at about 5 new connections/s; h4 spikes and then drops to 0 |
| Dashboard alert log | "Connection flood" for 10.0.0.4, then a block |
| `dump-flows` | `priority=100,ip,nw_src=10.0.0.4 actions=drop` |
| Last client command | `"ok": 5, "failed": 0` |
| Wireshark (`s1-eth4`, filter `http.request`) | the `GET /login?user=admin&pw=guess` lines stop after the block |

## 6. Verified results

Automated tests, run in Mininet (`sudo python3 tests/run_tests.py --ryu $HOME/ryu-env/bin/ryu-manager --only T9 T10`):

| Test | What it checks | Result |
|---|---|---|
| T9 | Normal HTTP traffic is allowed and raises no alert | PASS – success 100%, alerts 0 |
| T10 | HTTP login flood is detected and blocked, a benign HTTP client is unaffected | PASS – `syn_flood` alert, drop rule installed, **30** attack requests reached the web server (about 1000 sent), h2 success 100%, 0 false alerts |

Additional checks: `python3 tests/test_http_app.py` (15/15 loopback checks of the HTTP server, client and attacker); the original
detector and controller tests still pass.

## 7. Limitations (stated openly)

* **Detection works at the TCP level, not the HTTP level.** The IDS counts connections and cannot read request contents.
* **Keep-alive floods are not detected:** thousands of requests over one connection create only one SYN. Our server and attacker use
  one request per connection, which is the case the rule covers.
* HTTP/2 (multiplexing) and HTTP/3 (UDP/QUIC) are outside this design; HTTPS content cannot be inspected by any packet-level IDS.
* Slowloris-style, low-rate (under 30 connections/s per source) and distributed floods are not detected.
* About 30 attack requests reach the server before the block (the price of the threshold).
* The web server is a minimal GET-only demo server; the HTTP performance experiment (`run_experiments.py --http`) is optional and
  has not been run, the T10 test is the evidence for this feature.

Possible improvements: per-flow packet/byte-rate rules from the flow statistics the controller already collects, aggregate
per-destination rate rules, a reverse proxy or web application firewall, escalating block times.

## 8. Files added or changed for this demo

| File | Change |
|---|---|
| `apps/server.py` | `--protocol http`: HTTP request parsing, routes, status codes, `Content-Length`, `Connection: close` |
| `apps/client.py` | `--protocol http`: browser-like GET client |
| `apps/attacker.py` | new `http-flood` mode |
| `tests/test_http_app.py` | 15 loopback checks (no Mininet) |
| `tests/run_tests.py` | tests T9 and T10 |
| `tests/lab.py`, `run_experiments.py`, `plot_results.py` | protocol option and HTTP experiment support |
| `topology/topo.py`, `dashboard/dashboard.py` | accept `http-flood`; new dashboard button |

**Safety note:** the attacker script must be used only inside your own Mininet lab (10.0.0.0/24) against your own server.
