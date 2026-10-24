# SDN-Based Network Intrusion Detection and Response

**Computer Networks (UE25CS243A) – Jackfruit Mini Project #25: Network Intrusion Detection and Response (TCP)**


An intrusion-detection prototype that analyses TCP socket traffic inside a Mininet network, detects
predefined abnormal behaviour (connection floods and port scans) and **responds dynamically by
modifying SDN forwarding rules**: the OpenFlow controller installs a DROP rule for the offending source
within about 1 ms of detection.

For copy-ready setup, startup, traffic-generation, log-inspection, and cleanup commands, see the [NIDR Command Reference](COMMANDS.md).

---

## Table of contents
1. [What the project does](#1-what-the-project-does)
2. [Architecture and message flow](#2-architecture-and-message-flow)
3. [Repository layout](#3-repository-layout)
4. [Setup (Ubuntu 20.04 / 22.04)](#4-setup-ubuntu-2004--2204)
5. [Quick checks without Mininet](#5-quick-checks-without-mininet)
6. [Running the live demo](#6-running-the-live-demo)
7. [Automated test cases](#7-automated-test-cases)
8. [Performance evaluation](#8-performance-evaluation)
9. [Configuration](#9-configuration)
10. [Limitations](#10-limitations)
11. [Troubleshooting](#11-troubleshooting)
12. [Safety note](#12-safety-note)

---

## 1. What the project does

| Assignment requirement | Where it is implemented |
|---|---|
| Generate controlled TCP security-test traffic | `apps/attacker.py`, `apps/client.py` |
| Monitor connection rates | `controller/detector.py` (per-source sliding window) |
| Collect flow statistics | `controller/ids_ryu.py` polls `OFPFlowStatsRequest` every second |
| Define intrusion-detection rules | Flood: more than 30 new connections from one source in 1 s. Port scan: more than 10 distinct destination ports in 5 s |
| Detect abnormal connection behaviour | Packet-in handler in `controller/ids_ryu.py` |
| Simulate controlled scanning | `apps/attacker.py --mode scan` |
| Dynamically block suspicious sources | OpenFlow DROP flow (priority 100, 60 s hard timeout) |
| Measure detection and response time | `detection_ms` and `response_ms` in the event log (response time is confirmed by an OpenFlow barrier reply) |

## 2. Architecture and message flow

```
           Mininet network (one Open vSwitch s1, OpenFlow 1.3)

   h1 10.0.0.1  TCP server        (apps/server.py)  ---+
   h2-h3         benign clients                      ---+
   h4-h10        selectable dashboard senders        ---+---- s1 ===== Ryu controller (controller/ids_ryu.py)
                                                                      +--> results/events.jsonl --> dashboard (browser)
```

1. A host sends a TCP SYN. The switch has no flow for this connection, so it sends a **packet-in** to Ryu.
2. Ryu counts the SYN per source IP (`controller/detector.py`). Normal traffic gets a per-connection flow
   (priority 10, idle timeout 5 s) and is forwarded. Because every new connection has no matching flow,
   the controller sees **every** connection attempt.
3. When a rule is exceeded, Ryu logs an **alert** and installs `match ipv4_src=<ip> -> DROP`
   (priority 100, hard timeout 60 s), then sends an OpenFlow **barrier request**. The barrier reply proves
   the rule is active and gives the response time.
4. The switch now drops all packets from that source; they never reach the controller or the server.
5. Every second Ryu collects flow statistics. All events are written to `results/events.jsonl`, which the dashboard displays live.
6. After 60 s the rule expires (`block_removed` event). If the source misbehaves again it is detected again.

### Detection rules (defaults)
| Behaviour | Rule |
|---|---|
| Connection flood | more than `RATE_THRESHOLD` = 30 new connections from one source within `RATE_WINDOW` = 1 s |
| Port scan | more than `PORT_THRESHOLD` = 10 distinct destination ports from one source within `PORT_WINDOW` = 5 s |

### Modes (used in the evaluation)
| Mode (`IDS_MODE`) | Meaning |
|---|---|
| `baseline` | plain learning switch, no detection |
| `static` | alert raised, but the block is applied only after 5 s (emulates a slow manual response) |
| `ids` | **proposed approach**: block immediately on detection |

## 3. Repository layout

```
apps/        server.py  client.py  attacker.py      TCP socket application and test traffic
controller/  ids_ryu.py  detector.py                Ryu OpenFlow 1.3 controller and detection rules
topology/    topo.py                                Mininet topology
dashboard/   dashboard.py                           live web dashboard (FastAPI + WebSocket)
tests/       test_detector.py                       unit tests of the rules (no Mininet)
             test_controller_offline.py             controller test with a fake switch (Ryu only)
             run_tests.py                           8 functional test cases in Mininet
             run_experiments.py  plot_results.py    performance evaluation and graphs
             lab.py                                 helper that starts controller, network and server
docs/        legacy_simulation_v5.py                first software-only simulation (reference only)
             screenshots/                           screenshots used in the report
results/     generated logs, CSVs and figures
```

## 4. Setup (Ubuntu 20.04 / 22.04)

### 4.1 System packages
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-pip python3-matplotlib git
sudo apt install -y software-properties-common build-essential
sudo add-apt-repository ppa:deadsnakes/ppa -y && sudo apt update
sudo apt install -y python3.9 python3.9-venv python3.9-dev
```

### 4.2 Ryu in its own Python 3.9 virtual environment
Ryu 4.34 does not build or run on newer Python versions, so it lives in a separate environment.
The dashboard dependencies are installed in the same environment.

```bash
python3.9 -m venv ~/ryu-env
source ~/ryu-env/bin/activate
pip install --upgrade pip wheel
pip install "setuptools<58" pbr
PBR_VERSION=4.34 pip install --no-build-isolation eventlet==0.30.2 "ryu==4.34"
pip install fastapi "uvicorn[standard]"
ryu-manager --version          # must print: ryu-manager 4.34
deactivate
```
Notes:
* `--no-build-isolation` and `setuptools<58` are required, otherwise Ryu's build script fails.
* `PBR_VERSION=4.34` is required because the downloaded package carries no git metadata.
* `uvicorn[standard]` provides the WebSocket support the dashboard needs.
* A harmless `SyntaxWarning: "is not" with a literal` is printed by Ryu; ignore it.

### 4.3 Get the code
```bash
git clone <repository-url>
cd <repository-folder>
sudo chown -R $USER:$USER .     # files created by sudo runs belong to root otherwise
```

## 5. Quick checks without Mininet

```bash
python3 tests/test_detector.py                    # 8 unit tests of the detection rules

source ~/ryu-env/bin/activate
python3 tests/test_controller_offline.py          # 19 checks against a fake OpenFlow switch
deactivate
```
Expected: `OK` for the first and `19/19 checks passed` for the second.

## 6. Running the live demo

Open three terminals in the project folder.

**Clean start**
```bash
sudo mn -c
pkill -f ryu-manager
```

**Terminal 1 – controller**
```bash
source ~/ryu-env/bin/activate
ryu-manager controller/ids_ryu.py
```

**Terminal 2 – dashboard** (open http://127.0.0.1:8000)
```bash
source ~/ryu-env/bin/activate
python3 dashboard/dashboard.py
```

**Terminal 3 – network** (start this after the controller)
```bash
sudo python3 topology/topo.py
```
When the topology starts, it exposes a loopback-only action endpoint for the dashboard. The topology includes sender hosts `h2`–`h10`; **+ Add sender** reveals them in the dashboard one at a time. Choose a visible sender, then launch the fixed flood or scan workload from that real Mininet host to `h1`. Ryu still performs the detection and installs any block.

At the `mininet>` prompt (type only the command, not the prompt), start the TCP service:

```text
h1 python3 apps/server.py --host 10.0.0.1 --log results/server_log.csv &
```

Open the dashboard at http://127.0.0.1:8000. Its sender controls become available when Mininet is running. The flood uses 200 connections/s for 5 s; the scan probes ports 1–200. The generated TCP traffic crosses `s1`, so alerts and blocks shown in the dashboard come from the Ryu controller. You can also use the Mininet CLI commands below:

| Command | What it does |
|---|---|
| `pingall` | every host pings every other host; expect 0% dropped, proving network and controller work |
| `h2 python3 apps/client.py --host 10.0.0.1 --duration 600 --out results/h2.csv &` | normal client on h2 sending about 5 requests/s for 10 minutes |
| `h4 python3 apps/attacker.py --host 10.0.0.1 --mode flood --rate 200 --duration 5` | h4 floods the server with 200 connections/s for 5 s |
| `sh ovs-ofctl -O OpenFlow13 dump-flows s1 \| grep drop` | shows the DROP rule `nw_src=10.0.0.4 actions=drop` installed in the switch |
| `h2 python3 apps/client.py --host 10.0.0.1 --count 5` | normal users are unaffected: expect `"failed": 0` |
| `h3 python3 apps/attacker.py --host 10.0.0.1 --mode scan --ports 1-200 --delay 0.01 --timeout 0.1` | port scan from h3; about 10 probes get through before the block |

Expected: an alert and a DROP rule appear on the dashboard and in the controller terminal, the benign client keeps
working, and the rule disappears after 60 s. Attack from h4 (idle before the attack) and avoid recalling old commands
with the up-arrow key.

**Cleanup:** type `exit`, press Ctrl+C in terminals 1 and 2, then run `sudo mn -c`.

## 7. Automated test cases

```bash
sudo python3 tests/run_tests.py --ryu $HOME/ryu-env/bin/ryu-manager
sudo python3 tests/run_tests.py --ryu $HOME/ryu-env/bin/ryu-manager --only T2 T7     # selected tests
```
Each test starts a fresh controller, network and server. Results are saved to `results/tests/`.

| ID | Test | Expected | Result |
|---|---|---|---|
| T1 | Normal traffic | all requests succeed, no alert | PASS |
| T2 | Connection flood | flood alert, DROP rule installed, attacker cut off | PASS |
| T3 | Port scan | port-scan alert, DROP rule, about 10 of 200 probes reach the host | PASS |
| T4 | Benign client during an attack | 100% success, no false alert | PASS |
| T5 | Block expiry | rule removed after the hard timeout, host can reconnect | PASS |
| T6 | Legitimate burst (15 connections in under 1 s) | not flagged (no false positive) | PASS |
| T7 | Two simultaneous attackers (flood and scan) | both blocked, benign client unaffected | PASS |
| T8 | Slow scan (limitation study) | evades the 5 s window, caught with a 30 s window | PASS |

## 8. Performance evaluation

```bash
sudo python3 tests/run_experiments.py --ryu $HOME/ryu-env/bin/ryu-manager        # full run, about 40 minutes
python3 tests/plot_results.py                                                    # graphs and table
```
Quick trial: add `--reps 1 --rates 100 --modes baseline ids`. To start from scratch use `sudo rm -rf results/experiments`.

**Method.** 15 conditions (floods at 50, 100, 200 and 400 connections/s, plus a port scan) in 3 modes, 3 repetitions each (45 trials).
In each trial two benign clients run for 20 s and the attacker starts after 5 s. The server is deliberately given finite capacity
(4 workers x 30 ms per connection, about 133 connections/s) so that an unmitigated flood causes measurable harm.

**Results (mean of 3 runs; full data in `results/experiments/summary.csv`, graphs in `results/figures/`)**

| Attack | Mode | Detection (ms) | Response (ms) | Attack conns at server | Attack probes reaching host | Benign RTT during (ms) | Benign success (%) | False positives |
|---|---|---|---|---|---|---|---|---|
| flood 50/s | No IDS | - | - | 400 | 400 | 36.5 | 100.0 | 0 |
| flood 50/s | Static (5 s delay) | 599.4 | 5010.4 | 280 | 281 | 36.6 | 100.0 | 0 |
| flood 50/s | **Dynamic IDS** | 599.7 | **1.1** | **30** | 30 | 36.0 | 100.0 | 0 |
| flood 100/s | No IDS | - | - | 800 | 800 | 46.5 | 100.0 | 0 |
| flood 100/s | Static (5 s delay) | 299.2 | 5002.5 | 531 | 531 | 41.6 | 100.0 | 0 |
| flood 100/s | **Dynamic IDS** | 299.2 | **1.2** | **30** | 30 | 35.6 | 100.0 | 0 |
| flood 200/s | No IDS | - | - | 1601 | 1601 | 825.8 | 60.0 | 0 |
| flood 200/s | Static (5 s delay) | 148.9 | 5001.4 | 1030 | 1031 | 312.7 | 96.7 | 0 |
| flood 200/s | **Dynamic IDS** | 150.5 | **1.6** | **30** | 30 | 37.0 | 100.0 | 0 |
| flood 400/s | No IDS | - | - | 3200 | 3200 | 1031.4 | 47.8 | 0 |
| flood 400/s | Static (5 s delay) | 74.5 | 5001.7 | 2031 | 2031 | 324.0 | 77.5 | 0 |
| flood 400/s | **Dynamic IDS** | 74.4 | **0.9** | **30** | 30 | 37.6 | 100.0 | 0 |
| port scan | No IDS | - | - | 0 | 200 | 36.0 | 100.0 | 0 |
| port scan | Static (5 s delay) | 134.9 | 5002.9 | 0 | 200 | 35.4 | 100.0 | 0 |
| port scan | **Dynamic IDS** | 136.3 | **1.2** | 0 | **10** | 35.8 | 100.0 | 0 |

**Findings**
* The DROP rule is confirmed by the switch about 1 ms after detection, versus about 5 s for the delayed baseline.
* With the IDS only about 30 attack connections reach the server at every attack rate. This equals the detection threshold: the
  controller allows 30 connections and blocks the 31st.
* Detection time is about 31 divided by the attack rate (599 ms at 50/s down to 74 ms at 400/s), because the rule needs 31 connections.
* Without the IDS the server collapses at 200 and 400 connections/s (benign success falls to 60% and 48%). With the IDS benign clients
  stay at 100% success and about 36 ms latency. At 50 and 100 connections/s the modelled server is not saturated, so benign
  traffic is barely affected in any mode.
* A port scan does not harm benign traffic here; the benefit is containment (10 of 200 probes reach the host instead of 200).
* No false positives occurred in any trial.

**Figures** (generated in `results/figures/`): `attack_conns_at_server.png`, `benign_latency.png`, `benign_success.png`,
`detection_time.png`, `response_time.png`, plus `results_table.md`.

## 9. Configuration

Environment variables read by the controller (example: `RATE_THRESHOLD=20 BLOCK_TIMEOUT=30 ryu-manager controller/ids_ryu.py`):

| Variable | Default | Meaning |
|---|---|---|
| `IDS_MODE` | `ids` | `ids`, `static` or `baseline` |
| `RATE_WINDOW` / `RATE_THRESHOLD` | 1.0 s / 30 | flood rule |
| `PORT_WINDOW` / `PORT_THRESHOLD` | 5.0 s / 10 | port-scan rule |
| `BLOCK_TIMEOUT` | 60 | lifetime of a DROP rule in seconds |
| `STATIC_DELAY` | 5 | delay before blocking in `static` mode |
| `FLOW_IDLE` | 5 | idle timeout of per-connection flows |
| `STATS_INTERVAL` | 1 | seconds between flow-statistics polls |
| `WHITELIST` | `10.0.0.1` | IPs that are never blocked (the server) |
| `EVENTS_FILE` | `results/events.jsonl` | event log read by the dashboard |

Server options: `--workers`, `--service-time`, `--queue-size`. Attacker options: `--mode flood|scan`, `--rate`, `--duration`, `--ports`, `--delay`, `--timeout`.

## 10. Limitations

* **Slow scans evade the 5 s window** (test T8); a longer window catches them at the cost of more state.
* **Spoofed source addresses are not handled**; the rules are per source IP.
* **Detection time is measured from the start of the source's current activity burst** (a 2 s quiet gap starts a new burst), so it assumes
  the attacker was idle beforehand. A host that sends normal traffic and then attacks shows an inflated detection time, although the alert itself fires on the 31st connection.
* The detection threshold lets about 30 attack connections through before blocking.
* Every new connection is processed by the controller, which would limit scalability on a large network.
* The server's capacity is modelled, so absolute latency and success figures depend on that choice; the comparison between modes is the valid result.
* The "static" baseline is a fixed 5 s delay, not a real operator.
* Results come from 3 repetitions on a one-switch, four-host topology.

## 11. Troubleshooting

| Problem | Fix |
|---|---|
| `Failed to build ryu` (`get_script_args` error) | use the install commands in 4.2 (`setuptools<58`, `--no-build-isolation`) |
| `has inconsistent version: expected '4.34', but metadata has '0.0.0'` | prefix the install with `PBR_VERSION=4.34` |
| `ImportError ... eventlet` | `pip install eventlet==0.30.2` inside `~/ryu-env` |
| Dashboard shows "Connecting…" and the terminal says "No supported WebSocket library" | `pip install "uvicorn[standard]"` in `~/ryu-env`, restart the dashboard |
| Dashboard traffic buttons stay disabled | start or restart `sudo python3 topology/topo.py`; the dashboard checks its local Mininet action endpoint |
| Switch never connects / `pingall` shows packet loss | start the controller first, then Mininet; run `sudo mn -c` |
| Port 6653 already in use | `pkill -f ryu-manager` |
| `rm: Permission denied` in `results/` | files were created by `sudo`; use `sudo rm -rf results/...` or `sudo chown -R $USER:$USER .` |
| `Unknown command: mininet> ...` | you pasted the prompt text; type only the command |
| Dashboard is empty | start the controller before opening the dashboard, and refresh the page |

## 12. Safety note

`apps/attacker.py` generates flood and scan traffic. Use it **only inside your own Mininet lab** (10.0.0.0/24) against your own server.
Never point it at other machines or networks.
