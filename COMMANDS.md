# NIDR Command Reference

Commands below work from any clone location. First open a terminal in the repository folder; the live demo uses three terminals. Start the controller first, then the dashboard and Mininet topology.

## 1. Prepare the environment

Clone the project once, or skip the clone command if you already have it:

```bash
git clone https://github.com/Rishon-P/Network-Intrusion-Detection-and-Response.git
cd Network-Intrusion-Detection-and-Response
```

For the controller and dashboard terminals, change to your clone's directory and activate the Python environment you installed for this project:

```bash
cd /path/to/Network-Intrusion-Detection-and-Response
source ~/ryu-env/bin/activate
```

| Command | What it does |
|---|---|
| `cd /path/to/Network-Intrusion-Detection-and-Response` | Replace the placeholder with the path where you cloned the repository. |
| `source ~/ryu-env/bin/activate` | Activates the Python environment containing Ryu and the dashboard packages. Use this in the controller and dashboard terminals. |

If you installed the virtual environment inside the repository instead, activate it with `source ryu-env/bin/activate`.

## 2. Start the live demo

### Terminal 1: Ryu controller

Run from the project root with `ryu-env` activated:

```bash
ryu-manager controller/ids_ryu.py
```

Starts the IDS controller. It listens for the Mininet switch, detects flood and scan traffic, installs OpenFlow DROP rules, and writes events to `results/events.jsonl`. Leave this terminal open.

### Terminal 2: Dashboard

Run from the project root with `ryu-env` activated:

```bash
python3 dashboard/dashboard.py
```

Starts the dashboard at <http://127.0.0.1:8000/>. Leave this terminal open.

### Terminal 3: Mininet topology

Run from the project root in a regular terminal. Mininet is provided by the system Python installation:

```bash
sudo python3 topology/topo.py
```

Creates the Mininet hosts `h1` through `h10`, connects switch `s1` to Ryu, and starts the local dashboard action endpoint. The process opens a `mininet>` prompt. Keep this terminal open while using the demo.

## 3. Commands at the `mininet>` prompt

These commands run inside the Mininet CLI, not in a regular shell.

| Command | What it does |
|---|---|
| `h1 python3 apps/server.py --host 10.0.0.1 --log results/server_log.csv &` | Starts the TCP server on `h1` at `10.0.0.1:8080`. It records accepted and rejected connections in `results/server_log.csv`. |
| `pingall` | Checks connectivity between Mininet hosts. |
| `h2 python3 apps/client.py --host 10.0.0.1 --count 5` | Sends five normal client requests from `h2` to the server. |
| `h2 python3 apps/client.py --host 10.0.0.1 --duration 600 --out results/h2.csv &` | Starts a normal client on `h2` for ten minutes and records its measurements in `results/h2.csv`. |
| `h4 python3 apps/attacker.py --host 10.0.0.1 --mode flood --rate 200 --duration 5` | Generates a controlled TCP connection flood from `h4` at 200 attempts per second for five seconds. The IDS should detect and block the source. |
| `h5 python3 apps/attacker.py --host 10.0.0.1 --mode scan --ports 1-200 --delay 0.01 --timeout 0.1` | Probes TCP ports 1–200 from `h5` to demonstrate port scan detection. |
| `sh ovs-ofctl -O OpenFlow13 dump-flows s1 \| grep drop` | Displays installed OpenFlow DROP rules on switch `s1`. |
| `exit` | Exits the Mininet CLI and stops the topology process. |

The dashboard can also start a fixed flood or scan from a selected sender. Use **+ Add sender** to reveal additional sender hosts (`h5`–`h10`).

## 4. Check logs

Run these from a regular shell at the project root:

| Command | What it does |
|---|---|
| `tail -f results/events.jsonl` | Follows controller events as they are appended, including alerts and confirmed blocks. Press `Ctrl+C` to stop following. |
| `tail -f results/server_log.csv` | Follows TCP connections accepted or rejected by the server. |
| `python3 -c 'import json; [json.loads(line) for line in open("results/events.jsonl") if line.strip()]; print("events log is valid")'` | Parses each non-empty JSON Lines record and reports whether the events log is valid. |

## 5. Stop and clean up

1. At `mininet>`, type `exit`.
2. Press `Ctrl+C` in the dashboard and controller terminals.
3. From a regular shell, run:

```bash
sudo mn -c
```

Removes leftover Mininet namespaces, virtual interfaces, and switches. Use this before restarting the topology if Mininet reports stale state.

If port 6653 is already occupied, first identify the existing Ryu process. `pkill -f ryu-manager` stops every matching Ryu controller process, so use it only when you intend to stop all of them.

## 6. Optional automated checks

Run these only when you want to execute the repository's tests; they start Mininet/controller test scenarios and can take time.

```bash
python3 tests/test_detector.py
```

Runs unit checks for the detection rules without Mininet.

```bash
source ryu-env/bin/activate
python3 tests/test_controller_offline.py
```

Runs controller checks using a fake OpenFlow switch, without a live Mininet network.

```bash
sudo python3 tests/run_tests.py --ryu "$(command -v ryu-manager)"
```

Runs the end-to-end Mininet test scenarios and stores their outputs under `results/tests/`.
