# COMMANDS2 – Demo 2 (HTTP web mode): command reference

Demo 1 (README section 6 / `COMMANDS.md`) uses the plain TCP server. **Demo 2 shows the same IDS protecting a real web
service.** Everything is run from the project root, e.g. `cd ~/Desktop/Network-Intrusion-Detection-and-Response`.

> Lab use only: the attacker script must be used only inside your own Mininet network (10.0.0.0/24) against your own server.

## 0. Before you start (once)
```bash
sudo mn -c                                        # remove leftovers of old Mininet runs
sudo chown -R $USER:$USER results                 # only if old runs left root-owned files
python3 tests/test_http_app.py                    # expect: 15/15 checks passed
```

## 1. Start the three terminals (keep all open, start in this order)

| Terminal | Commands | What it does |
|---|---|---|
| 1 – controller | `source ~/ryu-env/bin/activate`<br>`ryu-manager controller/ids_ryu.py` | Starts the Ryu IDS controller. It waits for the switch, detects floods/scans and installs DROP rules. Writes events to `results/events.jsonl`. |
| 2 – dashboard | `source ~/ryu-env/bin/activate`<br>`python3 dashboard/dashboard.py` | Web dashboard at <http://127.0.0.1:8000/>. Reads the event log and shows rates, alerts, blocks. |
| 3 – Mininet | `sudo python3 topology/topo.py` | Creates h1..h10 and switch s1, connects s1 to Ryu, opens the `mininet>` prompt and the local action API used by the dashboard buttons. |

Open <http://127.0.0.1:8000/> in the browser. The buttons stay grey for a few seconds until Mininet is ready.

## 2. Commands at the `mininet>` prompt (Demo 2)

Type these exactly. Do **not** type `mininet>` or `sudo` yourself; for Linux commands use `sh <command>`.

| Step | Command | What it does / what to say | Expected result |
|---|---|---|---|
| 1 | `pingall` | Every host pings every other host. Proves the network and controller work. | `0% dropped` |
| 2 | `h1 python3 apps/server.py --host 10.0.0.1 --protocol http --log results/server_log.csv &` | Starts the **web server** on h1 (HTTP/1.1, port 8080, 4 workers x 30 ms per request). `&` keeps it running in the background. | prints `[server] http listening on 10.0.0.1:8080 ...` |
| 3 | `h2 python3 apps/client.py --host 10.0.0.1 --protocol http --count 5` | A normal browser-like user sends 5 `GET` requests. | `"ok": 5, "failed": 0` |
| 4 | `h2 python3 apps/client.py --host 10.0.0.1 --protocol http --duration 600 --out results/h2.csv &` | Normal user keeps browsing for 10 minutes (about 5 requests/s) so you can see it stay healthy during the attack. | blue line at about 5/s on the dashboard |
| 5 | `h4 python3 apps/attacker.py --host 10.0.0.1 --mode http-flood --rate 200 --duration 5` | **HTTP flood**: h4 sends 200 `GET /login?user=admin&pw=guess` requests per second for 5 s (a login-guessing attack). | dashboard spike, alert "Connection flood", DROP rule |
| 6 | `sh ovs-ofctl -O OpenFlow13 dump-flows s1 \| grep drop` | Shows the DROP rule installed in the switch. | `priority=100,ip,nw_src=10.0.0.4 actions=drop` (lasts 60 s) |
| 7 | `h2 python3 apps/client.py --host 10.0.0.1 --protocol http --count 5` | The normal user is still served while the attacker is blocked. | `"failed": 0` |
| 8 | `h4 python3 apps/attacker.py --host 10.0.0.1 --mode http-flood --rate 50 --duration 3` | (optional) Attack again while blocked: every packet is dropped at the switch. | all probes `timeout`, nothing reaches the server |
| 9 | wait 60 s, repeat step 6 | The block expires by itself (hard timeout) and the rule disappears. | no drop rule |

Optional extra attacks in the same session:

| Command | What it does |
|---|---|
| `h3 python3 apps/attacker.py --host 10.0.0.1 --mode scan --ports 1-200 --delay 0.01 --timeout 0.1` | Port scan from h3; blocked after about 10 probes (rule: more than 10 distinct ports in 5 s). |
| `h5 python3 apps/attacker.py --host 10.0.0.1 --mode flood --rate 200 --duration 5` | The old plain-TCP flood (no HTTP request), for comparison. Same dashboard graph. |

Tip: attack from a host that was idle before (h4, h5...). Do not use the up-arrow to re-run old commands by mistake.

## 3. Same demo from the dashboard buttons (GUI)
1. Do steps 1–4 above at `mininet>` (the buttons do not start the server or the normal client).
2. In the dashboard choose a **Sender** (default h4).
3. Click **Run HTTP flood from h4** (purple). The other buttons: **Run flood** = plain TCP flood, **Run port scan**.
4. Watch the graph (spike then 0), the alert log, the "Active drop rules" counter, and the blue normal-client line staying at about 5/s.

## 4. Optional: Wireshark proof that it is real HTTP
Start Wireshark before the attack, capture on the switch ports `s1-eth1` (server side) and `s1-eth4` (attacker side). Filters:

| Filter | Shows |
|---|---|
| `http.request` | the `GET /login?user=admin&pw=guess` lines |
| `http.response.code == 200` | the server's `200 OK` replies |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | the new-connection SYNs the controller counts |
| `ip.src == 10.0.0.4` | everything from the attacker; stops after the DROP rule |
| capture on `lo`, filter `openflow_v4` | OpenFlow messages: Packet-In, Flow-Mod, Barrier |

You will see the HTTP requests stop on `s1-eth1` right after the block, while h2's requests continue.

## 5. Automated checks (no manual typing)
```bash
sudo python3 tests/run_tests.py --ryu $HOME/ryu-env/bin/ryu-manager --only T9 T10   # the two HTTP tests
sudo python3 tests/run_tests.py --ryu $HOME/ryu-env/bin/ryu-manager                 # all 10 tests
sudo python3 tests/run_experiments.py --ryu $HOME/ryu-env/bin/ryu-manager --http --http-rates 200   # optional, slow
python3 tests/plot_results.py
```
Last verified in Mininet: T9 PASS (100% success, 0 alerts); T10 PASS (`syn_flood` alert, drop rule installed,
30 attack requests reached the web server, h2 100% success, 0 false alerts).

## 6. Stop and clean up
```text
mininet> exit
```
Then Ctrl+C in terminals 1 and 2, and run `sudo mn -c`.

## 7. If something goes wrong

| Problem | Fix |
|---|---|
| Dashboard buttons stay grey | Mininet terminal is not running; start `sudo python3 topology/topo.py`. |
| New HTTP button missing | Restart dashboard and topo.py, then hard refresh the browser (Ctrl+Shift+R). |
| `No supported WebSocket library` | `pip install "uvicorn[standard]"` and restart the dashboard. |
| `Address already in use` | Old server/controller still running: `sudo mn -c`, then `pkill -f ryu-manager` and retry. |
| Client says `failed` before any attack | The server was not started with `--protocol http`, or it is not running. Repeat step 2. |
| Flood did nothing visible | The attacker was already blocked from an earlier run; wait 60 s or check step 6. |
| Permission denied in `results/` | `sudo chown -R $USER:$USER results` |
