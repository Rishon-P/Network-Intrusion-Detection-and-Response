| Attack | Mode | Detected | Detection (ms) | Response (ms) | Attack conns at server | Attack probes reaching host | Benign RTT during (ms) | Benign success (%) | False positives |
|---|---|---|---|---|---|---|---|---|---|
| flood 50/s | No IDS (baseline) | 0.0 | - | - | 400.0 | 400.0 | 36.5 | 100.0 | 0.0 |
| flood 50/s | Static / delayed block | 1.0 | 599.4 | 5010.4 | 280.3 | 281.0 | 36.6 | 100.0 | 0.0 |
| flood 50/s | Dynamic SDN IDS | 1.0 | 599.7 | 1.1 | 30.0 | 30.0 | 36.0 | 100.0 | 0.0 |
| flood 100/s | No IDS (baseline) | 0.0 | - | - | 800.0 | 800.0 | 46.5 | 100.0 | 0.0 |
| flood 100/s | Static / delayed block | 1.0 | 299.2 | 5002.5 | 531.0 | 531.0 | 41.6 | 100.0 | 0.0 |
| flood 100/s | Dynamic SDN IDS | 1.0 | 299.2 | 1.2 | 30.0 | 30.0 | 35.6 | 100.0 | 0.0 |
| flood 200/s | No IDS (baseline) | 0.0 | - | - | 1601.0 | 1601.0 | 825.8 | 60.0 | 0.0 |
| flood 200/s | Static / delayed block | 1.0 | 148.9 | 5001.4 | 1030.3 | 1031.0 | 312.7 | 96.7 | 0.0 |
| flood 200/s | Dynamic SDN IDS | 1.0 | 150.5 | 1.6 | 30.0 | 30.0 | 37.0 | 100.0 | 0.0 |
| flood 400/s | No IDS (baseline) | 0.0 | - | - | 3200.0 | 3200.0 | 1031.4 | 47.8 | 0.0 |
| flood 400/s | Static / delayed block | 1.0 | 74.5 | 5001.7 | 2031.0 | 2031.0 | 324.0 | 77.5 | 0.0 |
| flood 400/s | Dynamic SDN IDS | 1.0 | 74.4 | 0.9 | 29.7 | 30.0 | 37.6 | 100.0 | 0.0 |
| port scan | No IDS (baseline) | 0.0 | - | - | 0.0 | 200.0 | 36.0 | 100.0 | 0.0 |
| port scan | Static / delayed block | 1.0 | 134.9 | 5002.9 | 0.0 | 200.0 | 35.4 | 100.0 | 0.0 |
| port scan | Dynamic SDN IDS | 1.0 | 136.3 | 1.2 | 0.0 | 10.0 | 35.8 | 100.0 | 0.0 |
