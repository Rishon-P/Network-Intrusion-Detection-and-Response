| Attack | Mode | Detected | Detection (ms) | Response (ms) | Attack conns at server | Attack probes reaching host | Benign RTT during (ms) | Benign success (%) | False positives |
|---|---|---|---|---|---|---|---|---|---|
| flood 50/s | No IDS (baseline) | 0.0 | - | - | 400.5 | 400.5 | 35.4 | 100.0 | 0.0 |
| flood 50/s | Static / delayed block | 1.0 | 599.5 | 5006.1 | 280.7 | 281.0 | 35.6 | 100.0 | 0.0 |
| flood 50/s | Dynamic SDN IDS | 1.0 | 599.4 | 1.0 | 30.0 | 30.0 | 35.4 | 100.0 | 0.0 |
| flood 100/s | No IDS (baseline) | 0.0 | - | - | 800.5 | 800.5 | 41.7 | 100.0 | 0.0 |
| flood 100/s | Static / delayed block | 1.0 | 299.0 | 5002.0 | 531.0 | 531.0 | 39.2 | 100.0 | 0.0 |
| flood 100/s | Dynamic SDN IDS | 1.0 | 299.1 | 1.0 | 30.0 | 30.0 | 35.1 | 100.0 | 0.0 |
| flood 200/s | No IDS (baseline) | 0.0 | - | - | 1600.5 | 1600.5 | 831.1 | 61.9 | 0.0 |
| flood 200/s | Static / delayed block | 1.0 | 149.0 | 5001.4 | 1030.7 | 1031.0 | 303.2 | 94.3 | 0.0 |
| flood 200/s | Dynamic SDN IDS | 1.0 | 149.7 | 1.1 | 30.0 | 30.0 | 36.1 | 100.0 | 0.0 |
| flood 400/s | No IDS (baseline) | 0.0 | - | - | 3200.0 | 3200.0 | 1059.8 | 45.0 | 0.0 |
| flood 400/s | Static / delayed block | 1.0 | 74.1 | 5024.7 | 2010.0 | 2013.2 | 316.2 | 78.5 | 0.0 |
| flood 400/s | Dynamic SDN IDS | 1.0 | 74.3 | 0.8 | 29.8 | 30.0 | 36.5 | 100.0 | 0.0 |
| port scan | No IDS (baseline) | 0.0 | - | - | 0.0 | 200.0 | 35.2 | 100.0 | 0.0 |
| port scan | Static / delayed block | 1.0 | 130.0 | 5002.9 | 0.0 | 200.0 | 34.8 | 100.0 | 0.0 |
| port scan | Dynamic SDN IDS | 1.0 | 131.4 | 1.0 | 0.0 | 10.0 | 35.1 | 100.0 | 0.0 |
