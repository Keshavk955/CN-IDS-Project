# Hybrid Network Security Monitoring & IDS

## Current contribution

This student prototype combines rule-based traffic detection with an Isolation Forest anomaly signal, a combined risk score, time-decayed source reputation, component-level score explanations, and feedback-guided adaptive weighting.

The adaptive weighting is a transparent bounded heuristic. When an analyst labels an alert as a true positive, components scoring above that alert's mean component score gain relative weight. When an analyst labels an alert as a false positive, those relatively high components lose relative weight. The weights remain positive, sum to 100%, and are saved in SQLite for subsequent alerts. This is a project-level feedback mechanism, not a claim that the system is production-ready or statistically calibrated.

## Detection pipeline

1. Scapy captures authorized IPv4 traffic, or the safe simulator generates synthetic packets.
2. The packet parser extracts addresses, protocol, packet size, ports and TCP flags where available.
3. The detection engine evaluates port-scan, packet-rate, ICMP-flood and SYN-flood patterns.
4. Isolation Forest produces a prototype anomaly signal based on a generated baseline.
5. Rule, ML, anomaly and time-decayed historical scores are combined using stored adaptive weights.
6. SQLite stores alerts, component scores, weights used for each alert, simulated/live status, and analyst feedback.
7. Streamlit displays traffic, alerts, score contributions, weights and feedback controls.

## Setup

From the project root in PowerShell:

```powershell
python -m pip install -r requirements.txt
python -m unittest -v test_adaptive_scoring.py
```

Start the dashboard:

```powershell
python -m streamlit run dashboard.py
```

The **Run safe demo** button processes 52 synthetic packets and does not send traffic to a network. The **Run benign-burst feedback example** button generates a labelled benign high-volume scenario that deliberately trips the simple packet-rate heuristic. Use that known benign alert to demonstrate a false-positive feedback update.

## Live capture

First list available Scapy interfaces:

```powershell
python run_live.py --list-interfaces
```

Then use one exact interface name from the output:

```powershell
python run_live.py --interface "Wi-Fi"
```

Replace `Wi-Fi` with the actual interface name on the machine. Capture may require elevated permissions and Npcap on Windows. Only monitor traffic you are authorized to capture. Press `Ctrl+C` to stop.

The live-capture bridge has been syntax-checked but should be verified on the user's Windows/Npcap setup before claiming live capture is working end to end.

## Risk scoring and explanation

The default weights are 35% rule, 35% ML, 20% anomaly and 10% historical. Every new alert stores the component scores and weights used at creation time. The dashboard's **Explain a risk score** section shows each component's weighted contribution. Feedback changes the weights for later alerts; it does not rewrite previous scores.

Historical source reputation uses exponential decay with a 15-minute half-life, so older alerts have progressively less influence.

## Limitations

- The Isolation Forest is trained on generated synthetic baseline features. It is an unsupervised prototype signal, not a calibrated probability and not yet evaluated against a labelled real-world IDS dataset.
- The anomaly signal is currently based on the strongest normalized traffic-rate/port/ICMP/SYN signal. A future improvement could replace it with a well-evaluated per-host rolling baseline.
- Rules and thresholds can generate false positives. Alert labels should reflect the known scenario or a justified analyst review.
- This project is for coursework and authorized experiments, not production network protection.
