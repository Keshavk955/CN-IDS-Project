# Hybrid Network Security Monitoring and Intrusion Detection System

## 1. Project overview

This project monitors network packets, detects selected suspicious traffic
patterns, calculates risk scores, stores records in SQLite, and displays
results in a Streamlit dashboard.

The main project contribution is feedback-guided contextual adaptive
risk scoring. When an alert is labelled as a true positive or false
positive, its alert type receives updated component weights for future
alerts of that type.

## 2. Requirements

- Python 3.12
- Scapy and Npcap for Windows packet capture
- Streamlit
- pandas
- Plotly
- NumPy
- scikit-learn
- joblib

## 3. Install dependencies

Open PowerShell in the project root and run:

    python -m pip install -r requirements.txt

## 4. Run the targeted regression tests

Run:

    python -m unittest -v test_adaptive_scoring test_historical_decay test_false_positive_history

The expected result is 11 passing tests.

Avoid using unittest discovery as the final regression command because
some legacy test scripts execute demonstrations and insert records
into the original database.

## 5. Run the synthetic evaluation

Run:

    python evaluate_holdout_benchmark.py

This uses temporary databases and model files. It does not intentionally
modify the project's saved database or generate network traffic.

The benchmark uses controlled synthetic examples. Its results are not
proof of real-world accuracy.

## 6. Start the dashboard

Run:

    python -m streamlit run dashboard.py

Open the Local URL displayed by Streamlit, normally:

    http://localhost:8501

Use the safe demo to generate synthetic traffic and alerts. Use the
review controls to label an alert only when its ground-truth label is
known.

## 7. Run live packet capture on Windows

List the available capture interfaces:

    python run_live.py --list-interfaces

Choose the correct interface for the network you are authorised to
monitor, then run:

    python run_live.py --interface "YOUR_NPF_INTERFACE" --count 100

Replace YOUR_NPF_INTERFACE with the actual Npcap interface identifier.
Live capture may require appropriate permissions.

A packet capture that produces no alerts is not necessarily a failure.
Ordinary traffic may not match any configured detection rule.

## 8. Risk-scoring contribution

The base component weights are:

- Rule-based score: 35%
- Machine-learning score: 35%
- Anomaly score: 20%
- Historical score: 10%

Feedback adjusts the weights separately for each alert type. The weights
are bounded, normalised, and stored in SQLite.

The historical score uses exponential time decay. Alerts labelled as
false positives are excluded from subsequent historical reputation
calculations.

## 9. Evaluation evidence

The results directory contains the targeted regression-test output and
the held-out synthetic benchmark.

The final database audit records traffic counts and learned feedback
weights from the development environment.

Keep the actual local database files separate from the source-code
submission unless database inclusion is explicitly required.

## 10. Limitations

- The system is a student prototype, not a production IDS.
- The anomaly detector uses a synthetic training baseline.
- Detection thresholds may generate false positives and require tuning.
- The benchmark uses generated scenarios rather than independently
  collected, labelled network traffic.
- Live traffic visibility depends on the interface, permissions and
  operating system.
- Synthetic benchmark metrics must not be described as real-world
  detection accuracy.

## 11. Suggested demonstration order

1. Explain the architecture and packet-processing flow.
2. Run the safe synthetic demo.
3. Show a port-scan or ICMP-flood alert.
4. Explain the four component scores and their weighted contributions.
5. Show a labelled benign example and the resulting contextual weight update.
6. Demonstrate that unrelated alert types retain their own weights.
7. Show the historical-decay and false-positive regression-test results.
8. Explain the benchmark and its limitations.
