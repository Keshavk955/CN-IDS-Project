
"""Repeated synthetic comparison of fixed and contextual risk scoring."""

from collections import defaultdict
from pathlib import Path
import tempfile

from ids.database import Database
from ids.detection import DetectionEngine
from ids.ml_detector import MLAnomalyDetector
from ids.risk_scoring import (
    DEFAULT_WEIGHTS,
    calculate_risk_score,
    get_risk_level,
)
from ids.simulation import generate_demo_packets, generate_benign_burst


TRIALS = 10
BENIGN_SOURCE = "192.0.2.40"
BENIGN_TYPE = "HIGH PACKET RATE DETECTED"


def component_scores(alert):
    return (
        float(alert["rule_score"] or 0),
        float(alert["ml_score"] or 0),
        float(alert["anomaly_score"] or 0),
        float(alert["historical_score"] or 0),
    )


def score_alert(alert, weights):
    return calculate_risk_score(
        *component_scores(alert),
        weights=weights,
    )


def run_trial(seed, work_folder):
    db_path = work_folder / f"trial_{seed}.db"
    model_path = work_folder / f"model_{seed}.joblib"

    db = Database(db_path)
    model = MLAnomalyDetector(model_path)
    engine = DetectionEngine(db, model)

    for packet in generate_demo_packets(seed=seed):
        engine.process(packet, simulated=True)

    for packet in generate_benign_burst(seed=1000 + seed):
        engine.process(packet, simulated=True)

    alerts = db.get_alerts(limit=1000)

    benign_alert = next(
        (
            alert for alert in alerts
            if alert["source_ip"] == BENIGN_SOURCE
            and alert["attack_type"] == BENIGN_TYPE
        ),
        None,
    )

    if benign_alert is None:
        raise RuntimeError(
            f"Trial {seed}: expected benign-burst alert was not generated."
        )

    # Learn from the labelled benign example.
    db.apply_feedback(
        benign_alert["id"],
        "FALSE_POSITIVE",
    )

    results = []

    for alert in db.get_alerts(limit=1000):
        fixed_score = score_alert(alert, DEFAULT_WEIGHTS)

        contextual_weights = db.get_weights(
            alert["attack_type"]
        )

        contextual_score = score_alert(
            alert,
            contextual_weights,
        )

        is_benign = alert["source_ip"] == BENIGN_SOURCE

        results.append({
            "seed": seed,
            "attack_type": alert["attack_type"],
            "label": "BENIGN" if is_benign else "ATTACK",
            "fixed_score": fixed_score,
            "contextual_score": contextual_score,
            "change": contextual_score - fixed_score,
        })

    return results


def main():
    grouped = defaultdict(list)
    all_results = []

    with tempfile.TemporaryDirectory(
        prefix="cn_ids_benchmark_"
    ) as temp_dir:
        root = Path(temp_dir)

        for seed in range(TRIALS):
            results = run_trial(seed, root)

            all_results.extend(results)

            for result in results:
                grouped[
                    (result["attack_type"], result["label"])
                ].append(result)

    print("CONTEXTUAL ADAPTIVE SCORING — SYNTHETIC BENCHMARK")
    print(f"Independent runs: {TRIALS}")
    print("Project database and saved model were not modified.")
    print("No live network packets were sent.")

    print("\nMean scores across runs")
    print(
        f"{'Scenario':28s} {'Label':8s} "
        f"{'Runs':>5s} {'Fixed mean':>11s} "
        f"{'Adaptive mean':>14s} {'Mean change':>12s}"
    )
    print("-" * 84)

    for (attack_type, label), rows in sorted(grouped.items()):
        n = len(rows)
        fixed_mean = sum(
            row["fixed_score"] for row in rows
        ) / n
        adaptive_mean = sum(
            row["contextual_score"] for row in rows
        ) / n
        change_mean = sum(
            row["change"] for row in rows
        ) / n

        print(
            f"{attack_type[:28]:28s} {label:8s} "
            f"{n:5d} {fixed_mean:11.2f} "
            f"{adaptive_mean:14.2f} {change_mean:+12.2f}"
        )

    unrelated = [
        row for row in all_results
        if row["attack_type"] != BENIGN_TYPE
    ]

    unchanged = all(
        abs(row["change"]) < 0.01
        for row in unrelated
    )

    benign_results = [
        row for row in all_results
        if row["attack_type"] == BENIGN_TYPE
        and row["label"] == "BENIGN"
    ]

    benign_lower = bool(benign_results) and all(
        row["change"] < -0.01
        for row in benign_results
    )

    print("\nChecks")
    print(
        "Unrelated alert types retain their base-weight scores:",
        "PASS" if unchanged else "CHECK RESULTS",
    )
    print(
        "Benign high-packet-rate scores decrease after feedback:",
        "PASS" if benign_lower else "CHECK RESULTS",
    )

    print(
        "\nInterpretation: these are repeated synthetic scenario "
        "comparisons, not real-network accuracy measurements. "
        "They do not establish precision, recall or F1."
    )


if __name__ == "__main__":
    main()
