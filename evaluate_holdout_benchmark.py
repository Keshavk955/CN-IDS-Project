
"""Held-out synthetic evaluation of contextual adaptive risk scoring."""

from collections import defaultdict
from pathlib import Path
import tempfile

from ids.database import Database
from ids.detection import DetectionEngine
from ids.ml_detector import MLAnomalyDetector
from ids.risk_scoring import (
    DEFAULT_WEIGHTS,
    calculate_risk_score,
)
from ids.simulation import (
    generate_demo_packets,
    generate_benign_burst,
)


TRIALS = 10
RISK_THRESHOLDS = (60, 65, 70, 71)

BENIGN_SOURCE = "192.0.2.40"
BENIGN_TYPE = "HIGH PACKET RATE DETECTED"


def score_alert(alert, weights):
    return calculate_risk_score(
        float(alert["rule_score"]),
        float(alert["ml_score"]),
        float(alert["anomaly_score"]),
        float(alert["historical_score"]),
        weights=weights,
    )


def confusion_metrics(rows, score_key, threshold):
    tp = fp = tn = fn = 0

    for row in rows:
        actual_attack = row["label"] == "ATTACK"
        predicted_attack = row[score_key] >= threshold

        if actual_attack and predicted_attack:
            tp += 1
        elif not actual_attack and predicted_attack:
            fp += 1
        elif not actual_attack and not predicted_attack:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )

    fpr = fp / (fp + tn) if fp + tn else 0.0

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def train_contextual_weights(folder, trial):
    """Learn from a benign feedback example separate from test traffic."""

    db = Database(folder / f"train_{trial}.db")
    model = MLAnomalyDetector(
        folder / f"train_model_{trial}.joblib"
    )
    engine = DetectionEngine(db, model)

    for packet in generate_benign_burst(seed=1000 + trial):
        engine.process(packet, simulated=True)

    benign = next(
        (
            row for row in db.get_alerts(limit=1000)
            if row["source_ip"] == BENIGN_SOURCE
            and row["attack_type"] == BENIGN_TYPE
        ),
        None,
    )

    if benign is None:
        raise RuntimeError(
            f"Training run {trial}: no benign-burst alert was generated."
        )

    db.apply_feedback(
        benign["id"],
        "FALSE_POSITIVE",
    )

    return db


def evaluate_held_out_scenarios(folder, trial, training_db):
    """Evaluate separate traffic using weights learned in training."""

    db = Database(folder / f"test_{trial}.db")
    model = MLAnomalyDetector(
        folder / f"test_model_{trial}.joblib"
    )
    engine = DetectionEngine(db, model)

    alerts = []

    for packet in generate_demo_packets(seed=trial + 7):
        result = engine.process(packet, simulated=True)
        if result:
            alerts.append(result)

    # The evaluation benign burst uses a seed different from training.
    for packet in generate_benign_burst(seed=2000 + trial):
        result = engine.process(packet, simulated=True)
        if result:
            alerts.append(result)

    results = []

    for alert in alerts:
        label = (
            "BENIGN"
            if alert["source_ip"] == BENIGN_SOURCE
            else "ATTACK"
        )

        base_score = score_alert(alert, DEFAULT_WEIGHTS)

        learned_weights = training_db.get_weights(
            alert["attack_type"]
        )

        contextual_score = score_alert(
            alert,
            learned_weights,
        )

        results.append({
            "trial": trial,
            "scenario": alert["attack_type"],
            "label": label,
            "fixed_score": base_score,
            "contextual_score": contextual_score,
        })

    return results


def main():
    all_results = []

    with tempfile.TemporaryDirectory(
        prefix="cn_ids_holdout_eval_"
    ) as temp_dir:
        root = Path(temp_dir)

        for trial in range(TRIALS):
            training_db = train_contextual_weights(
                root,
                trial,
            )

            results = evaluate_held_out_scenarios(
                root,
                trial,
                training_db,
            )

            all_results.extend(results)

    if not all_results:
        raise RuntimeError("No held-out alerts were generated.")

    print("HELD-OUT CONTEXTUAL RISK-SCORING EVALUATION")
    print(f"Training runs: {TRIALS}")
    print(f"Held-out alert examples: {len(all_results)}")
    print("Project database was not modified.")
    print("No live network traffic was generated.")

    print("\nMean held-out risk scores")
    grouped = defaultdict(list)

    for row in all_results:
        grouped[(row["scenario"], row["label"])].append(row)

    print(
        f"{'Scenario':28s} {'Label':8s} {'N':>4s} "
        f"{'Fixed mean':>11s} {'Contextual mean':>16s}"
    )
    print("-" * 74)

    for (scenario, label), rows in sorted(grouped.items()):
        fixed_mean = sum(
            r["fixed_score"] for r in rows
        ) / len(rows)

        contextual_mean = sum(
            r["contextual_score"] for r in rows
        ) / len(rows)

        print(
            f"{scenario[:28]:28s} {label:8s} {len(rows):4d} "
            f"{fixed_mean:11.2f} {contextual_mean:16.2f}"
        )

    print("\nRisk-threshold classification metrics")
    print(
        "Positive means the risk score meets or exceeds "
        "the selected evaluation threshold."
    )
    print(
        "These metrics evaluate risk prioritization, not whether "
        "the rule detector generated an alert."
    )

    for threshold in RISK_THRESHOLDS:
        fixed = confusion_metrics(
            all_results,
            "fixed_score",
            threshold,
        )

        contextual = confusion_metrics(
            all_results,
            "contextual_score",
            threshold,
        )

        print(f"\nThreshold: {threshold}/100")

        for name, metrics in (
            ("Fixed", fixed),
            ("Contextual", contextual),
        ):
            print(
                f"{name:10s}: "
                f"TP={metrics['TP']} "
                f"FP={metrics['FP']} "
                f"TN={metrics['TN']} "
                f"FN={metrics['FN']} | "
                f"Precision={metrics['precision']:.3f} "
                f"Recall={metrics['recall']:.3f} "
                f"F1={metrics['f1']:.3f} "
                f"FPR={metrics['fpr']:.3f}"
            )

    print(
        "\nLimitations: results come from generated scenarios and "
        "one feedback example per training run. They are not evidence "
        "of real-network generalization or production detection accuracy."
    )


if __name__ == "__main__":
    main()
