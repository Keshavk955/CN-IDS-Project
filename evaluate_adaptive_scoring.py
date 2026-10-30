"""Compare base and alert-type-specific weights on synthetic traffic."""

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
from ids.simulation import (
    generate_demo_packets,
    generate_benign_burst,
)


def component_scores(alert):
    return {
        "rule": float(alert["rule_score"]),
        "ml": float(alert["ml_score"]),
        "anomaly": float(alert["anomaly_score"]),
        "historical": float(alert["historical_score"]),
    }


def score_with(alert, weights):
    scores = component_scores(alert)

    return calculate_risk_score(
        scores["rule"],
        scores["ml"],
        scores["anomaly"],
        scores["historical"],
        weights,
    )


def main():
    with tempfile.TemporaryDirectory(
        prefix="cn_ids_context_eval_"
    ) as temp_dir:
        temp = Path(temp_dir)

        db = Database(temp / "evaluation.db")

        ml = MLAnomalyDetector(
            temp / "evaluation_model.joblib"
        )

        engine = DetectionEngine(db, ml)

        attack_alerts = []

        for packet in generate_demo_packets(seed=7):
            alert = engine.process(
                packet,
                simulated=True,
            )

            if alert:
                attack_alerts.append(alert)

        benign_alerts = []

        for packet in generate_benign_burst(seed=19):
            alert = engine.process(
                packet,
                simulated=True,
            )

            if alert:
                benign_alerts.append(alert)

        benign_row = next(
            (
                row
                for row in db.get_alerts(limit=1000)
                if row["source_ip"] == "192.0.2.40"
            ),
            None,
        )

        if benign_row is None:
            raise RuntimeError(
                "No alert was generated for the labelled benign burst."
            )

        old_pattern_weights, new_pattern_weights = (
            db.apply_feedback(
                benign_row["id"],
                "FALSE_POSITIVE",
            )
        )

        print("ISOLATED SYNTHETIC EVALUATION")

        print(
            "No live packets sent; project database and "
            "saved model were not changed."
        )

        print("Attack-demo alerts:", len(attack_alerts))
        print("Benign-burst alerts:", len(benign_alerts))

        print(
            "False-positive feedback applied to:",
            benign_row["attack_type"],
        )

        print("\nBase weights:")

        for name, weight in DEFAULT_WEIGHTS.items():
            print(f"  {name:12s} {weight:.1%}")

        print(
            "\nWeights for the reviewed alert type before feedback:"
        )

        for name, weight in old_pattern_weights.items():
            print(f"  {name:12s} {weight:.1%}")

        print(
            "Weights for the reviewed alert type after feedback:"
        )

        for name, weight in new_pattern_weights.items():
            print(f"  {name:12s} {weight:.1%}")

        print(
            "\nSame component scores, rescored with the relevant weights:"
        )

        print(
            f"{'Scenario':28s} {'Label':8s} "
            f"{'Base':>9s} {'After feedback':>15s} {'Change':>9s}"
        )

        print("-" * 76)

        for alert in attack_alerts + benign_alerts:
            is_benign = (
                alert.get("source_ip") == "192.0.2.40"
            )

            label = "BENIGN" if is_benign else "ATTACK"

            base_score = score_with(
                alert,
                DEFAULT_WEIGHTS,
            )

            contextual_weights = db.get_weights(
                alert["attack_type"]
            )

            after_score = score_with(
                alert,
                contextual_weights,
            )

            print(
                f"{alert['attack_type'][:28]:28s} "
                f"{label:8s} "
                f"{base_score:9.2f} "
                f"{after_score:15.2f} "
                f"{after_score - base_score:+9.2f}"
            )

            print(
                f"  Severity: {get_risk_level(base_score)}"
                f" -> {get_risk_level(after_score)}"
            )

        print(
            "\nExpected behavior: only HIGH PACKET RATE DETECTED "
            "uses the newly learned weights."
        )

        print(
            "Port-scan and ICMP scores should remain at their "
            "base-weight values."
        )

        print(
            "This is a small synthetic demonstration, "
            "not a real-world accuracy benchmark."
        )


if __name__ == "__main__":
    main()