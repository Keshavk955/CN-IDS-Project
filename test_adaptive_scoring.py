import tempfile
import unittest
from pathlib import Path

from ids.database import Database
from ids.risk_scoring import (
    COMPONENTS,
    DEFAULT_WEIGHTS,
    adapt_weights,
    calculate_contributions,
    calculate_risk_score,
)


class AdaptiveScoringTests(unittest.TestCase):

    def test_original_default_formula_is_preserved(self):
        self.assertEqual(
            calculate_risk_score(50, 40, 60, 30),
            46.5,
        )

    def test_adapted_weights_are_normalized_and_bounded(self):
        scores = {
            "rule": 90,
            "ml": 55,
            "anomaly": 100,
            "historical": 10,
        }

        updated = adapt_weights(
            DEFAULT_WEIGHTS,
            scores,
            "TRUE_POSITIVE",
        )

        self.assertAlmostEqual(
            sum(updated.values()),
            1.0,
            places=5,
        )

        self.assertTrue(
            all(0.05 <= value <= 0.65 for value in updated.values())
        )

        self.assertGreater(
            updated["rule"],
            DEFAULT_WEIGHTS["rule"],
        )

        self.assertLess(
            updated["historical"],
            DEFAULT_WEIGHTS["historical"],
        )

    def test_false_positive_adjusts_reviewed_pattern_not_all_patterns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "test.db"
            db = Database(path)

            db.insert_alert({
                "timestamp": "2026-10-28T00:00:00+00:00",
                "source_ip": "192.0.2.40",
                "destination_ip": "192.0.2.100",
                "attack_type": "HIGH PACKET RATE DETECTED",
                "severity": "MEDIUM",
                "risk_score": 68.51,
                "detection_method": "rule-based",
                "details": "test",
                "rule_score": 85,
                "ml_score": 57,
                "anomaly_score": 100,
                "historical_score": 0,
                "weights": DEFAULT_WEIGHTS,
                "is_simulated": True,
            })

            alert_id = db.get_alerts()[0]["id"]

            before, after = db.apply_feedback(
                alert_id,
                "FALSE_POSITIVE",
            )

            self.assertNotEqual(before, after)

            self.assertAlmostEqual(
                sum(after.values()),
                1.0,
                places=5,
            )

            # The default weights remain unchanged for other alert types.
            self.assertEqual(db.get_weights(), DEFAULT_WEIGHTS)

            self.assertEqual(
                db.get_weights("PORT SCAN DETECTED"),
                DEFAULT_WEIGHTS,
            )

            self.assertEqual(
                db.get_weights("ICMP FLOOD DETECTED"),
                DEFAULT_WEIGHTS,
            )

            stored_after = db.get_weights(
                "HIGH PACKET RATE DETECTED"
            )

            for name in COMPONENTS:
                self.assertAlmostEqual(
                    stored_after[name],
                    after[name],
                    places=5,
                )

            rows = db.get_pattern_weights()

            self.assertEqual(len(rows), 1)

            self.assertEqual(
                rows[0]["attack_type"],
                "HIGH PACKET RATE DETECTED",
            )

            self.assertEqual(
                rows[0]["false_positive_count"],
                1,
            )

            # Learned weights must persist after reopening the database.
            reopened = Database(path)

            reopened_weights = reopened.get_weights(
                "HIGH PACKET RATE DETECTED"
            )

            for name in COMPONENTS:
                self.assertAlmostEqual(
                    reopened_weights[name],
                    after[name],
                    places=5,
                )

            # One alert cannot be reviewed twice.
            with self.assertRaises(ValueError):
                reopened.apply_feedback(
                    alert_id,
                    "FALSE_POSITIVE",
                )

    def test_contributions_sum_to_weighted_risk(self):
        scores = {
            "rule": 90,
            "ml": 60,
            "anomaly": 80,
            "historical": 20,
        }

        weights = {
            "rule": 0.30,
            "ml": 0.30,
            "anomaly": 0.25,
            "historical": 0.15,
        }

        contributions = calculate_contributions(
            scores,
            weights,
        )

        total = calculate_risk_score(
            90,
            60,
            80,
            20,
            weights,
        )

        self.assertAlmostEqual(
            sum(contributions.values()),
            total,
            places=2,
        )

    def test_reset_clears_learned_weights_but_keeps_feedback_audit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = Database(Path(temp_dir) / "test.db")

            db.insert_alert({
                "timestamp": "2026-10-28T00:00:00+00:00",
                "source_ip": "192.0.2.40",
                "destination_ip": "192.0.2.100",
                "attack_type": "HIGH PACKET RATE DETECTED",
                "severity": "MEDIUM",
                "risk_score": 68.51,
                "detection_method": "rule-based",
                "details": "test",
                "rule_score": 85,
                "ml_score": 57,
                "anomaly_score": 100,
                "historical_score": 0,
                "weights": DEFAULT_WEIGHTS,
                "is_simulated": True,
            })

            alert_id = db.get_alerts()[0]["id"]

            db.apply_feedback(
                alert_id,
                "FALSE_POSITIVE",
            )

            db.reset_weights()

            self.assertEqual(
                db.get_weights("HIGH PACKET RATE DETECTED"),
                DEFAULT_WEIGHTS,
            )

            self.assertEqual(
                db.get_feedback_counts()["FALSE_POSITIVE"],
                1,
            )

            # Reopening should not recreate the cleared learned weights.
            reopened = Database(db.path)

            self.assertEqual(
                reopened.get_weights("HIGH PACKET RATE DETECTED"),
                DEFAULT_WEIGHTS,
            )


if __name__ == "__main__":
    unittest.main()