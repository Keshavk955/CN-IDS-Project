
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ids.database import Database
from ids.risk_scoring import DEFAULT_WEIGHTS


class FalsePositiveHistoryTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(
            Path(self.temp_dir.name) / "history_feedback.db"
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def add_alert(self, source_ip):
        return self.db.insert_alert({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "destination_ip": "192.0.2.100",
            "attack_type": "TEST ALERT",
            "severity": "MEDIUM",
            "risk_score": 50,
            "detection_method": "test",
            "details": "Synthetic regression test",
            "rule_score": 50,
            "ml_score": 40,
            "anomaly_score": 30,
            "historical_score": 0,
            "weights": DEFAULT_WEIGHTS,
            "is_simulated": True,
        })

    def test_false_positive_does_not_add_historical_risk(self):
        source = "192.0.2.10"
        alert_id = self.add_alert(source)

        self.db.apply_feedback(alert_id, "FALSE_POSITIVE")

        score = self.db.get_historical_score(source)

        self.assertEqual(score, 0.0)

    def test_unreviewed_history_still_contributes(self):
        source = "192.0.2.11"

        false_positive_id = self.add_alert(source)
        self.add_alert(source)

        self.db.apply_feedback(
            false_positive_id,
            "FALSE_POSITIVE",
        )

        score = self.db.get_historical_score(
            source,
            half_life_seconds=900,
            points_per_alert=20,
        )

        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 20.0)


if __name__ == "__main__":
    unittest.main()
