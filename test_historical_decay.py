import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ids.database import Database
from ids.risk_scoring import DEFAULT_WEIGHTS


class HistoricalDecayTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(self.temp_dir.name) / "history_test.db"
        self.db = Database(db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def insert_test_alert(self, source_ip, timestamp):
        self.db.insert_alert({
            "timestamp": timestamp.isoformat(),
            "source_ip": source_ip,
            "destination_ip": "192.0.2.100",
            "attack_type": "TEST ALERT",
            "severity": "MEDIUM",
            "risk_score": 50,
            "detection_method": "test",
            "details": "Historical decay unit test",
            "rule_score": 50,
            "ml_score": 40,
            "anomaly_score": 30,
            "historical_score": 0,
            "weights": DEFAULT_WEIGHTS,
            "is_simulated": True,
        })

    def test_no_history_has_zero_score(self):
        score = self.db.get_historical_score("192.0.2.10")
        self.assertEqual(score, 0)

    def test_recent_alert_contributes_more_than_old_alert(self):
        now = datetime.now(timezone.utc)

        self.insert_test_alert("192.0.2.10", now)
        self.insert_test_alert(
            "192.0.2.11",
            now - timedelta(seconds=900),
        )

        recent = self.db.get_historical_score(
            "192.0.2.10",
            half_life_seconds=900,
            points_per_alert=20,
        )

        older = self.db.get_historical_score(
            "192.0.2.11",
            half_life_seconds=900,
            points_per_alert=20,
        )

        self.assertGreater(recent, older)
        self.assertAlmostEqual(
            older / recent,
            0.5,
            delta=0.05,
        )

    def test_multiple_alerts_accumulate(self):
        now = datetime.now(timezone.utc)

        self.insert_test_alert("192.0.2.12", now)
        one_alert_score = self.db.get_historical_score(
            "192.0.2.12",
            half_life_seconds=900,
            points_per_alert=20,
        )

        self.insert_test_alert("192.0.2.13", now)
        self.insert_test_alert("192.0.2.13", now)

        two_alert_score = self.db.get_historical_score(
            "192.0.2.13",
            half_life_seconds=900,
            points_per_alert=20,
        )

        self.assertGreater(two_alert_score, one_alert_score)

    def test_historical_score_is_capped_at_100(self):
        now = datetime.now(timezone.utc)

        for _ in range(6):
            self.insert_test_alert("192.0.2.14", now)

        score = self.db.get_historical_score(
            "192.0.2.14",
            half_life_seconds=900,
            points_per_alert=20,
        )

        self.assertEqual(score, 100.0)


if __name__ == "__main__":
    unittest.main()