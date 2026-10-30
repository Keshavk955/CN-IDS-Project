
"""SQLite storage for traffic, alerts and per-alert-type adaptive risk weights."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import DB_PATH
from .risk_scoring import (
    COMPONENTS,
    DEFAULT_WEIGHTS,
    adapt_weights,
    normalize_weights,
)


class Database:
    def __init__(self, path=None):
        self.path = str(path or DB_PATH)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def initialize(self):
        with self.connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score REAL NOT NULL DEFAULT 0,
                    detection_method TEXT NOT NULL DEFAULT 'rule-based',
                    details TEXT NOT NULL DEFAULT '',
                    acknowledged INTEGER NOT NULL DEFAULT 0
                )
            """)

            con.execute("""
                CREATE TABLE IF NOT EXISTS traffic_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    source_port INTEGER,
                    destination_port INTEGER,
                    packet_size INTEGER NOT NULL,
                    flags TEXT NOT NULL DEFAULT '',
                    is_simulated INTEGER NOT NULL DEFAULT 0
                )
            """)

            cols = {
                row["name"]
                for row in con.execute("PRAGMA table_info(alerts)")
            }

            migrations = [
                ("risk_score", "REAL NOT NULL DEFAULT 0"),
                ("detection_method", "TEXT NOT NULL DEFAULT 'rule-based'"),
                ("acknowledged", "INTEGER NOT NULL DEFAULT 0"),
                ("rule_score", "REAL NOT NULL DEFAULT 0"),
                ("ml_score", "REAL NOT NULL DEFAULT 0"),
                ("anomaly_score", "REAL NOT NULL DEFAULT 0"),
                ("historical_score", "REAL NOT NULL DEFAULT 0"),
                ("rule_weight", "REAL NOT NULL DEFAULT 0.35"),
                ("ml_weight", "REAL NOT NULL DEFAULT 0.35"),
                ("anomaly_weight", "REAL NOT NULL DEFAULT 0.20"),
                ("historical_weight", "REAL NOT NULL DEFAULT 0.10"),
                ("feedback_label", "TEXT"),
                ("feedback_at", "TEXT"),
                ("is_simulated", "INTEGER NOT NULL DEFAULT 0"),
            ]

            for name, definition in migrations:
                if name not in cols:
                    con.execute(
                        f"ALTER TABLE alerts ADD COLUMN {name} {definition}"
                    )

            con.execute("""
                CREATE TABLE IF NOT EXISTS adaptive_weights (
                    component TEXT PRIMARY KEY,
                    weight REAL NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

            for component, weight in DEFAULT_WEIGHTS.items():
                con.execute(
                    """
                    INSERT OR IGNORE INTO adaptive_weights
                    (component, weight, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    (component, weight, stamp),
                )

            con.execute("""
                CREATE TABLE IF NOT EXISTS pattern_weights (
                    attack_type TEXT PRIMARY KEY,
                    rule_weight REAL NOT NULL,
                    ml_weight REAL NOT NULL,
                    anomaly_weight REAL NOT NULL,
                    historical_weight REAL NOT NULL,
                    feedback_count INTEGER NOT NULL DEFAULT 0,
                    true_positive_count INTEGER NOT NULL DEFAULT 0,
                    false_positive_count INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
            """)

            con.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    name TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
            """)

            con.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                ON alerts(timestamp)
            """)

            con.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_source
                ON alerts(source_ip)
            """)

            con.execute("""
                CREATE INDEX IF NOT EXISTS idx_traffic_timestamp
                ON traffic_events(timestamp)
            """)

            migration_name = "backfill_pattern_weights_from_feedback_v1"

            done = con.execute(
                """
                SELECT 1 FROM schema_migrations
                WHERE name = ?
                """,
                (migration_name,),
            ).fetchone()

            if not done:
                types = con.execute("""
                    SELECT DISTINCT attack_type
                    FROM alerts
                    WHERE feedback_label IN (
                        'TRUE_POSITIVE', 'FALSE_POSITIVE'
                    )
                """).fetchall()

                for type_row in types:
                    attack_type = type_row["attack_type"]
                    weights = dict(DEFAULT_WEIGHTS)
                    tp_count = 0
                    fp_count = 0

                    rows = con.execute(
                        """
                        SELECT *
                        FROM alerts
                        WHERE attack_type = ?
                        AND feedback_label IN (?, ?)
                        ORDER BY id
                        """,
                        (
                            attack_type,
                            "TRUE_POSITIVE",
                            "FALSE_POSITIVE",
                        ),
                    ).fetchall()

                    for row in rows:
                        scores = {
                            name: float(row[f"{name}_score"] or 0)
                            for name in COMPONENTS
                        }

                        weights = adapt_weights(
                            weights,
                            scores,
                            row["feedback_label"],
                        )

                        if row["feedback_label"] == "TRUE_POSITIVE":
                            tp_count += 1
                        else:
                            fp_count += 1

                    con.execute("""
                        INSERT OR IGNORE INTO pattern_weights (
                            attack_type,
                            rule_weight,
                            ml_weight,
                            anomaly_weight,
                            historical_weight,
                            feedback_count,
                            true_positive_count,
                            false_positive_count,
                            updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        attack_type,
                        weights["rule"],
                        weights["ml"],
                        weights["anomaly"],
                        weights["historical"],
                        tp_count + fp_count,
                        tp_count,
                        fp_count,
                        stamp,
                    ))

                con.execute(
                    """
                    INSERT INTO schema_migrations (name, applied_at)
                    VALUES (?, ?)
                    """,
                    (migration_name, stamp),
                )

    def insert_traffic(self, packet, simulated=False):
        with self.connect() as con:
            con.execute("""
                INSERT INTO traffic_events (
                    timestamp,
                    source_ip,
                    destination_ip,
                    protocol,
                    source_port,
                    destination_port,
                    packet_size,
                    flags,
                    is_simulated
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                packet.get("timestamp"),
                packet.get("source_ip", "unknown"),
                packet.get("destination_ip", "unknown"),
                packet.get("protocol", "Other"),
                packet.get("source_port"),
                packet.get("destination_port"),
                int(packet.get("packet_size", 0)),
                packet.get("flags", ""),
                int(simulated),
            ))

    def insert_alert(self, alert):
        scores = {
            name: float(alert.get(f"{name}_score", 0))
            for name in COMPONENTS
        }

        weights = normalize_weights(
            alert.get("weights")
            or self.get_weights(alert.get("attack_type"))
        )

        with self.connect() as con:
            cursor = con.execute("""
                INSERT INTO alerts (
                    timestamp,
                    source_ip,
                    destination_ip,
                    attack_type,
                    severity,
                    risk_score,
                    detection_method,
                    details,
                    rule_score,
                    ml_score,
                    anomaly_score,
                    historical_score,
                    rule_weight,
                    ml_weight,
                    anomaly_weight,
                    historical_weight,
                    is_simulated
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["timestamp"],
                alert["source_ip"],
                alert.get("destination_ip", ""),
                alert["attack_type"],
                alert["severity"],
                float(alert.get("risk_score", 0)),
                alert.get("detection_method", "rule-based"),
                alert.get("details", ""),
                scores["rule"],
                scores["ml"],
                scores["anomaly"],
                scores["historical"],
                weights["rule"],
                weights["ml"],
                weights["anomaly"],
                weights["historical"],
                int(bool(alert.get("is_simulated", False))),
            ))

            return cursor.lastrowid

    def get_alerts(self, limit=500, include_acknowledged=True):
        with self.connect() as con:
            sql = "SELECT * FROM alerts"

            if not include_acknowledged:
                sql += " WHERE acknowledged = 0"

            rows = con.execute(
                sql + " ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()

            return [dict(row) for row in rows]

    def get_traffic(self, limit=2000):
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT * FROM traffic_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()

            return [dict(row) for row in rows]

    def acknowledge(self, alert_id):
        with self.connect() as con:
            con.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                (int(alert_id),),
            )

    def get_weights(self, attack_type=None):
        """Return base weights or weights learned for one alert type."""
        if not attack_type:
            return dict(DEFAULT_WEIGHTS)

        with self.connect() as con:
            row = con.execute(
                """
                SELECT * FROM pattern_weights
                WHERE attack_type = ?
                """,
                (str(attack_type),),
            ).fetchone()

        if row is None:
            return dict(DEFAULT_WEIGHTS)

        return normalize_weights({
            name: float(row[f"{name}_weight"])
            for name in COMPONENTS
        })

    def get_pattern_weights(self):
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM pattern_weights ORDER BY attack_type"
            ).fetchall()

        result = []

        for row in rows:
            item = {
                "attack_type": row["attack_type"],
                "feedback_count": int(row["feedback_count"]),
                "true_positive_count": int(row["true_positive_count"]),
                "false_positive_count": int(row["false_positive_count"]),
            }

            for name in COMPONENTS:
                item[name] = float(row[f"{name}_weight"])

            result.append(item)

        return result

    def save_weights(self, weights):
        """Persist legacy global weights for backward compatibility."""
        weights = normalize_weights(weights)
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

        with self.connect() as con:
            for component, weight in weights.items():
                con.execute("""
                    INSERT INTO adaptive_weights
                    (component, weight, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(component) DO UPDATE SET
                        weight = excluded.weight,
                        updated_at = excluded.updated_at
                """, (component, weight, stamp))

        return weights

    def reset_weights(self):
        """Reset learned pattern weights while retaining feedback history."""
        with self.connect() as con:
            con.execute("DELETE FROM pattern_weights")

        self.save_weights(DEFAULT_WEIGHTS)
        return dict(DEFAULT_WEIGHTS)

    def apply_feedback(self, alert_id, label):
        """Update weights only for the alert type being reviewed."""
        label = str(label).upper()

        if label not in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
            raise ValueError(
                "Feedback must be TRUE_POSITIVE or FALSE_POSITIVE."
            )

        with self.connect() as con:
            row = con.execute(
                "SELECT * FROM alerts WHERE id = ?",
                (int(alert_id),),
            ).fetchone()

            if row is None:
                raise ValueError(f"Alert #{alert_id} does not exist.")

            if row["feedback_label"]:
                raise ValueError(
                    f"Alert #{alert_id} already has feedback: "
                    f"{row['feedback_label']}."
                )

            attack_type = row["attack_type"]

            pattern = con.execute(
                """
                SELECT * FROM pattern_weights
                WHERE attack_type = ?
                """,
                (attack_type,),
            ).fetchone()

            if pattern is None:
                current = dict(DEFAULT_WEIGHTS)
                tp_count = 0
                fp_count = 0
            else:
                current = normalize_weights({
                    name: float(pattern[f"{name}_weight"])
                    for name in COMPONENTS
                })

                tp_count = int(pattern["true_positive_count"])
                fp_count = int(pattern["false_positive_count"])

            scores = {
                name: float(row[f"{name}_score"] or 0)
                for name in COMPONENTS
            }

            updated = adapt_weights(current, scores, label)

            if label == "TRUE_POSITIVE":
                tp_count += 1
            else:
                fp_count += 1

            feedback_count = tp_count + fp_count
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

            con.execute(
                """
                UPDATE alerts
                SET feedback_label = ?, feedback_at = ?
                WHERE id = ?
                """,
                (label, stamp, int(alert_id)),
            )

            con.execute("""
                INSERT INTO pattern_weights (
                    attack_type,
                    rule_weight,
                    ml_weight,
                    anomaly_weight,
                    historical_weight,
                    feedback_count,
                    true_positive_count,
                    false_positive_count,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(attack_type) DO UPDATE SET
                    rule_weight = excluded.rule_weight,
                    ml_weight = excluded.ml_weight,
                    anomaly_weight = excluded.anomaly_weight,
                    historical_weight = excluded.historical_weight,
                    feedback_count = excluded.feedback_count,
                    true_positive_count = excluded.true_positive_count,
                    false_positive_count = excluded.false_positive_count,
                    updated_at = excluded.updated_at
            """, (
                attack_type,
                updated["rule"],
                updated["ml"],
                updated["anomaly"],
                updated["historical"],
                feedback_count,
                tp_count,
                fp_count,
                stamp,
            ))

            return current, updated

    def get_feedback_counts(self):
        with self.connect() as con:
            rows = con.execute("""
                SELECT feedback_label, COUNT(*) AS n
                FROM alerts
                WHERE feedback_label IS NOT NULL
                GROUP BY feedback_label
            """).fetchall()

        result = {
            "TRUE_POSITIVE": 0,
            "FALSE_POSITIVE": 0,
        }

        result.update({
            row["feedback_label"]: int(row["n"])
            for row in rows
        })

        return result

    def get_historical_score(
        self,
        source_ip,
        half_life_seconds=900,
        points_per_alert=20,
    ):
        """Calculate decayed source reputation, excluding false positives."""
        with self.connect() as con:
            rows = con.execute(
                """
                SELECT timestamp
                FROM alerts
                WHERE source_ip = ?
                  AND COALESCE(feedback_label, '') != 'FALSE_POSITIVE'
                ORDER BY id DESC
                LIMIT 500
                """,
                (source_ip,),
            ).fetchall()

        now = datetime.now(timezone.utc)
        score = 0.0

        for row in rows:
            try:
                event_time = datetime.fromisoformat(row["timestamp"])

                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)

                age = max(
                    0.0,
                    (
                        now - event_time.astimezone(timezone.utc)
                    ).total_seconds(),
                )

                score += points_per_alert * (
                    0.5 ** (age / max(half_life_seconds, 1))
                )

            except (TypeError, ValueError):
                continue

        return round(min(100.0, score), 2)

    def clear_demo_data(self):
        """Clear synthetic records without deleting live traffic records."""
        with self.connect() as con:
            con.execute(
                """
                DELETE FROM alerts
                WHERE is_simulated = 1 OR source_ip LIKE ?
                """,
                ("198.51.100.%",),
            )

            con.execute(
                "DELETE FROM traffic_events WHERE is_simulated = 1"
            )
