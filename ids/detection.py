from collections import defaultdict, deque
from datetime import datetime, timezone

from .config import *
from .risk_scoring import calculate_risk_score, get_risk_level


def utc_now():
    return datetime.now(timezone.utc).astimezone().isoformat(
        timespec="seconds"
    )


def severity_for_score(score):
    return get_risk_level(score)


class DetectionEngine:
    """Window-based detection with alert-type-specific adaptive weights."""

    def __init__(self, database, ml_detector):
        self.db = database
        self.ml = ml_detector
        self.events = defaultdict(deque)
        self.last_alert = {}

    def process(self, packet, simulated=False):
        packet = dict(packet)
        packet.setdefault("timestamp", utc_now())
        packet.setdefault("flags", "")

        if not packet.get("source_ip"):
            return None

        self.db.insert_traffic(packet, simulated=simulated)

        source_ip = packet["source_ip"]
        queue = self.events[source_ip]
        now = datetime.now().timestamp()

        queue.append((now, packet))

        while (
            queue
            and now - queue[0][0] > PORT_SCAN_WINDOW_SECONDS
        ):
            queue.popleft()

        current = [
            item for item in queue
            if now - item[0] <= PACKET_RATE_WINDOW_SECONDS
        ]

        packets_5s = len(current)

        unique_ports = len({
            item.get("destination_port")
            for _, item in queue
            if item.get("destination_port") is not None
        })

        icmp_count = sum(
            item.get("protocol") == "ICMP"
            for _, item in current
        )

        syn_count = sum(
            "S" in item.get("flags", "")
            for _, item in current
        )

        icmp_ratio = icmp_count / max(packets_5s, 1)
        syn_ratio = syn_count / max(packets_5s, 1)

        features = {
            "packets_per_window": packets_5s,
            "unique_dst_ports": unique_ports,
            "icmp_ratio": icmp_ratio,
            "syn_ratio": syn_ratio,
            "mean_packet_size": (
                sum(
                    item.get("packet_size", 0)
                    for _, item in current
                )
                / max(packets_5s, 1)
            ),
            "unique_destinations": len({
                item.get("destination_ip")
                for _, item in current
            }),
        }

        rule_reasons = []
        rule_score = 0.0

        if (
            unique_ports >= PORT_SCAN_UNIQUE_PORTS
            and packet.get("protocol") in ("TCP", "UDP")
        ):
            rule_reasons.append(
                f"Port-scan pattern: {unique_ports} unique "
                f"destination ports in {PORT_SCAN_WINDOW_SECONDS} seconds"
            )
            rule_score = max(rule_score, 90)

        if packets_5s >= PACKET_RATE_THRESHOLD:
            rule_reasons.append(
                f"High packet rate: {packets_5s} packets in "
                f"{PACKET_RATE_WINDOW_SECONDS} seconds"
            )
            rule_score = max(rule_score, 85)

        if (
            icmp_count >= ICMP_RATE_THRESHOLD
            and icmp_ratio > 0
        ):
            rule_reasons.append(
                f"ICMP flood pattern: {icmp_count} ICMP packets "
                f"in {PACKET_RATE_WINDOW_SECONDS} seconds"
            )
            rule_score = max(rule_score, 88)

        if syn_count >= SYN_RATE_THRESHOLD:
            rule_reasons.append(
                "Possible SYN flood: repeated TCP SYN packets"
            )
            rule_score = max(rule_score, 90)

        ml_score = float(self.ml.score(features))

        signal_scores = {
            "packet_rate": min(
                100.0,
                packets_5s / max(PACKET_RATE_THRESHOLD, 1) * 100.0,
            ),
            "unique_ports": min(
                100.0,
                unique_ports / max(PORT_SCAN_UNIQUE_PORTS, 1) * 100.0,
            ),
            "icmp_rate": min(
                100.0,
                icmp_count / max(ICMP_RATE_THRESHOLD, 1) * 100.0,
            ),
            "syn_rate": min(
                100.0,
                syn_count / max(SYN_RATE_THRESHOLD, 1) * 100.0,
            ),
        }

        # Use the strongest signal instead of allowing an unrelated
        # zero-valued signal to suppress a real single-pattern anomaly.
        anomaly_score = round(max(signal_scores.values()), 2)

        historical_score = self.db.get_historical_score(source_ip)

        component_scores = {
            "rule": float(rule_score),
            "ml": max(0.0, min(100.0, ml_score)),
            "anomaly": anomaly_score,
            "historical": historical_score,
        }

        reasons = list(rule_reasons)
        ml_flagged = ml_score >= 75

        if ml_flagged:
            reasons.append(
                f"ML anomaly detector flagged unusual traffic "
                f"(score {ml_score:.1f}/100)"
            )

        if not reasons:
            return None

        # Identify the alert family before scoring so that feedback for
        # one family cannot change scores for unrelated alert families.
        if any(
            "Port-scan pattern" in reason
            for reason in rule_reasons
        ):
            attack_type = "PORT SCAN DETECTED"
        elif any(
            "ICMP flood" in reason
            for reason in rule_reasons
        ):
            attack_type = "ICMP FLOOD DETECTED"
        elif any(
            "SYN flood" in reason
            for reason in rule_reasons
        ):
            attack_type = "SYN FLOOD DETECTED"
        elif any(
            "High packet rate" in reason
            for reason in rule_reasons
        ):
            attack_type = "HIGH PACKET RATE DETECTED"
        else:
            attack_type = "ML-DETECTED TRAFFIC ANOMALY"

        # Each alert type receives its own learned weights. An alert type
        # with no reviewed feedback continues using the base weights.
        weights = self.db.get_weights(attack_type)

        risk = calculate_risk_score(
            component_scores["rule"],
            component_scores["ml"],
            component_scores["anomaly"],
            component_scores["historical"],
            weights,
        )

        signature = (source_ip, attack_type)

        if now - self.last_alert.get(signature, 0) < 10:
            return None

        self.last_alert[signature] = now

        if rule_reasons and ml_flagged:
            method = "hybrid"
        elif rule_reasons:
            method = "rule-based"
        else:
            method = "machine-learning"

        score_details = ", ".join(
            (
                f"{name}={value:.1f} "
                f"(weight {weights[name]:.1%}, "
                f"contribution {value * weights[name]:.1f})"
            )
            for name, value in component_scores.items()
        )

        alert = {
            "timestamp": packet["timestamp"],
            "source_ip": source_ip,
            "destination_ip": packet.get("destination_ip", ""),
            "attack_type": attack_type,
            "severity": get_risk_level(risk),
            "risk_score": risk,
            "detection_method": method,
            "details": (
                " | ".join(reasons)
                + f" | Features: packets/5s={packets_5s}, "
                f"unique ports/10s={unique_ports}, "
                f"ICMP ratio={icmp_ratio:.2f}, "
                f"SYN ratio={syn_ratio:.2f}. | "
                f"Score breakdown: {score_details}"
            ),
            "rule_score": component_scores["rule"],
            "ml_score": component_scores["ml"],
            "anomaly_score": component_scores["anomaly"],
            "historical_score": component_scores["historical"],
            "weights": weights,
            "is_simulated": simulated,
        }

        if packet.get("scenario_label"):
            alert["details"] += (
                f" | Scenario label: {packet['scenario_label']}"
            )

        self.db.insert_alert(alert)
        return alert