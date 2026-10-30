
def validate_score(name, score):
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError(f"{name} must be a number.")

    if not 0 <= score <= 100:
        raise ValueError(f"{name} must be between 0 and 100.")


def calculate_risk_score(rule_score, ml_score, anomaly_score, historical_score):
    scores = {
        "Rule score": rule_score,
        "ML score": ml_score,
        "Anomaly score": anomaly_score,
        "Historical score": historical_score
    }

    for name, score in scores.items():
        validate_score(name, score)

    risk_score = (
        0.35 * rule_score
        + 0.35 * ml_score
        + 0.20 * anomaly_score
        + 0.10 * historical_score
    )

    return round(risk_score, 2)


def calculate_rule_only_score(rule_score):
    validate_score("Rule score", rule_score)
    return round(rule_score, 2)


def get_risk_level(risk_score):
    validate_score("Risk score", risk_score)

    if risk_score <= 25:
        return "SAFE"
    elif risk_score <= 50:
        return "LOW"
    elif risk_score <= 70:
        return "MEDIUM"
    elif risk_score <= 85:
        return "HIGH"
    else:
        return "CRITICAL"
