"""Risk calculation and bounded feedback-guided weight adaptation."""
import math

COMPONENTS = ("rule", "ml", "anomaly", "historical")
DEFAULT_WEIGHTS = {
    "rule": 0.35,
    "ml": 0.35,
    "anomaly": 0.20,
    "historical": 0.10,
}
MIN_WEIGHT = 0.05
MAX_WEIGHT = 0.65


def _validate_scores(scores):
    if any(
        isinstance(scores.get(name), bool)
        or not isinstance(scores.get(name), (int, float))
        or not 0 <= scores[name] <= 100
        for name in COMPONENTS
    ):
        raise ValueError("All risk inputs must be numeric values between 0 and 100.")


def normalize_weights(weights):
    values = {name: float(weights.get(name, DEFAULT_WEIGHTS[name])) for name in COMPONENTS}
    if any(not math.isfinite(v) or v <= 0 for v in values.values()):
        raise ValueError("All component weights must be finite positive numbers.")
    total = sum(values.values())
    return {name: values[name] / total for name in COMPONENTS}


def calculate_risk_score(rule_score, ml_score, anomaly_score, historical_score, weights=None):
    scores = dict(zip(COMPONENTS, (rule_score, ml_score, anomaly_score, historical_score)))
    _validate_scores(scores)
    used_weights = normalize_weights(weights or DEFAULT_WEIGHTS)
    return round(sum(scores[name] * used_weights[name] for name in COMPONENTS), 2)


def calculate_contributions(scores, weights):
    """Return each component's weighted contribution to the final 0-100 score."""
    _validate_scores(scores)
    used_weights = normalize_weights(weights)
    return {name: round(float(scores[name]) * used_weights[name], 2) for name in COMPONENTS}


def _bounded_simplex(values, lower=MIN_WEIGHT, upper=MAX_WEIGHT):
    """Normalize values to sum to one while keeping each weight within bounds."""
    positive = {name: max(float(values[name]), 1e-12) for name in COMPONENTS}
    fixed = {}
    free = list(COMPONENTS)
    remaining = 1.0

    for _ in range(len(COMPONENTS) + 2):
        if not free:
            break
        scale = remaining / sum(positive[name] for name in free)
        proposed = {name: positive[name] * scale for name in free}
        too_low = [name for name in free if proposed[name] < lower]
        too_high = [name for name in free if proposed[name] > upper]
        if not too_low and not too_high:
            fixed.update(proposed)
            return {name: round(fixed[name], 6) for name in COMPONENTS}
        for name in too_low:
            fixed[name] = lower
            remaining -= lower
            free.remove(name)
        for name in too_high:
            if name in free:
                fixed[name] = upper
                remaining -= upper
                free.remove(name)
    if len(fixed) == len(COMPONENTS):
        total = sum(fixed.values())
        return {name: round(fixed[name] / total, 6) for name in COMPONENTS}
    # This fallback is defensive; ordinary updates return from the loop above.
    return normalize_weights(fixed | {name: positive[name] for name in free})


def adapt_weights(weights, scores, feedback_label, learning_rate=0.5):
    """Adjust relative signal weights using a transparent analyst-feedback rule.

    For a confirmed attack, above-average component scores are rewarded. For a
    false positive, above-average component scores are penalized. This is a
    lightweight heuristic, not a statistically calibrated learning model.
    """
    label = str(feedback_label).upper()
    if label not in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
        raise ValueError("Feedback must be TRUE_POSITIVE or FALSE_POSITIVE.")
    _validate_scores(scores)
    current = normalize_weights(weights or DEFAULT_WEIGHTS)
    normalized_scores = {name: float(scores[name]) / 100.0 for name in COMPONENTS}
    mean_score = sum(normalized_scores.values()) / len(COMPONENTS)
    direction = 1.0 if label == "TRUE_POSITIVE" else -1.0

    logits = {
        name: math.log(max(current[name], 1e-12))
        + direction * learning_rate * (normalized_scores[name] - mean_score)
        for name in COMPONENTS
    }
    peak = max(logits.values())
    exponentials = {name: math.exp(logits[name] - peak) for name in COMPONENTS}
    return _bounded_simplex(exponentials)


def get_risk_level(score):
    if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100.")
    if score <= 25:
        return "SAFE"
    if score <= 50:
        return "LOW"
    if score <= 70:
        return "MEDIUM"
    if score <= 85:
        return "HIGH"
    return "CRITICAL"
