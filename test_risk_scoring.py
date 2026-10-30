from risk_scoring import calculate_risk_score, get_risk_level


def run_test(rule_score, ml_score, anomaly_score, historical_score):
    risk_score = calculate_risk_score(
        rule_score,
        ml_score,
        anomaly_score,
        historical_score
    )

    risk_level = get_risk_level(risk_score)

    print(f"Rule Score: {rule_score}")
    print(f"ML Score: {ml_score}")
    print(f"Anomaly Score: {anomaly_score}")
    print(f"Historical Score: {historical_score}")
    print(f"Final Risk Score: {risk_score}")
    print(f"Risk Level: {risk_level}")
    print("-" * 40)


print("TEST 1: All scores are zero")
run_test(0, 0, 0, 0)

print("TEST 2: Moderate scores")
run_test(50, 40, 60, 30)

print("TEST 3: High scores")
run_test(90, 85, 80, 70)

print("TEST 4: Maximum scores")
run_test(100, 100, 100, 100)