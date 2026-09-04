from ai.anomaly_detector import detect_anomalies
from security.threat_detector import apply_behavior_analysis
from security.contextual_risk_engine import apply_contextual_risk
from security.explanation_engine import apply_explanation_engine
from security.response_engine import apply_response_engine


def run_security_pipeline():

    print("\n" + "=" * 60)
    print("      AI CLOUD CYBERSECURITY ENGINE")
    print("=" * 60)

    # 1. AI anomaly detection
    df = detect_anomalies("data/sample_logs.csv")

    print(f"\nTotal security events: {len(df)}")

    # 2. Behavioral analysis
    baseline, results = apply_behavior_analysis(df)

    print(f"Historical baseline events: {len(baseline)}")
    print(f"Events evaluated: {len(results)}")

    # 3. Contextual risk analysis
    results = apply_contextual_risk(results)

    # 4. Explainable AI
    results = apply_explanation_engine(results)

    # 5. Adaptive response
    results = apply_response_engine(results)

    # Display important security events
    threats = results[
        results["contextual_risk_level"].isin(
            ["MEDIUM", "HIGH", "CRITICAL"]
        )
    ]

    print("\n===== DETECTED SECURITY THREATS =====\n")

    if len(threats) == 0:
        print("No significant threats detected.")
    else:
        print(
            threats[
                [
                    "timestamp",
                    "user",
                    "source_ip",
                    "action",
                    "contextual_risk_score",
                    "contextual_risk_level",
                    "recommended_response"
                ]
            ]
            .sort_values(
                "contextual_risk_score",
                ascending=False
            )
            .head(20)
            .to_string(index=False)
        )

    print("\n===== SECURITY SUMMARY =====")

    print("\nAI Threat Distribution:")
    print(
        results["threat_status"]
        .value_counts()
        .to_string()
    )

    print("\nContextual Risk Distribution:")
    print(
        results["contextual_risk_level"]
        .value_counts()
        .to_string()
    )

    print("\nResponse Distribution:")
    print(
        results["recommended_response"]
        .value_counts()
        .to_string()
    )

    print("\n" + "=" * 60)
    print("Security analysis completed successfully.")
    print("=" * 60)

    return results


if __name__ == "__main__":
    run_security_pipeline()
