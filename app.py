import pandas as pd

from ai.anomaly_detector import detect_anomalies
from ai.risk_engine import apply_risk_engine
from security.response_engine import apply_response_engine


def run_security_pipeline():

    print("\n" + "=" * 60)
    print("      AI CLOUD CYBERSECURITY ENGINE")
    print("=" * 60)

    # 1. Load and analyze cloud activity
    df = detect_anomalies("data/sample_logs.csv")

    print(f"\nTotal security events: {len(df)}")

    # 2. Calculate security risk
    df = apply_risk_engine(df)

    # 3. Determine automated response
    df = apply_response_engine(df)

    # Display important security events
    threats = df[df["risk_level"].isin(
        ["MEDIUM", "HIGH", "CRITICAL"]
    )]

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
                    "risk_score",
                    "risk_level",
                    "recommended_action"
                ]
            ].to_string(index=False)
        )

    print("\n===== SECURITY SUMMARY =====")

    print("\nRisk Distribution:")
    print(df["risk_level"].value_counts().to_string())

    print("\nResponse Distribution:")
    print(
        df["recommended_action"]
        .value_counts()
        .to_string()
    )

    print("\n" + "=" * 60)
    print("Security analysis completed.")
    print("=" * 60)

    return df


if __name__ == "__main__":
    run_security_pipeline()