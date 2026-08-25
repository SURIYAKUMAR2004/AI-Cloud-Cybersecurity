import pandas as pd


HIGH_RISK_ACTIONS = {
    "CreateUser",
    "ChangePassword",
    "AssumeRole",
    "DeleteObject"
}


def generate_explanation(row):

    reasons = []

    # AI anomaly
    if row["threat_status"] == "Anomaly":
        reasons.append(
            "AI anomaly detector identified unusual activity"
        )

    # Behavioral deviation
    behavior_score = row["behavior_deviation_score"]

    if behavior_score >= 70:
        reasons.append(
            "Severe deviation from the user's behavioral baseline"
        )

    elif behavior_score >= 40:
        reasons.append(
            "High deviation from the user's behavioral baseline"
        )

    elif behavior_score >= 20:
        reasons.append(
            "Moderate deviation from the user's behavioral baseline"
        )

    # High-risk operation
    if row["action"] in HIGH_RISK_ACTIONS:
        reasons.append(
            f"High-risk cloud operation detected: {row['action']}"
        )

    # Failed activity
    if row["status"] == "Failed":
        reasons.append(
            "Failed security operation detected"
        )

    # Large data transfer
    if row["bytes_transferred"] > 50000:
        reasons.append(
            "Unusually large data transfer detected"
        )

    elif row["bytes_transferred"] > 10000:
        reasons.append(
            "Elevated data transfer detected"
        )

    # Unusual time
    hour = row["hour"]

    if hour < 6 or hour > 22:
        reasons.append(
            "Activity occurred outside the normal security window"
        )

    if not reasons:
        reasons.append(
            "No significant security deviation detected"
        )

    return " | ".join(reasons)


def apply_explanation_engine(df):

    df = df.copy()

    df["security_explanation"] = df.apply(
        generate_explanation,
        axis=1
    )

    return df


if __name__ == "__main__":

    from ai.anomaly_detector import detect_anomalies
    from security.threat_detector import (
        apply_behavior_analysis
    )
    from security.contextual_risk_engine import (
        apply_contextual_risk
    )

    # AI anomaly detection
    df = detect_anomalies(
        "data/sample_logs.csv"
    )

    # Behavioral analysis
    baseline, results = apply_behavior_analysis(df)

    # Contextual risk
    results = apply_contextual_risk(results)

    # Explainable AI
    results = apply_explanation_engine(results)

    print("\n===== EXPLAINABLE AI SECURITY ENGINE =====\n")

    # Show highest-risk events first
    results = results.sort_values(
        "contextual_risk_score",
        ascending=False
    )

    print(
        results[
            [
                "user",
                "source_ip",
                "action",
                "contextual_risk_score",
                "contextual_risk_level",
                "security_explanation"
            ]
        ].head(15).to_string(index=False)
    )

    print("\n==========================================")