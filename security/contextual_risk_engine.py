import pandas as pd


HIGH_RISK_ACTIONS = {
    "CreateUser",
    "ChangePassword",
    "AssumeRole",
    "DeleteObject"
}


def calculate_contextual_score(row):
    """
    Combine multiple security signals into one
    contextual risk score.
    """

    score = 0

    # ------------------------------------------------
    # 1. AI anomaly signal
    # ------------------------------------------------

    if row["threat_status"] == "Anomaly":
        score += 30

    # ------------------------------------------------
    # 2. Behavioral deviation
    # ------------------------------------------------

    behavior_score = row["behavior_deviation_score"]

    score += int(behavior_score * 0.30)

    # ------------------------------------------------
    # 3. High-risk cloud operation
    # ------------------------------------------------

    if row["action"] in HIGH_RISK_ACTIONS:
        score += 15

    # ------------------------------------------------
    # 4. Failed security activity
    # ------------------------------------------------

    if row["status"] == "Failed":
        score += 10

    # ------------------------------------------------
    # 5. Large data transfer
    # ------------------------------------------------

    if row["bytes_transferred"] > 50000:
        score += 15

    elif row["bytes_transferred"] > 10000:
        score += 5

    # ------------------------------------------------
    # 6. Unusual activity time
    # ------------------------------------------------

    hour = row["hour"]

    if hour < 6 or hour > 22:
        score += 10

    # Maximum score
    return min(score, 100)


def classify_risk(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 30:
        return "MEDIUM"

    else:
        return "LOW"


def apply_contextual_risk(df):

    df = df.copy()

    # Calculate unified score
    df["contextual_risk_score"] = df.apply(
        calculate_contextual_score,
        axis=1
    )

    # Classify
    df["contextual_risk_level"] = (
        df["contextual_risk_score"]
        .apply(classify_risk)
    )

    return df


if __name__ == "__main__":

    from ai.anomaly_detector import detect_anomalies
    from security.threat_detector import (
        apply_behavior_analysis
    )

    # -----------------------------------------------
    # Step 1: AI anomaly detection
    # -----------------------------------------------

    df = detect_anomalies(
        "data/sample_logs.csv"
    )

    # -----------------------------------------------
    # Step 2: Behavioral baseline
    # -----------------------------------------------

    baseline, results = apply_behavior_analysis(df)

    # -----------------------------------------------
    # Step 3: Contextual risk
    # -----------------------------------------------

    results = apply_contextual_risk(results)

    print("\n===== UNIFIED CONTEXTUAL RISK ENGINE =====\n")

    print(
        results[
            [
                "timestamp",
                "user",
                "source_ip",
                "action",
                "threat_status",
                "behavior_deviation_score",
                "contextual_risk_score",
                "contextual_risk_level"
            ]
        ].head(30).to_string(index=False)
    )

    print("\n==========================================")

    print("\nContextual Risk Distribution:")

    print(
        results["contextual_risk_level"]
        .value_counts()
        .to_string()
    )