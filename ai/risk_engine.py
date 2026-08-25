import pandas as pd


SUSPICIOUS_IPS = {
    "185.220.101.5",
    "45.155.205.10",
    "103.27.186.20"
}

HIGH_RISK_ACTIONS = {
    "CreateUser",
    "ChangePassword",
    "AssumeRole",
    "DeleteObject"
}


def calculate_risk(row):
    score = 0

    # 1. AI anomaly detection
    if row["threat_status"] == "Anomaly":
        score += 40

    # 2. Suspicious source IP
    if row["source_ip"] in SUSPICIOUS_IPS:
        score += 20

    # 3. Failed activity
    if row["status"] == "Failed":
        score += 15

    # 4. High-risk cloud operation
    if row["action"] in HIGH_RISK_ACTIONS:
        score += 15

    # 5. Large data transfer
    if row["bytes_transferred"] > 50000:
        score += 10

    # Maximum score = 100
    score = min(score, 100)

    # Risk classification
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return pd.Series([score, level])


def apply_risk_engine(df):

    df[["risk_score", "risk_level"]] = df.apply(
        calculate_risk,
        axis=1
    )

    return df


if __name__ == "__main__":

    from .anomaly_detector import detect_anomalies

    # Run AI anomaly detection
    df = detect_anomalies("data/sample_logs.csv")

    # Apply risk engine
    df = apply_risk_engine(df)

    print("\n===== CLOUD SECURITY RISK ENGINE =====\n")

    print(
        df[
            [
                "user",
                "source_ip",
                "action",
                "status",
                "bytes_transferred",
                "threat_status",
                "risk_score",
                "risk_level"
            ]
        ].head(20).to_string(index=False)
    )

    print("\n=======================================")

    print("\nRisk Distribution:")

    print(
        df["risk_level"]
        .value_counts()
        .to_string()
    )