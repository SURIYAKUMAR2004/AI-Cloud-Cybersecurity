import pandas as pd


def build_user_profiles(df):

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed")
    df["hour"] = df["timestamp"].dt.hour

    profiles = {}

    for user in df["user"].unique():

        user_data = df[df["user"] == user]

        profiles[user] = {
            "known_ips": set(user_data["source_ip"].unique()),
            "known_actions": set(user_data["action"].unique()),
            "avg_bytes": user_data["bytes_transferred"].mean()
        }

    return profiles


def calculate_behavior_deviation(row, profile):

    score = 0

    # Unknown IP
    if row["source_ip"] not in profile["known_ips"]:
        score += 30

    # Unknown action
    if row["action"] not in profile["known_actions"]:
        score += 20

    # Large data transfer
    if row["bytes_transferred"] > profile["avg_bytes"] * 3:
        score += 20

    # Failed operation
    if row["status"] == "Failed":
        score += 15

    # Unusual hour
    if row["hour"] < 8 or row["hour"] > 18:
        score += 15

    return min(score, 100)


def apply_behavior_analysis(df, baseline_size=350):

    df = df.copy()

    df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed")
    df["hour"] = df["timestamp"].dt.hour

    # Sort chronologically
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Adaptive historical baseline
    # Use the requested baseline for large datasets,
    # but reserve events for detection on small datasets.
    if len(df) <= baseline_size:
        adaptive_size = max(1, int(len(df) * 0.70))
    else:
        adaptive_size = baseline_size

    baseline = df.iloc[:adaptive_size].copy()

    # Events to evaluate
    detection_data = df.iloc[adaptive_size:].copy()

    # Build profiles ONLY from historical events
    profiles = build_user_profiles(baseline)

    scores = []

    for _, row in detection_data.iterrows():

        # If a completely new user appears
        if row["user"] not in profiles:

            scores.append(100)
            continue

        score = calculate_behavior_deviation(
            row,
            profiles[row["user"]]
        )

        scores.append(score)

    detection_data["behavior_deviation_score"] = scores

    def classify(score):

        if score >= 70:
            return "SEVERE_DEVIATION"

        elif score >= 40:
            return "HIGH_DEVIATION"

        elif score >= 20:
            return "MODERATE_DEVIATION"

        else:
            return "NORMAL_BEHAVIOR"

    detection_data["behavior_status"] = (
        detection_data["behavior_deviation_score"]
        .apply(classify)
    )

    return baseline, detection_data


if __name__ == "__main__":

    from ai.anomaly_detector import detect_anomalies

    df = detect_anomalies(
        "data/sample_logs.csv"
    )

    baseline, results = apply_behavior_analysis(df)

    print("\n===== BEHAVIORAL BASELINE =====")

    print(f"Historical events: {len(baseline)}")
    print(f"Events evaluated: {len(results)}")

    print("\n===== NEW EVENT ANALYSIS =====\n")

    print(
        results[
            [
                "timestamp",
                "user",
                "source_ip",
                "action",
                "bytes_transferred",
                "hour",
                "behavior_deviation_score",
                "behavior_status"
            ]
        ].head(30).to_string(index=False)
    )

    print("\n================================")

    print("\nBehavior Distribution:")

    print(
        results["behavior_status"]
        .value_counts()
        .to_string()
    )