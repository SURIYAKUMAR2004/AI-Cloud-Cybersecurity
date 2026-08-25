import pandas as pd


def calculate_priority(row):

    score = float(row["sequence_score"])
    severity = str(row["severity"])
    confidence = str(row["confidence"])

    priority_score = score

    if severity == "CRITICAL":
        priority_score += 20
    elif severity == "HIGH":
        priority_score += 10
    elif severity == "MEDIUM":
        priority_score += 5

    if confidence == "HIGH":
        priority_score += 10
    elif confidence == "MEDIUM":
        priority_score += 5

    return min(priority_score, 130)


def prioritize_incidents(df):

    if df.empty:
        return pd.DataFrame()

    result = df.copy()

    result["priority_score"] = result.apply(
        calculate_priority,
        axis=1
    )

    result = result.sort_values(
        "priority_score",
        ascending=False
    ).reset_index(drop=True)

    result["investigation_rank"] = (
        result.index + 1
    )

    result["priority"] = result[
        "priority_score"
    ].apply(
        lambda x:
            "P1 - IMMEDIATE"
            if x >= 110
            else
            "P2 - HIGH"
            if x >= 80
            else
            "P3 - MEDIUM"
            if x >= 50
            else
            "P4 - LOW"
    )

    return result


if __name__ == "__main__":

    from security.attack_sequence_engine import (
        analyze_attack_sequence
    )

    print(
        "\n===== AI INCIDENT PRIORITIZATION =====\n"
    )

    events = pd.read_csv(
        "data/live_events.csv"
    )

    incidents = analyze_attack_sequence(
        events
    )

    prioritized = prioritize_incidents(
        incidents
    )

    if prioritized.empty:

        print(
            "No incidents require prioritization."
        )

    else:

        print(
            prioritized[
                [
                    "investigation_rank",
                    "user",
                    "sequence_score",
                    "severity",
                    "confidence",
                    "priority_score",
                    "priority",
                    "assessment"
                ]
            ].to_string(
                index=False
            )
        )

    print(
        "\n========================================"
    )