import pandas as pd


HIGH_RISK_ACTIONS = {
    "CreateUser",
    "ChangePassword",
    "AssumeRole",
    "DeleteObject"
}


def determine_response(row):
    """
    Determine the recommended security response
    using contextual risk and threat context.

    This is a simulation/recommendation layer.
    It does NOT perform real cloud actions.
    """

    risk = row["contextual_risk_level"]
    action = row["action"]
    behavior_score = row["behavior_deviation_score"]
    bytes_transferred = row["bytes_transferred"]
    threat_status = row["threat_status"]

    # ------------------------------------------------
    # CRITICAL RESPONSE
    # ------------------------------------------------

    if risk == "CRITICAL":

        if action in HIGH_RISK_ACTIONS:
            return "BLOCK_AND_ISOLATE_PRIVILEGED_OPERATION"

        if bytes_transferred > 50000:
            return "BLOCK_AND_ISOLATE_DATA_EXFILTRATION_RISK"

        return "BLOCK_AND_ISOLATE"

    # ------------------------------------------------
    # HIGH RESPONSE
    # ------------------------------------------------

    if risk == "HIGH":

        if behavior_score >= 40:
            return "RESTRICT_ACCESS_AND_ALERT"

        return "ESCALATE_SECURITY_INCIDENT"

    # ------------------------------------------------
    # MEDIUM RESPONSE
    # ------------------------------------------------

    if risk == "MEDIUM":

        if behavior_score >= 20:
            return "ALERT_SECURITY_TEAM_AND_MONITOR"

        return "ALERT_SECURITY_TEAM"

    # ------------------------------------------------
    # LOW RESPONSE
    # ------------------------------------------------

    return "MONITOR"


def generate_response_reason(row):

    response = row["recommended_response"]

    reasons = []

    if row["contextual_risk_level"] in {
        "HIGH",
        "CRITICAL"
    }:
        reasons.append(
            f"Risk level: {row['contextual_risk_level']}"
        )

    if row["behavior_deviation_score"] >= 20:
        reasons.append(
            "Behavioral deviation detected"
        )

    if row["action"] in HIGH_RISK_ACTIONS:
        reasons.append(
            f"Privileged/high-risk action: {row['action']}"
        )

    if row["bytes_transferred"] > 50000:
        reasons.append(
            "Potential data exfiltration pattern"
        )

    if row["threat_status"] == "Anomaly":
        reasons.append(
            "AI anomaly detected"
        )

    if not reasons:
        reasons.append(
            "No significant threat indicators"
        )

    return " | ".join(reasons)


def apply_response_engine(df):

    df = df.copy()

    # Determine response
    df["recommended_response"] = df.apply(
        determine_response,
        axis=1
    )

    # Explain response
    df["response_reason"] = df.apply(
        generate_response_reason,
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

    from security.explanation_engine import (
        apply_explanation_engine
    )

    # -----------------------------------------------
    # AI anomaly detection
    # -----------------------------------------------

    df = detect_anomalies(
        "data/sample_logs.csv"
    )

    # -----------------------------------------------
    # Behavioral analysis
    # -----------------------------------------------

    baseline, results = apply_behavior_analysis(df)

    # -----------------------------------------------
    # Contextual risk
    # -----------------------------------------------

    results = apply_contextual_risk(results)

    # -----------------------------------------------
    # Explainable AI
    # -----------------------------------------------

    results = apply_explanation_engine(results)

    # -----------------------------------------------
    # Response engine
    # -----------------------------------------------

    results = apply_response_engine(results)

    print("\n===== ADAPTIVE RESPONSE ENGINE =====\n")

    display_columns = [
        "user",
        "source_ip",
        "action",
        "contextual_risk_score",
        "contextual_risk_level",
        "recommended_response",
        "response_reason"
    ]

    results = results.sort_values(
        "contextual_risk_score",
        ascending=False
    )

    print(
        results[
            display_columns
        ].head(20).to_string(index=False)
    )

    print("\n====================================")

    print("\nResponse Distribution:")

    print(
        results["recommended_response"]
        .value_counts()
        .to_string()
    )