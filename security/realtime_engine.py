import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.live_log_stream import generate_security_event


def process_live_event(event):

    df = pd.DataFrame([event])

    print("\n===== REAL-TIME SECURITY EVENT =====")

    print(df.to_string(index=False))

    # Basic real-time threat indicators
    suspicious_ip = event["source_ip"] in {
        "45.155.205.10",
        "103.27.186.20",
        "185.220.101.5"
    }

    privileged_action = event["action"] in {
        "AssumeRole",
        "CreateUser",
        "ChangePassword",
        "DeleteObject"
    }

    large_transfer = (
        event["bytes_transferred"] > 50000
    )

    failed_operation = (
        event["status"] == "Failed"
    )

    risk_score = 0
    reasons = []

    if suspicious_ip:
        risk_score += 30
        reasons.append(
            "Suspicious source IP"
        )

    if privileged_action:
        risk_score += 25
        reasons.append(
            "High-risk cloud operation"
        )

    if large_transfer:
        risk_score += 30
        reasons.append(
            "Unusually large data transfer"
        )

    if failed_operation:
        risk_score += 15
        reasons.append(
            "Failed security operation"
        )

    risk_score = min(
        risk_score,
        100
    )

    if risk_score >= 80:
        risk_level = "CRITICAL"

    elif risk_score >= 60:
        risk_level = "HIGH"

    elif risk_score >= 30:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    print(
        f"\nRisk Score: {risk_score}"
    )

    print(
        f"Risk Level: {risk_level}"
    )

    print("\nThreat Indicators:")

    if reasons:

        for reason in reasons:
            print(f"- {reason}")

    else:

        print(
            "- No significant indicators"
        )

    if risk_level == "CRITICAL":

        response = (
            "BLOCK_AND_ISOLATE"
        )

    elif risk_level == "HIGH":

        response = (
            "RESTRICT_ACCESS_AND_ALERT"
        )

    elif risk_level == "MEDIUM":

        response = (
            "ALERT_SECURITY_TEAM"
        )

    else:

        response = "MONITOR"

    print(
        f"\nRecommended Response: {response}"
    )

    print(
        "\n===================================="
    )


if __name__ == "__main__":

    print(
        "\nAI REAL-TIME SECURITY ENGINE"
    )

    print(
        "Generating live events..."
    )

    import time

    try:

        while True:

            event = generate_security_event()

            process_live_event(event)

            time.sleep(3)

    except KeyboardInterrupt:

        print(
            "\nReal-time engine stopped."
        )