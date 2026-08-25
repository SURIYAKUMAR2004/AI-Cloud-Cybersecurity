import pandas as pd

from security.adaptive_response import determine_response


def generate_incident_response(row):

    response = determine_response(
        row["sequence_score"],
        row["severity"],
        row["confidence"],
        row["severity"],
        row["severity"],
        row["assessment"]
    )

    return response


def build_response_plan(df):

    if df.empty:
        return pd.DataFrame()

    result = df.copy()

    responses = result.apply(
        generate_incident_response,
        axis=1
    )

    result["response"] = responses.apply(
        lambda x: x.get("response", "MONITOR")
    )

    result["response_priority"] = responses.apply(
        lambda x: x.get("priority", "P4")
    )

    result["response_reason"] = responses.apply(
        lambda x: x.get("reason", "")
    )

    result["execution_mode"] = "SIMULATION"

    return result


if __name__ == "__main__":

    from security.attack_sequence_engine import (
        analyze_attack_sequence
    )

    print(
        "\n===== INCIDENT RESPONSE BRIDGE =====\n"
    )

    events = pd.read_csv(
        "data/live_events.csv"
    )

    incidents = analyze_attack_sequence(
        events
    )

    response_plan = build_response_plan(
        incidents
    )

    if response_plan.empty:

        print(
            "No incidents require a response."
        )

    else:

        print(
            response_plan[
                [
                    "user",
                    "sequence_score",
                    "severity",
                    "confidence",
                    "assessment",
                    "response",
                    "response_priority",
                    "response_reason",
                    "execution_mode"
                ]
            ].to_string(
                index=False
            )
        )

    print(
        "\n===================================="
    )