import pandas as pd
from ai.anomaly_detector import detect_anomalies
from security.risk_aggregator import (
    aggregate_incident_risk
)
from security.contextual_risk_engine import apply_contextual_risk
from security.threat_detector import apply_behavior_analysis
from security.attack_correlator import (
    correlate_attack_chain
)

from security.adaptive_response import (
    determine_response
)

from security.response_executor import (
    execute_response
)


def analyze_security_events(df):

    if df.empty:
        return pd.DataFrame()

    incidents = correlate_attack_chain(df)

    if incidents.empty:
        return incidents

    # Build event-level contextual intelligence
    # AI anomaly detection must run before behavioral analysis
    if "threat_status" not in df.columns:
        df = detect_anomalies(df)

    baseline, event_results = apply_behavior_analysis(df)
    event_results = apply_contextual_risk(event_results)

    # Aggregate event-level and incident-level intelligence
    incidents = aggregate_incident_risk(
        incidents,
        event_results
    )

    responses = []

    for _, incident in incidents.iterrows():

        response = determine_response(
            risk_score=int(
                incident["final_risk_score"]
            ),
            risk_level=incident["severity"],
            behavior_status="HIGH_DEVIATION",
            contextual_risk_level=incident["severity"],
            attack_severity=incident["severity"],
            assessment=incident["assessment"]
        )

        execution = execute_response(
            response=response["response"],
            user=incident["user"],
            source_ip=incident["source_ip"]
        )

        responses.append({
            "response": response["response"],
            "priority": response["priority"],
            "response_reason": response["reason"],
            "response_indicators": " | ".join(
                response["indicators"]
            ),
            "execution_mode": execution[
                "execution_mode"
            ],
            "execution_actions": " | ".join(
                execution["actions"]
            )
        })

    response_df = pd.DataFrame(
        responses
    )

    incidents = incidents.reset_index(
        drop=True
    )

    response_df = response_df.reset_index(
        drop=True
    )

    return pd.concat(
        [
            incidents,
            response_df
        ],
        axis=1
    )


if __name__ == "__main__":

    print(
        "\n===== SECURITY ORCHESTRATOR =====\n"
    )

    df = pd.read_csv(
        "data/live_events.csv"
    )

    result = analyze_security_events(
        df
    )

    if result.empty:

        print(
            "No security incidents detected."
        )

    else:

        print(
            result.to_string(
                index=False
            )
        )

    print(
        "\n================================="
    )
