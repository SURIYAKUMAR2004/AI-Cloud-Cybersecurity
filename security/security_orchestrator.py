import pandas as pd

from ai.anomaly_detector import detect_anomalies

from security.risk_aggregator import (
    aggregate_incident_risk
)

from security.contextual_risk_engine import (
    apply_contextual_risk
)

from security.threat_detector import (
    apply_behavior_analysis
)

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

    df = df.copy()

    # --------------------------------------------------
    # AI anomaly detection
    # --------------------------------------------------

    if "threat_status" not in df.columns:
        df = detect_anomalies(df)

    # --------------------------------------------------
    # Behavioral analysis
    # --------------------------------------------------

    baseline, event_results = apply_behavior_analysis(df)

    # --------------------------------------------------
    # Contextual risk analysis
    # --------------------------------------------------

    event_results = apply_contextual_risk(
        event_results
    )

    # --------------------------------------------------
    # Attack-chain correlation
    # --------------------------------------------------

    incidents = correlate_attack_chain(df)

    # --------------------------------------------------
    # No correlated incidents
    # --------------------------------------------------

    if incidents.empty:

        high_risk_events = len(
            event_results[
                event_results["contextual_risk_level"].isin(
                    ["HIGH", "CRITICAL"]
                )
            ]
        )

        return pd.DataFrame([{
            "event_level_analysis": "COMPLETED",
            "aws_events_analyzed": len(df),
            "historical_baseline": len(baseline),
            "events_evaluated": len(event_results),
            "high_risk_events": high_risk_events,
            "correlated_incidents": 0
        }])

    # --------------------------------------------------
    # Aggregate event + attack-chain intelligence
    # --------------------------------------------------

    incidents = aggregate_incident_risk(
        incidents,
        event_results
    )

    # --------------------------------------------------
    # Adaptive response
    # --------------------------------------------------

    responses = []

    for _, incident in incidents.iterrows():

        response = determine_response(
            risk_score=int(
                incident["final_risk_score"]
            ),
            risk_level=incident["final_risk_level"],
            behavior_status="HIGH_DEVIATION",
            contextual_risk_level=incident[
                "final_risk_level"
            ],
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

    # --------------------------------------------------
    # Combine incident + response intelligence
    # --------------------------------------------------

    response_df = pd.DataFrame(responses)

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


# ==========================================================
# Standalone execution
# ==========================================================

if __name__ == "__main__":

    print(
        "\n===== SECURITY ORCHESTRATOR =====\n"
    )

    df = pd.read_csv(
        "data/live_events.csv"
    )

    result = analyze_security_events(df)

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
