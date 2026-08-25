import pandas as pd


def calculate_signal_agreement(
    contextual_risk,
    chain_score
):
    """
    Measures how strongly event-level and
    incident-level signals agree.
    """

    difference = abs(
        contextual_risk - chain_score
    )

    agreement = max(
        0,
        100 - difference
    )

    return agreement

def calculate_final_risk(
    contextual_risk,
    chain_score,
    events_correlated
):
    """
    Hierarchical risk aggregation.

    Combines:
    - Event-level contextual risk
    - Incident-level attack-chain risk
    - Correlation strength
    """

    # Event-level intelligence
    event_component = contextual_risk * 0.40

    # Incident-level attack-chain intelligence
    chain_component = chain_score * 0.45

    # Correlation strength
    correlation_component = min(
        events_correlated * 2,
        10
    )

    # Base final score
    final_score = (
        event_component
        + chain_component
        + correlation_component
    )

    # Strong attack chain + meaningful contextual evidence
    # indicates a highly correlated attack.
    if (
        chain_score >= 90
        and 40 <= contextual_risk < 80
    ):
        final_score += 10

    # Keep score within 0-100
    final_score = min(
        round(final_score),
        100
    )

    # Risk classification
    if final_score >= 80:
        level = "CRITICAL"
    elif final_score >= 60:
        level = "HIGH"
    elif final_score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return final_score, level


def aggregate_incident_risk(
    incidents,
    event_results
):
    """
    Connects event-level intelligence with
    incident-level attack correlation.
    """

    if incidents.empty:
        return incidents

    incidents = incidents.copy()

    results = []

    for _, incident in incidents.iterrows():

        user = incident["user"]

        # -------------------------------------
        # Find events belonging to this user
        # -------------------------------------

        user_events = event_results[
            event_results["user"] == user
        ]

        if user_events.empty:

            contextual_risk = 0

        else:

            contextual_risk = int(
                user_events[
                    "contextual_risk_score"
                ].max()
            )

        chain_score = int(
            incident["chain_score"]
        )

        events_correlated = int(
            incident["events_correlated"]
        )

        # -------------------------------------
        # Signal agreement
        # -------------------------------------

        agreement = calculate_signal_agreement(
            contextual_risk,
            chain_score
        )

        # -------------------------------------
        # Final risk
        # -------------------------------------

        final_score, final_level = (
            calculate_final_risk(
                contextual_risk,
                chain_score,
                events_correlated
            )
        )

        results.append({

            "contextual_risk": contextual_risk,

            "chain_score":
                chain_score,

            "signal_agreement":
                agreement,

            "correlation_strength":
                events_correlated,

            "final_risk_score":
                final_score,

            "final_risk_level":
                final_level
        })

    risk_df = pd.DataFrame(results)

    incidents = incidents.reset_index(
        drop=True
    )

    risk_df = risk_df.reset_index(
        drop=True
    )

    return pd.concat(
        [
            incidents,
            risk_df
        ],
        axis=1
    )


if __name__ == "__main__":

    print(
        "\n===== HIERARCHICAL RISK AGGREGATOR =====\n"
    )

    print(
        "Module loaded successfully."
    )

    print(
        "\n========================================="
    )
