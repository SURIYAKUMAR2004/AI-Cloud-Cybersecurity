import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.anomaly_detector import detect_anomalies
from security.threat_detector import apply_behavior_analysis
from security.contextual_risk_engine import apply_contextual_risk
from security.response_engine import apply_response_engine
from security.attack_correlator import correlate_attack_chain


BASELINE_FILE = PROJECT_ROOT / "data" / "sample_logs.csv"
LIVE_FILE = PROJECT_ROOT / "data" / "live_events.csv"


def build_live_analysis(event):
    """
    Run one live event through the complete AI security pipeline.

    The historical sample logs provide the baseline.
    The incoming event is evaluated as a new detection event.
    """

    # -------------------------------------------------
    # 1. Load historical baseline
    # -------------------------------------------------

    baseline_df = pd.read_csv(BASELINE_FILE)

    # -------------------------------------------------
    # 2. Add the live event to the historical dataset
    # -------------------------------------------------

    live_df = pd.DataFrame([event])

    combined_df = pd.concat(
        [baseline_df, live_df],
        ignore_index=True
    )

    # -------------------------------------------------
    # 3. AI anomaly detection
    # -------------------------------------------------

    analyzed_df = detect_anomalies(combined_df)

    # -------------------------------------------------
    # 4. Behavioral analysis
    # -------------------------------------------------

    baseline, detection_results = apply_behavior_analysis(
        analyzed_df,
        baseline_size=len(baseline_df)
    )

    # -------------------------------------------------
    # 5. Contextual risk
    # -------------------------------------------------

    detection_results = apply_contextual_risk(
        detection_results
    )

    # -------------------------------------------------
    # 6. Response engine
    # -------------------------------------------------

    detection_results = apply_response_engine(
        detection_results
    )

    return detection_results


def analyze_attack_chain():
    """
    Analyze the accumulated live events for correlated
    multi-event attack patterns.
    """

    if not LIVE_FILE.exists():
        return pd.DataFrame()

    try:
        live_df = pd.read_csv(LIVE_FILE)

        if live_df.empty:
            return pd.DataFrame()

        return correlate_attack_chain(live_df)

    except Exception as error:
        print(
            f"\nAttack correlation warning: {error}"
        )
        return pd.DataFrame()


def process_live_event(event):

    print(
        "\n===== REAL-TIME AI SECURITY ANALYSIS ====="
    )

    # -------------------------------------------------
    # Complete AI pipeline
    # -------------------------------------------------

    results = build_live_analysis(event)

    if results.empty:
        print("\nNo analysis result generated.")
        return

    result = results.iloc[-1]

    # -------------------------------------------------
    # Display event
    # -------------------------------------------------

    print("\nEvent:")
    print(
        pd.DataFrame([event]).to_string(
            index=False
        )
    )

    # -------------------------------------------------
    # AI anomaly result
    # -------------------------------------------------

    print(
        f"\nAI Threat Status: "
        f"{result['threat_status']}"
    )

    print(
        f"AI Anomaly Score: "
        f"{result['anomaly_score']:.4f}"
    )

    # -------------------------------------------------
    # Behavioral analysis
    # -------------------------------------------------

    print(
        f"Behavior Deviation: "
        f"{result['behavior_deviation_score']}"
    )

    print(
        f"Behavior Status: "
        f"{result['behavior_status']}"
    )

    # -------------------------------------------------
    # Contextual risk
    # -------------------------------------------------

    print(
        f"\nContextual Risk Score: "
        f"{result['contextual_risk_score']}"
    )

    print(
        f"Contextual Risk Level: "
        f"{result['contextual_risk_level']}"
    )

    # -------------------------------------------------
    # Response
    # -------------------------------------------------

    print(
        f"\nRecommended Response: "
        f"{result['recommended_response']}"
    )

    print(
        f"Response Reason: "
        f"{result['response_reason']}"
    )

    # -------------------------------------------------
    # Attack-chain correlation
    # -------------------------------------------------

    incidents = analyze_attack_chain()

    if incidents is not None and not incidents.empty:

        print(
            "\n===== CORRELATED ATTACK DETECTED ====="
        )

        top_incident = incidents.iloc[0]

        print(
            f"User: {top_incident['user']}"
        )

        print(
            f"Chain Score: "
            f"{top_incident['chain_score']}"
        )

        print(
            f"Severity: "
            f"{top_incident['severity']}"
        )

        print(
            f"Assessment: "
            f"{top_incident['assessment']}"
        )

        print(
            f"Events Correlated: "
            f"{top_incident['events_correlated']}"
        )

        print(
            f"Attack Pattern: "
            f"{top_incident['attack_pattern']}"
        )

    else:

        print(
            "\nAttack Chain: "
            "No correlated incident detected."
        )

    print(
        "\n============================================"
    )


if __name__ == "__main__":

    print(
        "\nAI REAL-TIME SECURITY ENGINE"
    )

    print(
        "Generating live events..."
    )

    import time

    from security.live_log_stream import (
        generate_security_event
    )

    try:

        while True:

            event = generate_security_event()

            process_live_event(event)

            time.sleep(3)

    except KeyboardInterrupt:

        print(
            "\nReal-time engine stopped."
        )
