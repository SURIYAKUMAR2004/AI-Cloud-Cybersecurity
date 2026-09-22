from fastapi import FastAPI, HTTPException
from datetime import datetime
import os
import pandas as pd

# ============================================================
# EXISTING AI / SECURITY PIPELINE
# ============================================================

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

from security.response_engine import (
    apply_response_engine
)

from security.attack_correlator import (
    correlate_attack_chain
)


# ============================================================
# CONFIGURATION
# ============================================================

BASELINE_FILE = "data/aws_cloudtrail_events.csv"

LIVE_EVENTS_FILE = "data/live_events.csv"


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="AI Cloud Cybersecurity - Live Event API",
    version="1.0"
)


# ============================================================
# DATAFRAME HELPER
# ============================================================

def get_dataframe(result):
    """
    Convert different pipeline return formats
    into a Pandas DataFrame.
    """

    if isinstance(result, pd.DataFrame):
        return result

    if isinstance(result, tuple):

        for item in result:

            if isinstance(item, pd.DataFrame):
                return item

    if isinstance(result, list):

        return pd.DataFrame(result)

    if isinstance(result, dict):

        return pd.DataFrame([result])

    raise TypeError(
        f"Expected DataFrame but received {type(result)}"
    )


# ============================================================
# LOAD HISTORICAL BASELINE
# ============================================================

def load_baseline():

    if not os.path.exists(BASELINE_FILE):

        raise FileNotFoundError(
            f"Baseline file not found: {BASELINE_FILE}"
        )

    baseline = pd.read_csv(
        BASELINE_FILE
    )

    return baseline


# ============================================================
# SAVE LIVE SECURITY EVENT
# ============================================================

def save_live_event(event_data):
    """
    Save the processed live security event.

    The file is created automatically if it does not exist.
    New events are appended to the existing live event store.
    """

    os.makedirs(
        "data",
        exist_ok=True
    )

    new_event = pd.DataFrame(
        [event_data]
    )

    if os.path.exists(
        LIVE_EVENTS_FILE
    ):

        try:

            existing = pd.read_csv(
                LIVE_EVENTS_FILE
            )

            combined = pd.concat(
                [
                    existing,
                    new_event
                ],
                ignore_index=True
            )

        except Exception:

            combined = new_event

    else:

        combined = new_event

    combined.to_csv(
        LIVE_EVENTS_FILE,
        index=False
    )


# ============================================================
# ANALYZE LIVE EVENT
# ============================================================

def analyze_event(event: dict):

    # --------------------------------------------------------
    # DEFAULT VALUES
    # --------------------------------------------------------

    event.setdefault(
        "timestamp",
        datetime.utcnow().isoformat()
    )

    event.setdefault(
        "event_id",
        f"LIVE-{int(datetime.now().timestamp() * 1000)}"
    )

    event.setdefault(
        "aws_region",
        "ap-south-1"
    )

    event.setdefault(
        "read_only",
        False
    )

    event.setdefault(
        "error_code",
        ""
    )

    event.setdefault(
        "error_message",
        ""
    )

    # --------------------------------------------------------
    # CREATE LIVE EVENT DATAFRAME
    # --------------------------------------------------------

    live_df = pd.DataFrame(
        [event]
    )

    # --------------------------------------------------------
    # LOAD HISTORICAL EVENTS
    # --------------------------------------------------------

    baseline_df = load_baseline()

    # --------------------------------------------------------
    # COMBINE HISTORICAL + LIVE EVENT
    #
    # Historical events provide behavioral context.
    # The new event is evaluated against that history.
    # --------------------------------------------------------

    combined_df = pd.concat(
        [
            baseline_df,
            live_df
        ],
        ignore_index=True
    )

    # ========================================================
    # STEP 1 — AI ANOMALY DETECTION
    # ========================================================

    anomaly_result = detect_anomalies(
        combined_df
    )

    combined_df = get_dataframe(
        anomaly_result
    )

    # ========================================================
    # STEP 2 — BEHAVIOR ANALYSIS
    # ========================================================

    behavior_result = apply_behavior_analysis(
        combined_df
    )

    # Your existing function returns:
    #
    #     baseline, results
    #
    # We need the RESULTS DataFrame.

    if isinstance(
        behavior_result,
        tuple
    ):

        if len(behavior_result) >= 2:

            baseline_result = behavior_result[0]

            results = behavior_result[1]

        elif len(behavior_result) == 1:

            results = behavior_result[0]

        else:

            raise ValueError(
                "Behavior analysis returned an empty tuple."
            )

    else:

        results = behavior_result

    results = get_dataframe(
        results
    )

    # ========================================================
    # VERIFY BEHAVIOR ANALYSIS
    # ========================================================

    if (
        "behavior_deviation_score"
        not in results.columns
    ):

        raise ValueError(
            "Behavior analysis failed to create "
            "'behavior_deviation_score'. "
            f"Available columns: "
            f"{list(results.columns)}"
        )

    # ========================================================
    # FIND THE LIVE EVENT
    # ========================================================

    live_event_id = str(
        event["event_id"]
    )

    if "event_id" in results.columns:

        live_results = results[
            results["event_id"]
            .astype(str)
            == live_event_id
        ]

    else:

        live_results = results.tail(
            1
        )

    # --------------------------------------------------------
    # FALLBACK
    # --------------------------------------------------------

    if live_results.empty:

        live_results = results.tail(
            1
        )

    # ========================================================
    # STEP 3 — CONTEXTUAL RISK
    # ========================================================

    live_results = apply_contextual_risk(
        live_results
    )

    # ========================================================
    # STEP 4 — EXPLANATION ENGINE
    # ========================================================

    explanation_result = apply_explanation_engine(
        live_results
    )

    live_results = get_dataframe(
        explanation_result
    )

    # ========================================================
    # STEP 5 — RESPONSE ENGINE
    # ========================================================

    response_result = apply_response_engine(
        live_results
    )

    live_results = get_dataframe(
        response_result
    )

    # ========================================================
    # STEP 6 — ATTACK CORRELATION
    # ========================================================

    incidents = correlate_attack_chain(
        live_results
    )

    # --------------------------------------------------------
    # NORMALIZE ATTACK CHAIN RESULT
    # --------------------------------------------------------

    if incidents is None:

        incidents = []

    elif isinstance(
        incidents,
        pd.DataFrame
    ):

        incidents = incidents.to_dict(
            orient="records"
        )

    elif isinstance(
        incidents,
        dict
    ):

        incidents = [
            incidents
        ]

    elif isinstance(
        incidents,
        tuple
    ):

        converted = []

        for item in incidents:

            if isinstance(
                item,
                pd.DataFrame
            ):

                converted.extend(
                    item.to_dict(
                        orient="records"
                    )
                )

            elif isinstance(
                item,
                dict
            ):

                converted.append(
                    item
                )

        incidents = converted

    elif not isinstance(
        incidents,
        list
    ):

        incidents = []

    # ========================================================
    # FINAL SECURITY EVENT
    # ========================================================

    security_event = (
        live_results
        .iloc[0]
        .to_dict()
    )

    # ========================================================
    # SAVE LIVE EVENT
    # ========================================================

    save_live_event(
        security_event
    )

    # ========================================================
    # RETURN LIVE RESULT
    # ========================================================

    return {
        "status": "processed",

        "mode": "LIVE",

        "processed_at":
            datetime.utcnow().isoformat(),

        "event":
            security_event,

        "attack_chains":
            incidents
    }


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():

    return {

        "system":
            "AI Cloud Cybersecurity",

        "status":
            "LIVE",

        "message":
            "Live security event ingestion API is running."
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {

        "status":
            "healthy",

        "mode":
            "live"
    }


# ============================================================
# LIVE SECURITY EVENT ENDPOINT
# ============================================================

@app.post("/events")
def receive_event(event: dict):

    try:

        return analyze_event(
            event
        )

    except Exception as e:

        print(
            "\n========================================"
        )

        print(
            "LIVE EVENT PROCESSING ERROR"
        )

        print(
            "========================================"
        )

        print(
            type(e).__name__,
            ":",
            str(e)
        )

        print(
            "========================================\n"
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
