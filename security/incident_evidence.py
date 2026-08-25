import os
import json
from datetime import datetime


EVIDENCE_DIR = "data/incidents"


def preserve_incident_evidence(row):

    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    user = str(row.get("user", "unknown"))

    filename = f"{user}_{timestamp}.json"

    filepath = os.path.join(
        EVIDENCE_DIR,
        filename
    )

    evidence = {
        "evidence_id": filename,
        "preserved_at": datetime.now().isoformat(),

        "user": user,

        "start_time": str(
            row.get("start_time", "")
        ),

        "end_time": str(
            row.get("end_time", "")
        ),

        "sequence_score": float(
            row.get("sequence_score", 0)
        ),

        "severity": str(
            row.get("severity", "UNKNOWN")
        ),

        "assessment": str(
            row.get("assessment", "")
        ),

        "attack_phases": str(
            row.get("phases_detected", "")
        ),

        "indicators": str(
            row.get("indicators_detected", "")
        ),

        "events_analyzed": int(
            row.get("events_analyzed", 0)
        ),

        "recommended_response": str(
            row.get("response", "")
        ),

        "response_priority": str(
            row.get("response_priority", "")
        ),

        "execution_mode": "SIMULATION"
    }

    with open(
        filepath,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            evidence,
            file,
            indent=4
        )

    return filepath


def preserve_all_incidents(df):

    preserved = []

    for _, row in df.iterrows():

        filepath = preserve_incident_evidence(
            row
        )

        preserved.append(filepath)

    return preserved


if __name__ == "__main__":

    import pandas as pd

    from security.attack_sequence_engine import (
        analyze_attack_sequence
    )

    from security.incident_response_bridge import (
        build_response_plan
    )

    print(
        "\n===== INCIDENT EVIDENCE PRESERVATION =====\n"
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

    files = preserve_all_incidents(
        response_plan
    )

    print(
        f"Preserved {len(files)} incident records."
    )

    for filepath in files:

        print(
            f"Evidence saved: {filepath}"
        )

    print(
        "\n=========================================="
    )