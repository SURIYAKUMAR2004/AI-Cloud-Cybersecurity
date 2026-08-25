import os
import json
import time
import pandas as pd

from security.attack_sequence_engine import analyze_attack_sequence
from security.incident_response_bridge import build_response_plan
from security.incident_evidence import preserve_all_incidents


EVENT_FILE = "data/live_events.csv"
STATE_FILE = "data/realtime_state.json"
CHECK_INTERVAL = 5


def load_state():
    if not os.path.exists(STATE_FILE):
        return {
            "last_timestamp": None,
            "processed_incidents": []
        }

    try:
        with open(
            STATE_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)

    except Exception:
        return {
            "last_timestamp": None,
            "processed_incidents": []
        }


def save_state(state):
    os.makedirs(
        os.path.dirname(STATE_FILE),
        exist_ok=True
    )

    with open(
        STATE_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            state,
            file,
            indent=4
        )


def process_events(state):

    try:
        events = pd.read_csv(
            EVENT_FILE
        )

    except Exception as e:
        print(
            f"Unable to read event file: {e}"
        )
        return state

    if events.empty:
        print(
            "No security events available."
        )
        return state

    # Support timestamps with and without microseconds.
    events["timestamp"] = pd.to_datetime(
        events["timestamp"],
        format="mixed"
    )

    events = events.sort_values(
        "timestamp"
    ).reset_index(
        drop=True
    )

    last_timestamp = state.get(
        "last_timestamp"
    )

    # Establish initial baseline.
    if last_timestamp is None:

        state["last_timestamp"] = (
            events["timestamp"]
            .max()
            .isoformat()
        )

        save_state(state)

        print(
            f"\n[{time.strftime('%H:%M:%S')}] "
            f"Baseline established with "
            f"{len(events)} events."
        )

        print(
            "Waiting for NEW security events..."
        )

        return state

    last_timestamp = pd.to_datetime(
        last_timestamp
    )

    new_events = events[
        events["timestamp"] > last_timestamp
    ]

    if new_events.empty:

        print(
            f"\n[{time.strftime('%H:%M:%S')}] "
            "No new security events."
        )

        return state

    print(
        f"\n[{time.strftime('%H:%M:%S')}] "
        f"NEW EVENTS: {len(new_events)}"
    )

    print(
        new_events[
            [
                "timestamp",
                "user",
                "source_ip",
                "action",
                "status",
                "bytes_transferred"
            ]
        ].to_string(index=False)
    )

    try:

        incidents = analyze_attack_sequence(
            events
        )

        response_plan = build_response_plan(
            incidents
        )

    except Exception as e:

        print(
            f"Security analysis error: {e}"
        )

        return state

    if response_plan.empty:

        print(
            "No correlated security incidents."
        )

    else:

        print(
            "\n===== NEW SECURITY ASSESSMENT ====="
        )

        for _, incident in response_plan.iterrows():

            user = str(
                incident["user"]
            )

            start_time = str(
                incident.get(
                    "start_time",
                    ""
                )
            )

            incident_id = (
                f"{user}|{start_time}"
            )

            if incident_id in state[
                "processed_incidents"
            ]:
                continue

            print(
                f"\nUser: {user}"
            )

            print(
                f"Severity: "
                f"{incident['severity']}"
            )

            print(
                f"Assessment: "
                f"{incident['assessment']}"
            )

            print(
                f"Response: "
                f"{incident['response']}"
            )

            print(
                f"Priority: "
                f"{incident['response_priority']}"
            )

            print(
                f"Execution Mode: "
                f"{incident['execution_mode']}"
            )

            preserve_all_incidents(
                pd.DataFrame([incident])
            )

            state[
                "processed_incidents"
            ].append(
                incident_id
            )

    state["last_timestamp"] = (
        events["timestamp"]
        .max()
        .isoformat()
    )

    save_state(state)

    print(
        "\nCheckpoint updated:"
    )

    print(
        state["last_timestamp"]
    )

    return state


if __name__ == "__main__":

    print(
        "\n========================================"
    )

    print(
        "   AI CLOUD SECURITY REAL-TIME MONITOR"
    )

    print(
        "========================================"
    )

    print(
        f"Monitoring: {EVENT_FILE}"
    )

    print(
        f"Refresh interval: "
        f"{CHECK_INTERVAL} seconds"
    )

    print(
        "Execution mode: SIMULATION"
    )

    print(
        "\nPress Ctrl+C to stop.\n"
    )

    state = load_state()

    while True:

        state = process_events(
            state
        )

        time.sleep(
            CHECK_INTERVAL
        )