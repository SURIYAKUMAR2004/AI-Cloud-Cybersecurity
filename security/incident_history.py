import os
import json
import pandas as pd


EVIDENCE_DIR = "data/incidents"


def load_incident_history():

    if not os.path.exists(EVIDENCE_DIR):
        return pd.DataFrame()

    records = []

    for filename in os.listdir(EVIDENCE_DIR):

        if not filename.endswith(".json"):
            continue

        filepath = os.path.join(
            EVIDENCE_DIR,
            filename
        )

        try:

            with open(
                filepath,
                "r",
                encoding="utf-8"
            ) as file:

                record = json.load(file)

            records.append(record)

        except Exception as e:

            print(
                f"Could not load {filename}: {e}"
            )

    if not records:
        return pd.DataFrame()

    return pd.DataFrame(records)


def get_incident_by_user(
    user
):

    history = load_incident_history()

    if history.empty:
        return pd.DataFrame()

    return history[
        history["user"].astype(str).str.lower()
        == str(user).lower()
    ]


if __name__ == "__main__":

    print(
        "\n===== INCIDENT HISTORY =====\n"
    )

    history = load_incident_history()

    if history.empty:

        print(
            "No preserved incidents found."
        )

    else:

        print(
            f"Total preserved incidents: {len(history)}"
        )

        print()

        columns = [
            "evidence_id",
            "user",
            "severity",
            "sequence_score",
            "assessment",
            "response_priority"
        ]

        available_columns = [
            column
            for column in columns
            if column in history.columns
        ]

        print(
            history[
                available_columns
            ].to_string(index=False)
        )

    print(
        "\n============================"
    )