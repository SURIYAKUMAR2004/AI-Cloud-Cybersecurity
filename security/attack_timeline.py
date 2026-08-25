import pandas as pd


SUSPICIOUS_IPS = [
    "45.155.205.10",
    "103.27.186.20",
    "185.220.101.5"
]

PRIVILEGED_ACTIONS = [
    "AssumeRole",
    "CreateUser",
    "DeleteObject"
]


def detect_indicators(row):

    indicators = []

    if row["status"] == "Failed":
        indicators.append(
            "FAILED_OPERATION"
        )

    if row["source_ip"] in SUSPICIOUS_IPS:
        indicators.append(
            "SUSPICIOUS_EXTERNAL_SOURCE"
        )

    if row["action"] in PRIVILEGED_ACTIONS:
        indicators.append(
            "PRIVILEGED_CLOUD_OPERATION"
        )

    if row["bytes_transferred"] > 100000:
        indicators.append(
            "LARGE_DATA_TRANSFER"
        )

    if not indicators:
        return "NORMAL_ACTIVITY"

    return " | ".join(indicators)


def build_attack_timeline(df, user=None):

    if df.empty:
        return pd.DataFrame()

    timeline = df.copy()

    timeline["timestamp"] = pd.to_datetime(
        timeline["timestamp"],
        format="mixed"
    )
    timeline = timeline.sort_values(
        "timestamp"
    )

    if user is not None:
        timeline = timeline[
            timeline["user"] == user
        ]

    timeline["indicator"] = timeline.apply(
        detect_indicators,
        axis=1
    )

    timeline["attack_event"] = (
        timeline["indicator"] !=
        "NORMAL_ACTIVITY"
    )

    return timeline[
        [
            "timestamp",
            "user",
            "source_ip",
            "action",
            "status",
            "bytes_transferred",
            "indicator",
            "attack_event"
        ]
    ]


if __name__ == "__main__":

    print(
        "\n===== ATTACK TIMELINE =====\n"
    )

    df = pd.read_csv(
        "data/live_events.csv"
    )

    timeline = build_attack_timeline(
        df
    )

    suspicious = timeline[
        timeline["attack_event"]
    ]

    if suspicious.empty:

        print(
            "No suspicious events detected."
        )

    else:

        print(
            suspicious.to_string(
                index=False
            )
        )

    print(
        "\n============================"
    )
