import pandas as pd

from security.attack_timeline import build_attack_timeline


def classify_attack_phase(row):

    indicators = str(row["indicator"])

    if "LARGE_DATA_TRANSFER" in indicators:
        return "DATA_EXFILTRATION"

    if "SUSPICIOUS_EXTERNAL_SOURCE" in indicators:
        return "SUSPICIOUS_EXTERNAL_ACCESS"

    if "PRIVILEGED_CLOUD_OPERATION" in indicators:
        return "PRIVILEGE_ABUSE"

    if "FAILED_OPERATION" in indicators:
        return "INITIAL_ACCESS / FAILED_OPERATION"

    return "NORMAL_ACTIVITY"


def build_attack_phases(df):

    if df.empty:
        return pd.DataFrame()

    # First build the security indicators
    result = build_attack_timeline(df)

    if result.empty:
        return result

    # Then classify the attack phase
    result["attack_phase"] = result.apply(
        classify_attack_phase,
        axis=1
    )

    result["phase_event"] = (
        result["attack_phase"] !=
        "NORMAL_ACTIVITY"
    )

    return result


if __name__ == "__main__":

    print(
        "\n===== ATTACK PHASE CLASSIFICATION =====\n"
    )

    df = pd.read_csv(
        "data/live_events.csv"
    )

    phases = build_attack_phases(df)

    suspicious = phases[
        phases["phase_event"]
    ]

    if suspicious.empty:

        print(
            "No attack phases detected."
        )

    else:

        print(
            suspicious[
                [
                    "timestamp",
                    "user",
                    "action",
                    "indicator",
                    "attack_phase"
                ]
            ].to_string(
                index=False
            )
        )

    print(
        "\n========================================"
    )