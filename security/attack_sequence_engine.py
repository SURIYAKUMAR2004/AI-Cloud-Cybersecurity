import pandas as pd

from security.attack_phase_classifier import (
    build_attack_phases
)


PHASE_ORDER = [
    "INITIAL_ACCESS / FAILED_OPERATION",
    "PRIVILEGE_ABUSE",
    "SUSPICIOUS_EXTERNAL_ACCESS",
    "DATA_EXFILTRATION"
]


def analyze_attack_sequence(df):

    if df.empty:
        return pd.DataFrame()

    # Build event-level attack phases
    phases = build_attack_phases(df)

    if phases.empty:
        return pd.DataFrame()

    suspicious = phases[
        phases["phase_event"]
    ].copy()

    if suspicious.empty:
        return pd.DataFrame()

    suspicious["timestamp"] = pd.to_datetime(
        suspicious["timestamp"]
    )

    incidents = []

    for user, group in suspicious.groupby("user"):

        # Always analyze events chronologically
        group = group.sort_values(
            "timestamp"
        ).reset_index(drop=True)

        detected_phases = set(
            group["attack_phase"]
        )

        ordered_phases = []

        for phase in PHASE_ORDER:

            if phase in detected_phases:
                ordered_phases.append(
                    phase
                )

        # --------------------------------------------------
        # Indicator detection
        # --------------------------------------------------

        indicators_detected = set()

        for indicator_string in group[
            "indicator"
        ]:

            for indicator in str(
                indicator_string
            ).split(" | "):

                indicator = indicator.strip()

                if indicator:
                    indicators_detected.add(
                        indicator
                    )

        indicators_detected = sorted(
            indicators_detected
        )

        # --------------------------------------------------
        # Sequence scoring
        # --------------------------------------------------

        score = 0

        if "FAILED_OPERATION" in indicators_detected:
            score += 20

        if "PRIVILEGED_CLOUD_OPERATION" in indicators_detected:
            score += 25

        if "SUSPICIOUS_EXTERNAL_SOURCE" in indicators_detected:
            score += 25

        if "LARGE_DATA_TRANSFER" in indicators_detected:
            score += 30

        score = min(score, 100)

        # --------------------------------------------------
        # Attack pattern
        # --------------------------------------------------

        pattern_parts = []

        if "INITIAL_ACCESS / FAILED_OPERATION" in ordered_phases:
            pattern_parts.append(
                "Failed Operation"
            )

        if "PRIVILEGE_ABUSE" in ordered_phases:
            pattern_parts.append(
                "Privilege Abuse"
            )

        if "SUSPICIOUS_EXTERNAL_ACCESS" in ordered_phases:
            pattern_parts.append(
                "Suspicious External Access"
            )

        if "DATA_EXFILTRATION" in ordered_phases:
            pattern_parts.append(
                "Data Exfiltration"
            )

        attack_pattern = " → ".join(
            pattern_parts
        )

        # --------------------------------------------------
        # Severity and assessment
        # --------------------------------------------------

        if score >= 90:

            severity = "CRITICAL"

            assessment = (
                "POSSIBLE_ACCOUNT_COMPROMISE"
            )

            confidence = "HIGH"

        elif score >= 70:

            severity = "HIGH"

            assessment = (
                "SUSPICIOUS_ATTACK_SEQUENCE"
            )

            confidence = "HIGH"

        elif score >= 40:

            severity = "MEDIUM"

            assessment = (
                "SUSPICIOUS_ACTIVITY"
            )

            confidence = "MEDIUM"

        else:

            severity = "LOW"

            assessment = (
                "LOW_RISK_ACTIVITY"
            )

            confidence = "LOW"

        incidents.append({

            "user": user,

            "start_time": group[
                "timestamp"
            ].min(),

            "end_time": group[
                "timestamp"
            ].max(),

            "sequence_score": score,

            "severity": severity,

            "confidence": confidence,

            "assessment": assessment,

            "attack_pattern": attack_pattern,

            "phases_detected":
                " → ".join(ordered_phases),

            "indicators_detected":
                " | ".join(indicators_detected),

            "events_analyzed":
                len(group)

        })

    return pd.DataFrame(
        incidents
    )


if __name__ == "__main__":

    print(
        "\n===== ATTACK SEQUENCE ENGINE V2 =====\n"
    )

    df = pd.read_csv(
        "data/live_events.csv"
    )

    result = analyze_attack_sequence(
        df
    )

    if result.empty:

        print(
            "No suspicious attack sequences detected."
        )

    else:

        print(
            result.to_string(
                index=False
            )
        )

    print(
        "\n======================================"
    )