
import hashlib
import pandas as pd


SUSPICIOUS_IPS = {
    "45.155.205.10",
    "103.27.186.20",
    "185.220.101.5",
}


PRIVILEGED_ACTIONS = {
    "AssumeRole",
    "CreateUser",
    "ChangePassword",
    "DeleteObject",
    "CreateTrail",
}


RECON_ACTIONS = {
    "DescribeTrails",
    "GetTrailStatus",
    "ListBuckets",
    "LookupEvents",
    "GetCallerIdentity",
}


def generate_incident_id(user, start_time, end_time):
    raw = f"{user}|{start_time}|{end_time}"

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:16]


def correlate_attack_chain(df):

    columns = [
        "incident_id",
        "user",
        "source_ip",
        "start_time",
        "end_time",
        "chain_score",
        "severity",
        "assessment",
        "attack_pattern",
        "events_correlated",
    ]

    if df.empty:
        return pd.DataFrame(columns=columns)

    df = df.copy()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        format="mixed",
    )

    df = df.sort_values(
        "timestamp"
    ).reset_index(drop=True)

    incidents = []

    for user, events in df.groupby("user"):

        events = (
            events
            .sort_values("timestamp")
            .reset_index(drop=True)
        )

        i = 0

        while i < len(events):

            start_time = events.loc[
                i,
                "timestamp",
            ]

            end_time = (
                start_time
                + pd.Timedelta(minutes=10)
            )

            window = events[
                (events["timestamp"] >= start_time)
                &
                (events["timestamp"] <= end_time)
            ].copy()

            if window.empty:
                i += 1
                continue

            # --------------------------------------------------
            # Security indicators
            # --------------------------------------------------

            failed = (
                window["status"]
                .eq("Failed")
                .any()
            )

            privileged = (
                window["action"]
                .isin(PRIVILEGED_ACTIONS)
                .any()
            )

            suspicious_ip = (
                window["source_ip"]
                .isin(SUSPICIOUS_IPS)
                .any()
            )

            large_transfer = (
                window["bytes_transferred"]
                > 50000
            ).any()

            recon_actions = (
                window["action"]
                .isin(RECON_ACTIONS)
                .sum()
            )

            unique_ips = (
                window["source_ip"]
                .nunique()
            )

            failed_count = (
                window["status"]
                .eq("Failed")
                .sum()
            )

            # --------------------------------------------------
            # Attack-chain scoring
            # --------------------------------------------------

            score = 0
            reasons = []

            if failed:
                score += 20
                reasons.append(
                    "Failed cloud operation"
                )

            if failed_count >= 2:
                score += 20
                reasons.append(
                    "Repeated failed operations"
                )

            if privileged:
                score += 30
                reasons.append(
                    "Privileged cloud operation"
                )

            if suspicious_ip:
                score += 30
                reasons.append(
                    "Known suspicious source"
                )

            if large_transfer:
                score += 20
                reasons.append(
                    "Large data transfer"
                )

            if recon_actions >= 2:
                score += 20
                reasons.append(
                    "Repeated reconnaissance activity"
                )

            if unique_ips >= 2:
                score += 15
                reasons.append(
                    "Multiple source IPs"
                )

            score = min(score, 100)

            # --------------------------------------------------
            # Only create an incident for meaningful chains
            # --------------------------------------------------

            if score >= 60:

                if score >= 80:
                    severity = "CRITICAL"
                else:
                    severity = "HIGH"

                # --------------------------------------------------
                # Assessment
                # --------------------------------------------------

                if (
                    privileged
                    and suspicious_ip
                    and large_transfer
                ):
                    assessment = (
                        "POSSIBLE_ACCOUNT_COMPROMISE"
                    )

                elif (
                    suspicious_ip
                    and large_transfer
                ):
                    assessment = (
                        "POSSIBLE_DATA_EXFILTRATION"
                    )

                elif (
                    failed_count >= 2
                    and recon_actions >= 2
                ):
                    assessment = (
                        "POSSIBLE_CLOUD_RECONNAISSANCE"
                    )

                elif privileged:
                    assessment = (
                        "SUSPICIOUS_PRIVILEGED_ACTIVITY"
                    )

                elif recon_actions >= 2:
                    assessment = (
                        "SUSPICIOUS_RECONNAISSANCE"
                    )

                else:
                    assessment = (
                        "SUSPICIOUS_ACTIVITY"
                    )

                # --------------------------------------------------
                # Incident metadata
                # --------------------------------------------------

                incident_start = start_time

                incident_end = (
                    window["timestamp"].max()
                )

                source_ip = (
                    window["source_ip"].iloc[0]
                )

                incident_id = generate_incident_id(
                    user,
                    incident_start,
                    incident_end,
                )

                incidents.append(
                    {
                        "incident_id": incident_id,
                        "user": user,
                        "source_ip": source_ip,
                        "start_time": incident_start,
                        "end_time": incident_end,
                        "chain_score": score,
                        "severity": severity,
                        "assessment": assessment,
                        "attack_pattern": (
                            " → ".join(reasons)
                        ),
                        "events_correlated": len(window),
                    }
                )

                # --------------------------------------------------
                # Move beyond this incident window
                # --------------------------------------------------

                future_events = events[
                    events["timestamp"] > end_time
                ]

                if future_events.empty:
                    break

                next_time = (
                    future_events["timestamp"]
                    .min()
                )

                next_positions = events.index[
                    events["timestamp"] == next_time
                ]

                if len(next_positions) > 0:
                    i = next_positions[0]
                else:
                    i += 1

            else:
                i += 1

    if not incidents:
        return pd.DataFrame(columns=columns)

    return (
        pd.DataFrame(incidents)
        .sort_values(
            "chain_score",
            ascending=False,
        )
        .reset_index(drop=True)
    )


if __name__ == "__main__":

    print(
        "\n===== CORRELATED SECURITY INCIDENTS =====\n"
    )

    df = pd.read_csv(
        "data/aws_cloudtrail_events.csv"
    )

    incidents = correlate_attack_chain(df)

    if incidents.empty:

        print(
            "No correlated security incidents detected."
        )

    else:

        print(
            incidents.to_string(
                index=False
            )
        )

    print(
        "\n=========================================="
    )
