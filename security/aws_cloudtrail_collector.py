import json
import time
from pathlib import Path
from datetime import datetime, timezone

import boto3
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

AWS_REGION = "ap-south-1"
OUTPUT_FILE = "data/aws_cloudtrail_events.csv"
DEFAULT_MAX_RESULTS = 50


# ============================================================
# AWS CLIENT
# ============================================================

def get_cloudtrail_client():
    """
    Create an AWS CloudTrail client using the currently
    authenticated AWS CLI / boto3 session.
    """
    return boto3.client(
        "cloudtrail",
        region_name=AWS_REGION,
    )


# ============================================================
# CLOUDTRAIL JSON PARSER
# ============================================================

def parse_cloudtrail_event(event):
    """
    Safely parse the embedded CloudTrailEvent JSON.
    """
    raw_event = event.get("CloudTrailEvent")

    if not raw_event:
        return {}

    if isinstance(raw_event, dict):
        return raw_event

    try:
        return json.loads(raw_event)
    except Exception:
        return {}


# ============================================================
# TIMESTAMP NORMALIZATION
# ============================================================

def normalize_timestamp(event_time):
    """
    Convert a timestamp into UTC ISO-8601 format.
    """

    if event_time is None:
        return None

    try:
        if isinstance(event_time, datetime):

            if event_time.tzinfo is None:
                event_time = event_time.replace(
                    tzinfo=timezone.utc
                )

            return event_time.astimezone(
                timezone.utc
            ).isoformat()

        parsed_time = pd.to_datetime(
            event_time,
            errors="coerce",
            utc=True,
        )

        if pd.isna(parsed_time):
            return None

        return parsed_time.isoformat()

    except Exception:
        return None


def extract_timestamp(event):
    """
    Extract timestamp using multiple CloudTrail sources.

    Priority:
    1. LookupEvents EventTime
    2. Embedded CloudTrailEvent eventTime
    """

    event_time = event.get("EventTime")

    timestamp = normalize_timestamp(event_time)

    if timestamp is not None:
        return timestamp

    cloudtrail_event = parse_cloudtrail_event(event)

    embedded_time = (
        cloudtrail_event.get("eventTime")
        or cloudtrail_event.get("EventTime")
    )

    return normalize_timestamp(embedded_time)


# ============================================================
# USER EXTRACTION
# ============================================================

def extract_user(event):
    """
    Extract the most useful identity from a CloudTrail event.
    """

    username = event.get("Username")

    if username:
        return username

    cloudtrail_event = parse_cloudtrail_event(event)

    user_identity = cloudtrail_event.get(
        "userIdentity",
        {},
    )

    user_name = user_identity.get("userName")

    if user_name:
        return user_name

    arn = user_identity.get("arn")

    if arn:
        return arn

    principal_id = user_identity.get("principalId")

    if principal_id:
        return principal_id

    return "Unknown"


# ============================================================
# SOURCE IP EXTRACTION
# ============================================================

def extract_source_ip(event):
    """
    Extract source IP from CloudTrail event.
    """

    source_ip = event.get("SourceIPAddress")

    if source_ip:
        return source_ip

    cloudtrail_event = parse_cloudtrail_event(event)

    source_ip = cloudtrail_event.get(
        "sourceIPAddress"
    )

    if source_ip:
        return source_ip

    return "Unknown"


# ============================================================
# ACTION EXTRACTION
# ============================================================

def extract_action(event):
    """
    Extract CloudTrail API action/event name.
    """

    event_name = event.get("EventName")

    if event_name:
        return event_name

    cloudtrail_event = parse_cloudtrail_event(event)

    event_name = cloudtrail_event.get("eventName")

    if event_name:
        return event_name

    return "Unknown"


# ============================================================
# ERROR EXTRACTION
# ============================================================

def extract_error_details(event):
    """
    Extract CloudTrail error information.
    """

    error_code = event.get("ErrorCode")
    error_message = event.get("ErrorMessage")

    if error_code or error_message:
        return error_code, error_message

    cloudtrail_event = parse_cloudtrail_event(event)

    error_code = cloudtrail_event.get(
        "errorCode"
    )

    error_message = cloudtrail_event.get(
        "errorMessage"
    )

    return error_code, error_message


# ============================================================
# READ-ONLY EXTRACTION
# ============================================================

def extract_read_only(event):
    """
    Determine whether the CloudTrail event is read-only.
    """

    read_only = event.get("ReadOnly")

    if read_only is not None:
        return read_only

    cloudtrail_event = parse_cloudtrail_event(event)

    read_only = cloudtrail_event.get(
        "readOnly"
    )

    if read_only is not None:
        return read_only

    return None


# ============================================================
# EVENT ID EXTRACTION
# ============================================================

def extract_event_id(event):
    """
    Extract a stable CloudTrail event ID.
    """

    event_id = (
        event.get("EventId")
        or event.get("EventID")
        or event.get("eventID")
    )

    if event_id:
        return event_id

    cloudtrail_event = parse_cloudtrail_event(event)

    return (
        cloudtrail_event.get("eventID")
        or cloudtrail_event.get("eventId")
    )


# ============================================================
# AWS REGION EXTRACTION
# ============================================================

def extract_region(event):
    """
    Extract AWS region from event.
    """

    cloudtrail_event = parse_cloudtrail_event(event)

    return (
        cloudtrail_event.get("awsRegion")
        or AWS_REGION
    )


# ============================================================
# EVENT NORMALIZATION
# ============================================================

def normalize_event(event):
    """
    Convert a raw AWS CloudTrail event into the common
    security-event format used by the AI security pipeline.
    """

    event_time = extract_timestamp(event)

    user = extract_user(event)

    source_ip = extract_source_ip(event)

    action = extract_action(event)

    error_code, error_message = (
        extract_error_details(event)
    )

    read_only = extract_read_only(event)

    event_id = extract_event_id(event)

    aws_region = extract_region(event)

    status = (
        "Failed"
        if error_code or error_message
        else "Success"
    )

    return {
        "timestamp": event_time,
        "user": user,
        "source_ip": source_ip,
        "action": action,
        "status": status,
        "bytes_transferred": 0,
        "event_id": event_id,
        "aws_region": aws_region,
        "read_only": read_only,
        "error_code": error_code,
        "error_message": error_message,
    }


# ============================================================
# COLLECT CLOUDTRAIL EVENTS
# ============================================================

def collect_cloudtrail_events(
    max_results=DEFAULT_MAX_RESULTS
):
    """
    Retrieve recent CloudTrail events from AWS.
    """

    client = get_cloudtrail_client()

    print(
        f"Collecting CloudTrail events from "
        f"AWS region: {AWS_REGION}"
    )

    response = client.lookup_events(
        MaxResults=max_results
    )

    events = response.get("Events", [])

    normalized_events = []

    for event in events:

        try:
            normalized_event = normalize_event(event)

            normalized_events.append(
                normalized_event
            )

        except Exception as exc:
            print(
                f"Warning: Could not normalize "
                f"event: {exc}"
            )

    print(
        f"Collected {len(normalized_events)} "
        f"CloudTrail events."
    )

    return normalized_events


# ============================================================
# PRESERVE BEST DUPLICATE
# ============================================================

def preserve_best_event(group):
    """
    When the same event_id exists multiple times,
    preserve the record containing the most complete data.

    Most importantly, NEVER replace a valid timestamp
    with a missing timestamp.
    """

    group = group.copy()

    group["_timestamp_valid"] = (
        pd.to_datetime(
            group["timestamp"],
            errors="coerce",
            utc=True,
        ).notna()
    )

    group["_completeness"] = (
        group.notna().sum(axis=1)
    )

    group = group.sort_values(
        [
            "_timestamp_valid",
            "_completeness",
        ],
        ascending=[
            False,
            False,
        ],
    )

    best_row = group.iloc[0].copy()

    return best_row


# ============================================================
# SAVE EVENTS
# ============================================================

def save_events(events):
    """
    Save normalized CloudTrail events to CSV.

    Existing events are preserved.
    Events are deduplicated using event_id.

    A valid timestamp is never overwritten by a missing one.
    """

    output_path = Path(OUTPUT_FILE)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    new_df = pd.DataFrame(events)

    if new_df.empty:
        print(
            "No new CloudTrail events to save."
        )
        return

    # --------------------------------------------------------
    # Expected columns
    # --------------------------------------------------------

    expected_columns = [
        "timestamp",
        "user",
        "source_ip",
        "action",
        "status",
        "bytes_transferred",
        "event_id",
        "aws_region",
        "read_only",
        "error_code",
        "error_message",
    ]

    # --------------------------------------------------------
    # Load existing data
    # --------------------------------------------------------

    if output_path.exists():

        try:
            existing_df = pd.read_csv(
                output_path
            )

        except Exception:
            existing_df = pd.DataFrame()

    else:
        existing_df = pd.DataFrame()

    # --------------------------------------------------------
    # Ensure columns
    # --------------------------------------------------------

    for column in expected_columns:

        if column not in new_df.columns:
            new_df[column] = None

        if (
            not existing_df.empty
            and column not in existing_df.columns
        ):
            existing_df[column] = None

    new_df = new_df[expected_columns]

    if not existing_df.empty:
        existing_df = existing_df[
            expected_columns
        ]

    # --------------------------------------------------------
    # Normalize timestamps before combining
    # --------------------------------------------------------

    new_df["timestamp"] = (
        new_df["timestamp"].apply(
            normalize_timestamp
        )
    )

    if not existing_df.empty:

        existing_df["timestamp"] = (
            existing_df["timestamp"].apply(
                normalize_timestamp
            )
        )

    # --------------------------------------------------------
    # Combine
    # --------------------------------------------------------

    if not existing_df.empty:

        combined_df = pd.concat(
            [
                existing_df,
                new_df,
            ],
            ignore_index=True,
        )

    else:
        combined_df = new_df.copy()

    # --------------------------------------------------------
    # Handle missing event IDs safely
    # --------------------------------------------------------

    missing_event_id_mask = (
        combined_df["event_id"].isna()
        | combined_df["event_id"]
        .astype(str)
        .str.strip()
        .isin(["", "nan", "None"])
    )

    rows_without_id = combined_df[
        missing_event_id_mask
    ].copy()

    rows_with_id = combined_df[
        ~missing_event_id_mask
    ].copy()

    # --------------------------------------------------------
    # Preserve best duplicate for each event_id
    # --------------------------------------------------------

    if not rows_with_id.empty:

        best_rows = []

        for _, group in rows_with_id.groupby(
            "event_id",
            sort=False,
        ):

            best_rows.append(
                preserve_best_event(group)
            )

        rows_with_id = pd.DataFrame(
            best_rows
        )

    # --------------------------------------------------------
    # Recombine
    # --------------------------------------------------------

    combined_df = pd.concat(
        [
            rows_with_id,
            rows_without_id,
        ],
        ignore_index=True,
    )

    # --------------------------------------------------------
    # Remove helper columns
    # --------------------------------------------------------

    helper_columns = [
        "_timestamp_valid",
        "_completeness",
    ]

    combined_df = combined_df.drop(
        columns=[
            column
            for column in helper_columns
            if column in combined_df.columns
        ],
        errors="ignore",
    )

    combined_df = combined_df[
        expected_columns
    ]

    # --------------------------------------------------------
    # Final timestamp normalization
    # --------------------------------------------------------

    combined_df["timestamp"] = (
        combined_df["timestamp"].apply(
            normalize_timestamp
        )
    )

    # --------------------------------------------------------
    # Sort by timestamp
    # --------------------------------------------------------

    combined_df["_sort_timestamp"] = (
        pd.to_datetime(
            combined_df["timestamp"],
            errors="coerce",
            utc=True,
        )
    )

    combined_df = combined_df.sort_values(
        "_sort_timestamp",
        na_position="last",
    )

    combined_df = combined_df.drop(
        columns=["_sort_timestamp"]
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    combined_df.to_csv(
        output_path,
        index=False,
    )

    missing_timestamps = (
        pd.to_datetime(
            combined_df["timestamp"],
            errors="coerce",
            utc=True,
        )
        .isna()
        .sum()
    )

    print(
        f"Saved {len(combined_df)} unique "
        f"CloudTrail events to {OUTPUT_FILE}"
    )

    print(
        f"Events with missing timestamps: "
        f"{missing_timestamps}"
    )


# ============================================================
# REPAIR EXISTING MISSING TIMESTAMPS
# ============================================================

def repair_missing_timestamps():
    """
    Recover missing timestamps from AWS CloudTrail by EventId.
    """

    output_path = Path(OUTPUT_FILE)

    if not output_path.exists():
        print(
            "No existing CloudTrail CSV found."
        )
        return

    df = pd.read_csv(output_path)

    if "timestamp" not in df.columns:
        df["timestamp"] = None

    parsed_timestamp = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        utc=True,
    )

    missing_mask = parsed_timestamp.isna()

    missing_count = int(
        missing_mask.sum()
    )

    print(
        f"Missing timestamps before repair: "
        f"{missing_count}"
    )

    if missing_count == 0:

        print(
            "No timestamp repair required."
        )

        return

    client = get_cloudtrail_client()

    repaired = 0
    failed = 0

    missing_indices = df.index[
        missing_mask
    ].tolist()

    for position, index in enumerate(
        missing_indices,
        start=1,
    ):

        event_id = df.at[
            index,
            "event_id"
        ]

        if (
            pd.isna(event_id)
            or not str(event_id).strip()
        ):
            failed += 1
            continue

        try:

            response = client.lookup_events(
                LookupAttributes=[
                    {
                        "AttributeKey": "EventId",
                        "AttributeValue": str(
                            event_id
                        ),
                    }
                ],
                MaxResults=1,
            )

            events = response.get(
                "Events",
                [],
            )

            if events:

                timestamp = extract_timestamp(
                    events[0]
                )

                if timestamp is not None:

                    df.at[
                        index,
                        "timestamp"
                    ] = timestamp

                    repaired += 1

                else:
                    failed += 1

            else:
                failed += 1

        except Exception as exc:

            failed += 1

            print(
                f"Could not repair "
                f"{event_id}: {exc}"
            )

        if position % 10 == 0:

            print(
                f"Repair progress: "
                f"{position}/"
                f"{len(missing_indices)}"
            )

        time.sleep(0.15)

    # --------------------------------------------------------
    # Final normalization
    # --------------------------------------------------------

    df["timestamp"] = (
        df["timestamp"].apply(
            normalize_timestamp
        )
    )

    timestamp_sort = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        utc=True,
    )

    df["_sort_timestamp"] = timestamp_sort

    df = df.sort_values(
        "_sort_timestamp",
        na_position="last",
    )

    df = df.drop(
        columns=["_sort_timestamp"]
    )

    df.to_csv(
        output_path,
        index=False,
    )

    final_missing = (
        pd.to_datetime(
            df["timestamp"],
            errors="coerce",
            utc=True,
        )
        .isna()
        .sum()
    )

    print("=" * 60)

    print(
        f"Repaired: {repaired}"
    )

    print(
        f"Failed: {failed}"
    )

    print(
        f"Rows: {len(df)}"
    )

    print(
        f"Missing timestamps remaining: "
        f"{final_missing}"
    )

    if final_missing == 0:
        print(
            "✅ ALL AWS EVENT TIMESTAMPS ARE PRESENT"
        )

    else:
        print(
            "⚠️ Some timestamps could not "
            "be recovered from AWS."
        )

    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)

    print(
        "AWS CLOUDTRAIL COLLECTOR"
    )

    print("=" * 60)

    try:

        events = collect_cloudtrail_events()

        save_events(events)

        print("=" * 60)

        print(
            "CLOUDTRAIL COLLECTION COMPLETED"
        )

        print("=" * 60)

    except Exception as exc:

        print("=" * 60)

        print(
            "CLOUDTRAIL COLLECTION FAILED"
        )

        print("=" * 60)

        print(exc)

        raise


if __name__ == "__main__":
    main()
