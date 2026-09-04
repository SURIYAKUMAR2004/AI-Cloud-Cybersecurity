# ============================================================
# THREAT DETECTOR
# AI Cloud Cybersecurity
# ============================================================

import os
import warnings

import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_BASELINE_SIZE = 350


# ============================================================
# TIMESTAMP NORMALIZATION
# ============================================================

def normalize_timestamps(df):
    """
    Normalize timestamp column safely.

    Supports:
    - ISO timestamps
    - AWS timestamps
    - mixed timestamp formats
    - timezone-aware timestamps
    """

    df = df.copy()

    if "timestamp" not in df.columns:
        df["timestamp"] = pd.NaT

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        format="mixed",
        errors="coerce",
        utc=True,
    )

    return df


# ============================================================
# LOAD SECURITY DATA
# ============================================================

def load_security_data(file_path):
    """
    Load security events from CSV.
    """

    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"Security data file not found: {file_path}"
        )

    df = pd.read_csv(file_path)

    df = normalize_timestamps(df)

    if "hour" not in df.columns:
        df["hour"] = df["timestamp"].dt.hour

    return df


# ============================================================
# USER BEHAVIOR PROFILES
# ============================================================

def build_user_profiles(df):
    """
    Build historical behavioral profiles for every user.

    Profile includes:
    - known source IPs
    - known actions
    - average bytes transferred
    - normal activity hours
    """

    df = df.copy()

    df = normalize_timestamps(df)

    if "timestamp" in df.columns:
        df["hour"] = df["timestamp"].dt.hour
    else:
        df["hour"] = 0

    profiles = {}

    users = (
        df["user"]
        .dropna()
        .astype(str)
        .unique()
        if "user" in df.columns
        else []
    )

    for user in users:

        user_data = df[
            df["user"].astype(str) == user
        ]

        # ----------------------------------------------------
        # KNOWN SOURCE IPs
        # ----------------------------------------------------

        known_ips = set()

        if "source_ip" in user_data.columns:

            known_ips = set(
                user_data["source_ip"]
                .dropna()
                .astype(str)
                .unique()
            )

        # ----------------------------------------------------
        # KNOWN ACTIONS
        # ----------------------------------------------------

        known_actions = set()

        if "action" in user_data.columns:

            known_actions = set(
                user_data["action"]
                .dropna()
                .astype(str)
                .unique()
            )

        # ----------------------------------------------------
        # AVERAGE BYTES
        # ----------------------------------------------------

        average_bytes = 0.0

        if "bytes_transferred" in user_data.columns:

            average_bytes = (
                pd.to_numeric(
                    user_data["bytes_transferred"],
                    errors="coerce",
                )
                .fillna(0)
                .mean()
            )

        # ----------------------------------------------------
        # NORMAL ACTIVITY HOURS
        # ----------------------------------------------------

        active_hours = set()

        if "hour" in user_data.columns:

            active_hours = set(
                user_data["hour"]
                .dropna()
                .astype(int)
                .unique()
            )

        profiles[user] = {
            "known_ips": known_ips,
            "known_actions": known_actions,
            "average_bytes": float(average_bytes),
            "active_hours": active_hours,
        }

    return profiles


# ============================================================
# BEHAVIOR FEATURES
# ============================================================

def create_behavior_features(df):
    """
    Create numerical features for anomaly detection.
    """

    df = df.copy()

    features = pd.DataFrame(
        index=df.index
    )

    # --------------------------------------------------------
    # SOURCE IP FEATURE
    # --------------------------------------------------------

    if "source_ip" in df.columns:

        encoder = LabelEncoder()

        values = (
            df["source_ip"]
            .fillna("UNKNOWN")
            .astype(str)
        )

        features["source_ip_encoded"] = (
            encoder.fit_transform(values)
        )

    else:

        features["source_ip_encoded"] = 0

    # --------------------------------------------------------
    # ACTION FEATURE
    # --------------------------------------------------------

    if "action" in df.columns:

        encoder = LabelEncoder()

        values = (
            df["action"]
            .fillna("UNKNOWN")
            .astype(str)
        )

        features["action_encoded"] = (
            encoder.fit_transform(values)
        )

    else:

        features["action_encoded"] = 0

    # --------------------------------------------------------
    # STATUS FEATURE
    # --------------------------------------------------------

    if "status" in df.columns:

        features["status_failed"] = (
            df["status"]
            .astype(str)
            .str.upper()
            .eq("FAILED")
            .astype(int)
        )

    else:

        features["status_failed"] = 0

    # --------------------------------------------------------
    # BYTES FEATURE
    # --------------------------------------------------------

    if "bytes_transferred" in df.columns:

        features["bytes_transferred"] = (
            pd.to_numeric(
                df["bytes_transferred"],
                errors="coerce",
            )
            .fillna(0)
        )

    else:

        features["bytes_transferred"] = 0

    # --------------------------------------------------------
    # TIME FEATURE
    # --------------------------------------------------------

    if "timestamp" in df.columns:

        timestamps = pd.to_datetime(
            df["timestamp"],
            format="mixed",
            errors="coerce",
            utc=True,
        )

        features["hour"] = (
            timestamps.dt.hour
            .fillna(0)
        )

    else:

        features["hour"] = 0

    return features


# ============================================================
# AI ANOMALY DETECTION
# ============================================================

def detect_anomalies(
    df,
    contamination=0.05,
    random_state=42,
):
    """
    Detect anomalous security events using Isolation Forest.

    Accepts either:
    - pandas DataFrame
    - CSV file path
    """

    if isinstance(df, str):

        df = pd.read_csv(df)

    elif not isinstance(df, pd.DataFrame):

        raise TypeError(
            "df must be a pandas DataFrame or CSV file path"
        )

    df = df.copy()

    if df.empty:

        df["anomaly_score"] = []

        df["is_anomaly"] = []

        return df

    df = normalize_timestamps(df)

    if "hour" not in df.columns:

        df["hour"] = (
            df["timestamp"].dt.hour
        )

    features = create_behavior_features(df)

    # --------------------------------------------------------
    # CLEAN FEATURE DATA
    # --------------------------------------------------------

    features = features.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    features = features.fillna(0)

    # --------------------------------------------------------
    # HANDLE VERY SMALL DATASETS
    # --------------------------------------------------------

    if len(features) < 2:

        df["anomaly_score"] = 0.0

        df["is_anomaly"] = False

        return df

    # --------------------------------------------------------
    # ISOLATION FOREST
    # --------------------------------------------------------

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
    )

    with warnings.catch_warnings():

        warnings.simplefilter("ignore")

        predictions = model.fit_predict(
            features
        )

    raw_scores = model.decision_function(
        features
    )

    # --------------------------------------------------------
    # CONVERT TO 0-100 ANOMALY SCORE
    # --------------------------------------------------------

    anomaly_scores = (
        50 - (raw_scores * 100)
    )

    anomaly_scores = np.clip(
        anomaly_scores,
        0,
        100,
    )

    df["anomaly_score"] = (
        anomaly_scores
    )

    df["is_anomaly"] = (
        predictions == -1
    )

    return df


# ============================================================
# BEHAVIORAL DEVIATION
# ============================================================

def calculate_behavior_deviation(
    row,
    profile,
):
    """
    Calculate how far an event deviates
    from the user's historical behavior.

    Scoring signals:

    Unknown source IP       +30
    New action              +25
    Unusual data transfer   +25
    Unusual activity hour  +20

    Maximum score = 100
    """

    if not profile:

        return 50

    score = 0

    # --------------------------------------------------------
    # UNKNOWN SOURCE IP
    # --------------------------------------------------------

    source_ip = row.get(
        "source_ip"
    )

    if (
        pd.notna(source_ip)
        and str(source_ip)
        not in profile["known_ips"]
    ):

        score += 30

    # --------------------------------------------------------
    # NEW ACTION
    # --------------------------------------------------------

    action = row.get(
        "action"
    )

    if (
        pd.notna(action)
        and str(action)
        not in profile["known_actions"]
    ):

        score += 25

    # --------------------------------------------------------
    # UNUSUAL DATA TRANSFER
    # --------------------------------------------------------

    try:

        bytes_transferred = float(
            row.get(
                "bytes_transferred",
                0,
            )
        )

        average_bytes = float(
            profile.get(
                "average_bytes",
                0,
            )
        )

        if (
            average_bytes > 0
            and bytes_transferred
            > average_bytes * 5
        ):

            score += 25

    except (
        TypeError,
        ValueError,
    ):

        pass

    # --------------------------------------------------------
    # UNUSUAL ACTIVITY HOUR
    # --------------------------------------------------------

    try:

        timestamp = row.get(
            "timestamp"
        )

        if pd.notna(timestamp):

            timestamp = pd.to_datetime(
                timestamp,
                errors="coerce",
                utc=True,
            )

            if pd.notna(timestamp):

                hour = timestamp.hour

                active_hours = (
                    profile.get(
                        "active_hours",
                        set(),
                    )
                )

                if (
                    active_hours
                    and hour
                    not in active_hours
                ):

                    score += 20

    except Exception:

        pass

    return min(
        score,
        100,
    )


# ============================================================
# BEHAVIOR ANALYSIS
# ============================================================

def apply_behavior_analysis(
    df,
    baseline_size=DEFAULT_BASELINE_SIZE,
):
    """
    Apply historical behavioral analysis.

    The first portion of the dataset is used as the
    historical behavioral baseline.

    ALL events are retained for downstream processing.

    Behavioral classification:

        0-29   -> NORMAL
        30-59  -> MEDIUM_DEVIATION
        60-100 -> HIGH_DEVIATION
    """

    df = df.copy()

    if df.empty:

        return (
            df.copy(),
            df.copy(),
        )

    # --------------------------------------------------------
    # NORMALIZE TIMESTAMPS
    # --------------------------------------------------------

    df = normalize_timestamps(
        df
    )

    df["hour"] = (
        df["timestamp"].dt.hour
    )

    # --------------------------------------------------------
    # BUILD HISTORICAL BASELINE
    # --------------------------------------------------------
    #
    # IMPORTANT:
    #
    # We do NOT use the entire dataset as its own baseline.
    #
    # Example:
    #
    # 186 events
    #       ↓
    # 93 historical baseline events
    #       ↓
    # 186 events evaluated
    #
    # This prevents baseline contamination.
    # --------------------------------------------------------

    if len(df) <= 1:

        baseline_count = len(df)

    else:

        baseline_count = min(
            baseline_size,
            max(
                1,
                len(df) // 2,
            ),
        )

    baseline = df.head(
        baseline_count
    ).copy()

    # --------------------------------------------------------
    # KEEP ALL EVENTS
    # --------------------------------------------------------

    events = df.copy()

    # --------------------------------------------------------
    # BUILD PROFILES FROM HISTORICAL DATA
    # --------------------------------------------------------

    profiles = build_user_profiles(
        baseline
    )

    # --------------------------------------------------------
    # INITIALIZE BEHAVIOR COLUMNS
    # --------------------------------------------------------

    events[
        "behavior_deviation_score"
    ] = 0

    events[
        "behavior_status"
    ] = "NORMAL"

    # --------------------------------------------------------
    # CALCULATE BEHAVIORAL DEVIATION
    # --------------------------------------------------------

    for idx, row in events.iterrows():

        user = row.get(
            "user"
        )

        if pd.notna(user):

            user = str(user)

        else:

            user = ""

        profile = profiles.get(
            user,
            {},
        )

        score = calculate_behavior_deviation(
            row,
            profile,
        )

        score = int(score)

        events.at[
            idx,
            "behavior_deviation_score",
        ] = score

        # ----------------------------------------------------
        # BEHAVIOR CLASSIFICATION
        # ----------------------------------------------------
        #
        # 0-29   = NORMAL
        # 30-59  = MEDIUM DEVIATION
        # 60-100 = HIGH DEVIATION
        #
        # This makes a score of 30 meaningful.
        # ----------------------------------------------------

        if score >= 60:

            events.at[
                idx,
                "behavior_status",
            ] = "HIGH_DEVIATION"

        elif score >= 30:

            events.at[
                idx,
                "behavior_status",
            ] = "MEDIUM_DEVIATION"

        else:

            events.at[
                idx,
                "behavior_status",
            ] = "NORMAL"

    return (
        baseline,
        events,
    )


# ============================================================
# COMPLETE THREAT DETECTION PIPELINE
# ============================================================

def run_threat_detection(
    df,
    baseline_size=DEFAULT_BASELINE_SIZE,
):
    """
    Run the complete behavioral threat detection pipeline.
    """

    df = df.copy()

    df = normalize_timestamps(
        df
    )

    # --------------------------------------------------------
    # AI ANOMALY DETECTION
    # --------------------------------------------------------

    results = detect_anomalies(
        df
    )

    # --------------------------------------------------------
    # BEHAVIORAL INTELLIGENCE
    # --------------------------------------------------------

    baseline, results = (
        apply_behavior_analysis(
            results,
            baseline_size=baseline_size,
        )
    )

    return (
        baseline,
        results,
    )


# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================

apply_threat_detection = (
    run_threat_detection
)


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    file_path = (
        "data/aws_cloudtrail_events.csv"
    )

    if not os.path.exists(
        file_path
    ):

        print(
            f"❌ File not found: {file_path}"
        )

        raise SystemExit(1)

    print(
        "\n🔐 AI CLOUD CYBERSECURITY"
    )

    print(
        "\n🧠 THREAT DETECTOR"
    )

    print(
        "\n========================================"
    )

    # --------------------------------------------------------
    # LOAD DATA
    # --------------------------------------------------------

    df = pd.read_csv(
        file_path
    )

    print(
        f"\nTotal events loaded: {len(df)}"
    )

    # --------------------------------------------------------
    # RUN BEHAVIOR ANALYSIS
    # --------------------------------------------------------

    baseline, results = (
        apply_behavior_analysis(
            df,
            baseline_size=DEFAULT_BASELINE_SIZE,
        )
    )

    print(
        f"\nHistorical baseline events: "
        f"{len(baseline)}"
    )

    print(
        f"\nEvents evaluated: "
        f"{len(results)}"
    )

    # --------------------------------------------------------
    # BEHAVIOR STATUS
    # --------------------------------------------------------

    print(
        "\nBehavior Status:"
    )

    print(
        results[
            "behavior_status"
        ].value_counts()
    )

    # --------------------------------------------------------
    # BEHAVIOR SCORE STATISTICS
    # --------------------------------------------------------

    print(
        "\nBehavior Score Statistics:"
    )

    print(
        results[
            "behavior_deviation_score"
        ].describe()
    )

    # --------------------------------------------------------
    # TOP DEVIATIONS
    # --------------------------------------------------------

    print(
        "\nTop Behavioral Deviations:"
    )

    columns = [
        "timestamp",
        "user",
        "source_ip",
        "action",
        "behavior_deviation_score",
        "behavior_status",
    ]

    available_columns = [
        column
        for column in columns
        if column in results.columns
    ]

    print(
        results.sort_values(
            "behavior_deviation_score",
            ascending=False,
        )[
            available_columns
        ]
        .head(15)
        .to_string(
            index=False
        )
    )

    print(
        "\n✅ Threat detection completed."
    )
