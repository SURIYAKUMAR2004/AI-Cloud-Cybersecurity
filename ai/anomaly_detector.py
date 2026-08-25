import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder


def detect_anomalies(file_path):
    # Load security logs
    if isinstance(file_path, pd.DataFrame):
        df = file_path.copy()
    else:
        df = pd.read_csv(file_path)

    # Create a copy for ML processing
    ml_data = df.copy()

    # Encode categorical security features
    encoders = {}

    categorical_columns = [
        "user",
        "source_ip",
        "action",
        "status"
    ]

    if "resource" in ml_data.columns:
        categorical_columns.insert(3, "resource")

    for column in categorical_columns:
        encoder = LabelEncoder()
        ml_data[column] = encoder.fit_transform(ml_data[column])
        encoders[column] = encoder

    # Select features for anomaly detection
    features = [
        "user",
        "source_ip",
        "action",
        "status",
        "bytes_transferred"
    ]

    if "resource" in ml_data.columns:
        features.insert(3, "resource")

    X = ml_data[features]

    # Create Isolation Forest model
    model = IsolationForest(
        contamination=0.10,
        random_state=42
    )

    # Train model
    model.fit(X)

    # Predict anomalies
    predictions = model.predict(X)

    # Convert prediction:
    # 1  = Normal
    # -1 = Anomaly

    df["anomaly"] = predictions

    # Calculate anomaly score
    df["anomaly_score"] = model.decision_function(X)

    # Human-readable classification
    df["threat_status"] = df["anomaly"].apply(
        lambda x: "Anomaly" if x == -1 else "Normal"
    )

    return df


if __name__ == "__main__":

    result = detect_anomalies("data/sample_logs.csv")

    print("\n===== AI CLOUD SECURITY ANALYSIS =====\n")

    print(
        result[
            [
                "timestamp",
                "user",
                "source_ip",
                "action",
                "status",
                "bytes_transferred",
                "anomaly_score",
                "threat_status"
            ]
        ].head(20).to_string(index=False)
    )

    print("\n======================================")

    anomalies = result[result["threat_status"] == "Anomaly"]

    print(f"\nTotal events: {len(result)}")
    print(f"Anomalies detected: {len(anomalies)}")