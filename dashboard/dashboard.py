import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# --------------------------------------------------
# Project path
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# --------------------------------------------------
# Security engines
# --------------------------------------------------

from ai.anomaly_detector import detect_anomalies

from security.threat_detector import (
    apply_behavior_analysis
)

from security.contextual_risk_engine import (
    apply_contextual_risk
)

from security.explanation_engine import (
    apply_explanation_engine
)

from security.response_engine import (
    apply_response_engine
)


# --------------------------------------------------
# Streamlit configuration
# --------------------------------------------------

st.set_page_config(
    page_title="AI Cloud Cybersecurity",
    page_icon="🔐",
    layout="wide"
)


# --------------------------------------------------
# Load complete security pipeline
# --------------------------------------------------

@st.cache_data
def load_security_data():

    # 1. AI anomaly detection
    df = detect_anomalies(
        str(
            PROJECT_ROOT
            / "data"
            / "sample_logs.csv"
        )
    )

    # 2. Behavioral analysis
    baseline, results = apply_behavior_analysis(df)

    # 3. Contextual risk
    results = apply_contextual_risk(results)

    # 4. Explainable AI
    results = apply_explanation_engine(results)

    # 5. Adaptive response
    results = apply_response_engine(results)

    return baseline, results


baseline, results = load_security_data()


# ==================================================
# HEADER
# ==================================================

st.title("🔐 AI Cloud Cybersecurity Dashboard")

st.markdown(
    """
    **AI-powered cloud threat detection and adaptive
    security response system**
    """
)

st.divider()


# ==================================================
# TOP METRICS
# ==================================================

total_events = len(results)

anomalies = len(
    results[
        results["threat_status"] == "Anomaly"
    ]
)

critical = len(
    results[
        results["contextual_risk_level"] == "CRITICAL"
    ]
)

high = len(
    results[
        results["contextual_risk_level"] == "HIGH"
    ]
)


col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Events Evaluated",
        total_events
    )

with col2:
    st.metric(
        "AI Anomalies",
        anomalies
    )

with col3:
    st.metric(
        "High Risk",
        high
    )

with col4:
    st.metric(
        "Critical Threats",
        critical
    )


# ==================================================
# RISK DISTRIBUTION
# ==================================================

st.subheader("📊 Contextual Risk Distribution")

risk_counts = (
    results[
        "contextual_risk_level"
    ]
    .value_counts()
    .reindex(
        [
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ],
        fill_value=0
    )
)

st.bar_chart(risk_counts)


# ==================================================
# BEHAVIOR DISTRIBUTION
# ==================================================

st.subheader("🧠 Behavioral Intelligence")

behavior_counts = (
    results[
        "behavior_status"
    ]
    .value_counts()
)

st.bar_chart(behavior_counts)


# ==================================================
# RESPONSE DISTRIBUTION
# ==================================================

st.subheader("🛡️ Adaptive Response Distribution")

response_counts = (
    results[
        "recommended_response"
    ]
    .value_counts()
)

st.bar_chart(response_counts)


# ==================================================
# SECURITY EVENTS
# ==================================================

st.subheader("🚨 Security Events")

display_columns = [
    "timestamp",
    "user",
    "source_ip",
    "action",
    "threat_status",
    "behavior_deviation_score",
    "contextual_risk_score",
    "contextual_risk_level",
    "recommended_response"
]

sorted_events = results.sort_values(
    "contextual_risk_score",
    ascending=False
)

st.dataframe(
    sorted_events[
        display_columns
    ],
    width="stretch",
    hide_index=True
)


# ==================================================
# EVENT INVESTIGATION
# ==================================================

st.subheader("🔎 Security Event Investigation")

event_indices = sorted_events.index.tolist()

selected_index = st.selectbox(
    "Select an event to investigate",
    event_indices,
    format_func=lambda index: (
        f"{sorted_events.loc[index, 'user']} | "
        f"{sorted_events.loc[index, 'action']} | "
        f"Risk "
        f"{sorted_events.loc[index, 'contextual_risk_score']}"
    )
)


# ==================================================
# SELECTED EVENT DETAILS
# ==================================================

if selected_index is not None:

    selected_event = sorted_events.loc[selected_index]

    st.markdown("---")

    st.subheader("🧾 Investigation Result")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Contextual Risk Score",
            selected_event[
                "contextual_risk_score"
            ]
        )

    with col2:
        st.metric(
            "Risk Level",
            selected_event[
                "contextual_risk_level"
            ]
        )

    with col3:
        st.metric(
            "Behavior Score",
            selected_event[
                "behavior_deviation_score"
            ]
        )


    # ------------------------------------------------
    # Security Explanation
    # ------------------------------------------------

    st.markdown(
        "### 🔍 Security Explanation"
    )

    st.info(
        selected_event[
            "security_explanation"
        ]
    )


    # ------------------------------------------------
    # Recommended Response
    # ------------------------------------------------

    st.markdown(
        "### 🛡️ Recommended Response"
    )

    st.warning(
        selected_event[
            "recommended_response"
        ]
    )


    # ------------------------------------------------
    # Event Details
    # ------------------------------------------------

    st.markdown(
        "### 📌 Event Details"
    )

    event_details = pd.DataFrame({

        "Field": [
            "Timestamp",
            "User",
            "Source IP",
            "Action",
            "Status",
            "Bytes Transferred",
            "Threat Status",
            "Behavior Status"
        ],

        "Value": [
            selected_event["timestamp"],
            selected_event["user"],
            selected_event["source_ip"],
            selected_event["action"],
            selected_event["status"],
            selected_event["bytes_transferred"],
            selected_event["threat_status"],
            selected_event["behavior_status"]
        ]

    })

    st.dataframe(
        event_details,
        width="stretch",
        hide_index=True
    )


# ==================================================
# FOOTER
# ==================================================

st.divider()

st.caption(
    "AI Cloud Cybersecurity | "
    "AI Anomaly Detection + Behavioral Intelligence + "
    "Contextual Risk + Explainable AI + Adaptive Response"
)
