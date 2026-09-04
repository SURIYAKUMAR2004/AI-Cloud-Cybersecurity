import sys
from pathlib import Path

import pandas as pd
import streamlit as st


# ==================================================
# PROJECT PATH
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ==================================================
# SECURITY ENGINES
# ==================================================

from ai.anomaly_detector import detect_anomalies
from security.threat_detector import apply_behavior_analysis
from security.contextual_risk_engine import apply_contextual_risk
from security.explanation_engine import apply_explanation_engine
from security.response_engine import apply_response_engine
from security.security_orchestrator import analyze_security_events


# ==================================================
# STREAMLIT CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="AI Cloud Cybersecurity",
    page_icon="🔐",
    layout="wide"
)


# ==================================================
# DATA FILES
# ==================================================

AWS_FILE = PROJECT_ROOT / "data" / "aws_cloudtrail_events.csv"
LIVE_FILE = PROJECT_ROOT / "data" / "live_events.csv"
SAMPLE_FILE = PROJECT_ROOT / "data" / "sample_logs.csv"


# ==================================================
# COMPLETE SECURITY PIPELINE
# ==================================================

@st.cache_data(ttl=5)
def load_security_data(data_mode):

    # --------------------------------------------------
    # SELECT DATA SOURCE
    # --------------------------------------------------

    if data_mode == "AWS CloudTrail":

        if AWS_FILE.exists() and AWS_FILE.stat().st_size > 0:
            data_source = str(AWS_FILE)
            source_name = "AWS CloudTrail"
        else:
            data_source = str(SAMPLE_FILE)
            source_name = "Demo / Sample Data"

    elif data_mode == "Live Demo":

        if LIVE_FILE.exists() and LIVE_FILE.stat().st_size > 0:
            data_source = str(LIVE_FILE)
            source_name = "Live Demo Events"
        else:
            data_source = str(SAMPLE_FILE)
            source_name = "Demo / Sample Data"

    else:

        data_source = str(SAMPLE_FILE)
        source_name = "Historical Sample Data"

    # --------------------------------------------------
    # LOAD DATA
    # --------------------------------------------------

    raw_df = pd.read_csv(data_source)

    if raw_df.empty:
        return pd.DataFrame(), pd.DataFrame(), source_name

    # --------------------------------------------------
    # 1. AI ANOMALY DETECTION
    # --------------------------------------------------

    df = detect_anomalies(raw_df)

    # --------------------------------------------------
    # 2. BEHAVIORAL INTELLIGENCE
    # --------------------------------------------------

    baseline, results = apply_behavior_analysis(df)

    # --------------------------------------------------
    # 3. CONTEXTUAL RISK
    # --------------------------------------------------

    results = apply_contextual_risk(results)

    # --------------------------------------------------
    # 4. EXPLAINABLE AI
    # --------------------------------------------------

    results = apply_explanation_engine(results)

    # --------------------------------------------------
    # 5. ADAPTIVE RESPONSE
    # --------------------------------------------------

    results = apply_response_engine(results)

    # --------------------------------------------------
    # 6. SECURITY ORCHESTRATOR
    # --------------------------------------------------

    # Run the complete correlation + risk + response pipeline
    # on the same raw events used by the dashboard.
    try:
        incidents = analyze_security_events(results.copy())
    except Exception as exc:
        print(f"Orchestrator warning: {exc}")
        incidents = pd.DataFrame()

    return baseline, results, source_name, incidents


# ==================================================
# DATA SOURCE SELECTOR
# ==================================================

st.sidebar.title("⚙️ Security Controls")

data_mode = st.sidebar.selectbox(
    "Security Data Source",
    [
        "AWS CloudTrail",
        "Live Demo",
        "Historical Sample"
    ],
    index=0
)


# ==================================================
# REFRESH CONTROL
# ==================================================

if st.sidebar.button("🔄 Refresh Security Data"):

    st.cache_data.clear()

    st.rerun()


# ==================================================
# LOAD SECURITY DATA
# ==================================================

baseline, results, source_name, incidents = load_security_data(data_mode)


# ==================================================
# SAFETY CHECK
# ==================================================

if results.empty:

    st.error(
        "No security events are currently available."
    )

    st.stop()


# ==================================================
# RESPONSE LABELS
# ==================================================

RESPONSE_LABELS = {

    "MONITOR":
        "👀 Monitor",

    "ALERT_SECURITY_TEAM":
        "📢 Alert Security Team",

    "ALERT_SECURITY_TEAM_AND_MONITOR":
        "👁️ Alert Security Team & Monitor",

    "ESCALATE_SECURITY_INCIDENT":
        "🚨 Escalate Security Incident",

    "RESTRICT_ACCESS_AND_ALERT":
        "🔒 Restrict Access & Alert",

    "BLOCK_AND_ISOLATE_PRIVILEGED_OPERATION":
        "🛡️ Block & Isolate Privileged Operation",

    "BLOCK_AND_ISOLATE_DATA_EXFILTRATION_RISK":
        "🛡️ Block & Isolate Data Exfiltration Risk",

    "BLOCK_AND_ISOLATE":
        "🛡️ Block & Isolate"
}


# ==================================================
# HEADER
# ==================================================

st.title(
    "🔐 AI Cloud Cybersecurity Dashboard"
)

st.markdown(
    """
    ### AI-powered cloud threat detection and adaptive security response

    The system combines **AI anomaly detection, behavioral intelligence,
    contextual risk analysis, explainable AI and adaptive response**
    to identify suspicious cloud activity.
    """
)

st.divider()


# ==================================================
# DATA SOURCE STATUS
# ==================================================

st.subheader("☁️ Security Data Source")

if source_name == "AWS CloudTrail":

    st.success(
        "🟢 Connected to AWS CloudTrail security events"
    )

elif source_name == "Live Demo Events":

    st.info(
        "🔵 Running using local live-demo security events"
    )

else:

    st.warning(
        "🟡 Running using historical sample data"
    )

st.caption(
    f"Current source: **{source_name}**"
)


# ==================================================
# CORRELATED SECURITY INCIDENTS
# ==================================================

st.divider()

st.subheader("🔗 Correlated Security Incidents")

if incidents.empty:
    st.info(
        "No correlated multi-event security incidents detected."
    )
else:
    st.warning(
        f"🚨 {len(incidents)} correlated security incident(s) detected"
    )

    incident_columns = [
        "incident_id",
        "user",
        "source_ip",
        "severity",
        "assessment",
        "attack_pattern",
        "events_correlated",
        "contextual_risk",
        "chain_score",
        "final_risk_score",
        "response",
        "priority",
        "execution_mode"
    ]

    available_columns = []
    seen_columns = set()

    for column in incident_columns:
        if column in incidents.columns and column not in seen_columns:
            available_columns.append(column)
            seen_columns.add(column)

    # Remove any duplicate columns produced by the orchestrator.
    incident_display = incidents.loc[:, ~incidents.columns.duplicated()].copy()

    available_columns = [
        column
        for column in available_columns
        if column in incident_display.columns
    ]

    st.dataframe(
        incident_display[available_columns],
        use_container_width=True,
        hide_index=True
    )

    # Incident investigation
    st.markdown("### 🔍 Incident Investigation")

    incident_index = st.selectbox(
        "Select an incident",
        range(len(incidents)),
        format_func=lambda i: (
            f"{incidents.iloc[i].get('incident_id', 'Unknown')} — "
            f"{incidents.iloc[i].get('severity', 'Unknown')} — "
            f"Risk {incidents.iloc[i].get('final_risk_score', 'N/A')}"
        )
    )

    # Remove duplicate column names before reading the selected incident.
    incident_data = incidents.loc[:, ~incidents.columns.duplicated()].copy()
    selected_incident = incident_data.iloc[incident_index]

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Final Risk",
            selected_incident.get("final_risk_score", "N/A")
        )

    with col2:
        st.metric(
            "Chain Score",
            selected_incident.get("chain_score", "N/A")
        )

    with col3:
        st.metric(
            "Events Correlated",
            selected_incident.get("events_correlated", "N/A")
        )

    with col4:
        st.metric(
            "Priority",
            selected_incident.get("priority", "N/A")
        )

    st.markdown(
        f"**Attack Pattern:** "
        f"{selected_incident.get('attack_pattern', 'N/A')}"
    )

    st.markdown(
        f"**Assessment:** "
        f"{selected_incident.get('assessment', 'N/A')}"
    )

    response_value = selected_incident.get(
        "response",
        selected_incident.get("response", "N/A")
    )

    st.markdown(
        f"**Recommended Response:** {response_value}"
    )
    st.markdown(
        f"**Execution Mode:** "
        f"{selected_incident.get('execution_mode', 'N/A')}"
    )


# ==================================================
# SYSTEM WORKFLOW
# ==================================================

st.subheader(
    "⚙️ Security Intelligence Pipeline"
)

workflow = st.columns(5)

steps = [

    (
        "🤖",
        "AI Detection",
        "Identify unusual activity"
    ),

    (
        "🧠",
        "Behavior Analysis",
        "Compare with user baseline"
    ),

    (
        "⚠️",
        "Contextual Risk",
        "Combine security signals"
    ),

    (
        "🔎",
        "Explainable AI",
        "Explain why an event is risky"
    ),

    (
        "🛡️",
        "Adaptive Response",
        "Recommend security action"
    )

]

for column, (icon, title, description) in zip(
    workflow,
    steps
):

    with column:

        st.markdown(
            f"### {icon} {title}"
        )

        st.caption(description)


st.divider()


# ==================================================
# TOP SECURITY METRICS
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

medium = len(
    results[
        results["contextual_risk_level"] == "MEDIUM"
    ]
)


col1, col2, col3, col4, col5 = st.columns(5)


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
        "Critical",
        critical
    )


with col4:

    st.metric(
        "High Risk",
        high
    )


with col5:

    st.metric(
        "Medium Risk",
        medium
    )


# ==================================================
# SECURITY SITUATION
# ==================================================

st.subheader(
    "🚨 Current Security Situation"
)


correlated_incidents = len(incidents) if incidents is not None else 0

incident_critical = 0
incident_high = 0

if correlated_incidents > 0:
    incident_critical = (
        incidents["severity"]
        .astype(str)
        .str.upper()
        .eq("CRITICAL")
        .sum()
        if "severity" in incidents.columns
        else 0
    )

    incident_high = (
        incidents["severity"]
        .astype(str)
        .str.upper()
        .eq("HIGH")
        .sum()
        if "severity" in incidents.columns
        else 0
    )

if critical > 0 or incident_critical > 0:

    st.error(
        f"🚨 {max(critical, incident_critical)} CRITICAL "
        "security threat(s) detected. "
        "Immediate investigation is recommended."
    )

elif high > 0 or incident_high > 0 or correlated_incidents > 0:

    st.warning(
        f"⚠️ {max(high, incident_high)} HIGH-risk threat(s) "
        f"and {correlated_incidents} correlated incident(s) detected. "
        "Security investigation is recommended."
    )

else:

    st.success(
        "✅ No high-severity threats or correlated security "
        "incidents detected."
    )


# ==================================================
# RISK DISTRIBUTION
# ==================================================

st.subheader(
    "📊 Contextual Risk Distribution"
)

risk_counts = (

    results["contextual_risk_level"]

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
# BEHAVIORAL INTELLIGENCE
# ==================================================

st.subheader(
    "🧠 Behavioral Intelligence"
)

behavior_counts = (
    results["behavior_status"]
    .value_counts()
)

st.bar_chart(
    behavior_counts
)


# ==================================================
# ADAPTIVE RESPONSE
# ==================================================

st.subheader(
    "🛡️ Adaptive Response Distribution"
)

response_counts = (

    results["recommended_response"]

    .value_counts()

    .rename(
        index=RESPONSE_LABELS
    )

)

st.dataframe(

    response_counts

    .rename("Events")

    .reset_index()

    .rename(
        columns={
            "recommended_response":
                "Recommended Response"
        }
    ),

    width="stretch",

    hide_index=True
)


# ==================================================
# SECURITY EVENTS
# ==================================================

st.subheader(
    "🚨 Security Events"
)

sorted_events = (

    results

    .sort_values(
        "contextual_risk_score",
        ascending=False
    )
)


display_columns = [

    "timestamp",
    "user",
    "source_ip",
    "action",
    "threat_status",
    "behavior_deviation_score",
    "contextual_risk",
    "contextual_risk_level",
    "recommended_response"

]


# --------------------------------------------------
# SAFELY DISPLAY AVAILABLE COLUMNS
# --------------------------------------------------

available_columns = [

    column

    for column in display_columns

    if column in sorted_events.columns

]


display_df = (

    sorted_events[available_columns]

    .rename(
        columns={

            "timestamp":
                "Timestamp",

            "user":
                "User",

            "source_ip":
                "Source IP",

            "action":
                "Cloud Action",

            "threat_status":
                "AI Threat",

            "behavior_deviation_score":
                "Behavior Score",

            "contextual_risk_score":
                "Risk Score",

            "contextual_risk_level":
                "Risk Level",

            "recommended_response":
                "Recommended Response"

        }
    )
)


st.dataframe(

    display_df,

    width="stretch",

    hide_index=True
)


# ==================================================
# EVENT INVESTIGATION
# ==================================================

st.subheader(
    "🔎 Security Event Investigation"
)

st.caption(
    "Select a security event to understand why the system "
    "classified it as risky and what response it recommends."
)


event_indices = (
    sorted_events.index.tolist()
)


selected_index = st.selectbox(

    "Select event",

    event_indices,

    format_func=lambda index: (

        f"{sorted_events.loc[index, 'user']} | "

        f"{sorted_events.loc[index, 'action']} | "

        f"Risk Score: "

        f"{sorted_events.loc[index, 'contextual_risk_score']} | "

        f"{sorted_events.loc[index, 'contextual_risk_level']}"

    )

)


# ==================================================
# INVESTIGATION RESULT
# ==================================================

if selected_index is not None:

    selected_event = (
        sorted_events.loc[selected_index]
    )

    st.divider()

    st.subheader(
        "🧾 Investigation Result"
    )


    # ------------------------------------------------
    # RISK METRICS
    # ------------------------------------------------

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
    # SECURITY EXPLANATION
    # ------------------------------------------------

    st.markdown(
        "### 🔍 Why was this event detected?"
    )

    st.caption(
        "The AI combines multiple security signals "
        "to explain why this event was classified as risky."
    )


    reason_details = (

        selected_event.get(
            "security_reason_details",
            []
        )

    )


    if isinstance(reason_details, list) and reason_details:

        for detail in reason_details:

            category = detail.get(
                "category",
                "Security Signal"
            )

            reason = detail.get(
                "reason",
                ""
            )

            st.markdown(
                f"**🔹 {category}**"
            )

            st.info(reason)

    else:

        st.info(

            selected_event.get(
                "security_explanation",
                "No detailed explanation available."
            )

        )


    # ------------------------------------------------
    # RECOMMENDED RESPONSE
    # ------------------------------------------------

    st.markdown(
        "### 🛡️ Recommended Security Response"
    )


    response_code = (

        selected_event[
            "recommended_response"
        ]

    )


    response_label = RESPONSE_LABELS.get(

        response_code,

        response_code

    )


    st.warning(
        response_label
    )


    st.caption(
        f"Security response policy: `{response_code}`"
    )


    # ------------------------------------------------
    # RESPONSE EXPLANATION
    # ------------------------------------------------

    st.markdown(
        "### 🔍 Why was this response recommended?"
    )


    response_reason = (

        selected_event.get(

            "response_reason",

            "No additional response explanation available."

        )

    )


    st.info(
        response_reason
    )


    # ------------------------------------------------
    # EVENT DETAILS
    # ------------------------------------------------

    st.markdown(
        "### 📌 Event Details"
    )


    event_detail_fields = [

        "timestamp",
        "user",
        "source_ip",
        "action",
        "status",
        "bytes_transferred",
        "threat_status",
        "behavior_status"

    ]


    event_detail_values = [

        selected_event.get(
            field,
            "N/A"
        )

        for field in event_detail_fields

    ]


    event_details = pd.DataFrame({

        "Field": [

            "Timestamp",
            "User",
            "Source IP",
            "Cloud Action",
            "Status",
            "Bytes Transferred",
            "AI Threat Status",
            "Behavior Status"

        ],

        "Value": event_detail_values

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

    "AWS CloudTrail + "

    "AI Anomaly Detection + "

    "Behavioral Intelligence + "

    "Contextual Risk + "

    "Explainable AI + "

    "Adaptive Response"

)
