
import html
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh
import textwrap

try:
    import plotly.graph_objects as go
    PLOTLY_OK = True
except Exception:
    PLOTLY_OK = False

from ai.anomaly_detector import detect_anomalies
from security.threat_detector import apply_behavior_analysis
from security.contextual_risk_engine import apply_contextual_risk
from security.explanation_engine import apply_explanation_engine
from security.response_engine import apply_response_engine
from security.attack_correlator import correlate_attack_chain

def soc_markdown(content, **kwargs):
    kwargs.setdefault("unsafe_allow_html", True)
    # Remove indentation from every HTML line. Without this, Streamlit/Markdown
    # can interpret indented <div> lines as a code block and display raw HTML.
    normalized = "\n".join(line.strip() for line in textwrap.dedent(content).splitlines()).strip()
    return st.markdown(normalized, **kwargs)



# ============================================================
# PAGE
# ============================================================
st.set_page_config(
    page_title="AI Cloud Cybersecurity SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
# Automatically refresh the SOC dashboard every 5 seconds
st_autorefresh(interval=5000, key="soc_live_refresh")
BASE_DIR = Path(__file__).resolve().parent
AWS_FILE = BASE_DIR / "data" / "aws_cloudtrail_events.csv"
LIVE_FILE = BASE_DIR / "data" / "live_events.csv"
SAMPLE_FILE = BASE_DIR / "data" / "sample_logs.csv"


# ============================================================
# SOC DESIGN SYSTEM
# ============================================================
soc_markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg: #050a12;
    --bg2: #08111d;
    --panel: #0a1422;
    --panel2: #0d1929;
    --border: #183047;
    --border2: #23435d;
    --text: #e7f2fb;
    --muted: #71869b;
    --cyan: #27d9ff;
    --cyan2: #0aa6d8;
    --green: #36dfaa;
    --red: #ff5364;
    --orange: #ffb454;
    --yellow: #f1d56a;
    --purple: #9c86ff;
}

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 75% 0%, rgba(16, 93, 132, .13), transparent 32%),
        radial-gradient(circle at 20% 100%, rgba(14, 69, 100, .08), transparent 30%),
        var(--bg);
    color: var(--text);
}

.block-container {
    max-width: 1500px;
    padding-top: 1.15rem;
    padding-bottom: 2rem;
}

[data-testid="stSidebar"] {
    background: #06101b;
    border-right: 1px solid #13283b;
}

[data-testid="stSidebar"] > div:first-child {
    padding-top: 1.25rem;
}

[data-testid="stSidebar"] .stMarkdown {
    color: var(--text);
}

.sidebar-brand {
    padding: 0 8px 18px 8px;
    border-bottom: 1px solid #13283b;
    margin-bottom: 16px;
}

.sidebar-logo {
    width: 42px;
    height: 42px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1px solid #1b7798;
    border-radius: 11px;
    background: rgba(39,217,255,.08);
    color: var(--cyan);
    font-size: 22px;
    box-shadow: 0 0 22px rgba(39,217,255,.10);
}

.sidebar-title {
    font-size: 14px;
    font-weight: 800;
    letter-spacing: 1.7px;
    margin-top: 12px;
}

.sidebar-sub {
    color: var(--muted);
    font-size: 10px;
    letter-spacing: 1.4px;
    margin-top: 4px;
}

.nav-label {
    color: #526a7f;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 1.8px;
    margin: 20px 8px 8px;
}

.nav-item {
    padding: 9px 10px;
    border-radius: 7px;
    color: #8ea3b6;
    font-size: 12px;
    margin: 2px 0;
}

.nav-item.active {
    background: linear-gradient(90deg, rgba(39,217,255,.13), rgba(39,217,255,.025));
    color: #dff9ff;
    border-left: 2px solid var(--cyan);
}

.status-box {
    margin: 7px 0;
    padding: 10px 11px;
    border: 1px solid #132b40;
    border-radius: 7px;
    background: rgba(7, 19, 31, .72);
}

.status-line {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 10px;
}

.status-name {
    color: #9db0c1;
}

.status-online {
    color: var(--green);
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px;
}

.dot {
    display: inline-block;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--green);
    margin-right: 5px;
    box-shadow: 0 0 8px rgba(54,223,170,.75);
}

.sidebar-source {
    margin-top: 18px;
    padding: 10px;
    border: 1px solid #163149;
    border-radius: 7px;
    background: #081521;
    font-size: 9px;
    color: #698095;
}

.sidebar-source b {
    color: #bcd1e0;
    font-size: 10px;
}

.soc-header {
    border-bottom: 1px solid #173047;
    padding: 2px 0 17px 0;
    margin-bottom: 15px;
}

.header-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 18px;
}

.header-kicker {
    color: var(--cyan);
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px;
    letter-spacing: 2.4px;
    margin-bottom: 5px;
}

.soc-title {
    font-size: 25px;
    font-weight: 800;
    letter-spacing: 1.7px;
    line-height: 1.1;
}

.soc-subtitle {
    color: #71879a;
    font-size: 11px;
    margin-top: 7px;
}

.header-right {
    text-align: right;
    min-width: 290px;
}

.system-live {
    color: var(--green);
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px;
    letter-spacing: 1px;
}

.sim-badge {
    display: inline-block;
    margin-top: 8px;
    padding: 5px 9px;
    border: 1px solid #6d5127;
    border-radius: 5px;
    color: var(--orange);
    background: rgba(255,180,84,.07);
    font-family: 'JetBrains Mono', monospace;
    font-size: 8px;
    letter-spacing: 1px;
}

.section-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin: 20px 0 9px;
}

.section-title {
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}

.section-note {
    color: #52697d;
    font-family: 'JetBrains Mono', monospace;
    font-size: 8px;
    letter-spacing: .7px;
}

.kpi {
    background: linear-gradient(145deg, #0b1725, #08121e);
    border: 1px solid #173148;
    border-radius: 8px;
    min-height: 105px;
    padding: 15px 16px 12px;
    position: relative;
    overflow: hidden;
}

.kpi:before {
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--cyan);
    opacity: .75;
}

.kpi-label {
    color: #6f8497;
    font-size: 8px;
    font-weight: 700;
    letter-spacing: 1.4px;
    text-transform: uppercase;
}

.kpi-value {
    margin-top: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 26px;
    font-weight: 600;
    letter-spacing: -1px;
}

.kpi-meta {
    margin-top: 5px;
    color: #526a7d;
    font-size: 9px;
}

.kpi-red:before { background: var(--red); }
.kpi-orange:before { background: var(--orange); }
.kpi-green:before { background: var(--green); }
.kpi-purple:before { background: var(--purple); }

.panel {
    background: linear-gradient(145deg, rgba(11,23,37,.97), rgba(7,16,27,.97));
    border: 1px solid #173148;
    border-radius: 9px;
    padding: 17px;
    min-height: 100%;
}

.panel-title {
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1.25px;
    text-transform: uppercase;
}

.panel-sub {
    color: #5f768a;
    font-size: 9px;
    margin-top: 4px;
}

.posture-wrap {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 15px 0 7px;
}

.ring {
    width: 145px;
    height: 145px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: conic-gradient(var(--red) var(--score), #132a3e 0);
    box-shadow: 0 0 35px rgba(255,83,100,.08);
    position: relative;
    flex: 0 0 auto;
}

.ring:after {
    content: "";
    position: absolute;
    width: 113px;
    height: 113px;
    border-radius: 50%;
    background: #08121e;
    border: 1px solid #173148;
}

.ring-inner {
    position: relative;
    z-index: 1;
    text-align: center;
}

.ring-score {
    font-family: 'JetBrains Mono', monospace;
    font-size: 30px;
    font-weight: 600;
}

.ring-label {
    color: #5f768a;
    font-size: 8px;
    letter-spacing: 1px;
    margin-top: 2px;
}

.posture-level {
    color: var(--red);
    font-size: 18px;
    font-weight: 800;
    letter-spacing: 1.3px;
}

.posture-copy {
    color: #8397a8;
    font-size: 10px;
    line-height: 1.55;
    margin-top: 7px;
}

.signal-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 7px;
    margin-top: 12px;
}

.signal-pill {
    border: 1px solid #183249;
    border-radius: 6px;
    padding: 7px 8px;
    background: #091522;
}

.signal-name {
    color: #687e91;
    font-size: 8px;
    text-transform: uppercase;
    letter-spacing: .8px;
}

.signal-val {
    font-family: 'JetBrains Mono', monospace;
    color: #cfe2ef;
    font-size: 10px;
    margin-top: 3px;
}

.intel-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #132a3d;
    padding: 9px 0;
    gap: 10px;
}

.intel-row:last-child { border-bottom: 0; }

.intel-left {
    display: flex;
    align-items: center;
    gap: 9px;
}

.intel-icon {
    width: 25px;
    height: 25px;
    border: 1px solid #17445a;
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--cyan);
    font-size: 10px;
    background: rgba(39,217,255,.04);
}

.intel-name {
    font-size: 9px;
    font-weight: 600;
}

.intel-desc {
    color: #536b7e;
    font-size: 8px;
    margin-top: 2px;
}

.online {
    color: var(--green);
    font-family: 'JetBrains Mono', monospace;
    font-size: 8px;
}

.pipeline {
    display: flex;
    align-items: stretch;
    gap: 7px;
    margin-top: 13px;
}

.pipe {
    flex: 1;
    min-width: 0;
    border: 1px solid #173148;
    background: #081521;
    border-radius: 7px;
    padding: 10px 8px;
    text-align: center;
    position: relative;
}

.pipe:not(:last-child):after {
    content: "›";
    position: absolute;
    right: -9px;
    top: 18px;
    color: #2c6b84;
    z-index: 3;
    font-size: 14px;
}

.pipe-icon {
    color: var(--cyan);
    font-size: 16px;
    margin-bottom: 5px;
}

.pipe-name {
    font-size: 8px;
    font-weight: 700;
    letter-spacing: .5px;
}

.pipe-status {
    color: var(--green);
    font-family: 'JetBrains Mono', monospace;
    font-size: 7px;
    margin-top: 4px;
}

.chart-panel {
    background: linear-gradient(145deg, rgba(11,23,37,.97), rgba(7,16,27,.97));
    border: 1px solid #173148;
    border-radius: 9px;
    padding: 15px;
}

.incident {
    border: 1px solid #243447;
    border-left: 3px solid var(--orange);
    border-radius: 7px;
    padding: 12px 13px;
    background: #091521;
    margin-bottom: 8px;
}

.incident.critical { border-left-color: var(--red); }
.incident.high { border-left-color: var(--orange); }
.incident.medium { border-left-color: var(--yellow); }
.incident.low { border-left-color: var(--green); }

.incident-top {
    display: flex;
    justify-content: space-between;
    gap: 10px;
}

.badge {
    display: inline-block;
    border-radius: 4px;
    padding: 3px 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 7px;
    letter-spacing: .8px;
    border: 1px solid;
}

.badge-critical { color: var(--red); border-color: #7e3440; background: rgba(255,83,100,.06); }
.badge-high { color: var(--orange); border-color: #765526; background: rgba(255,180,84,.06); }
.badge-medium { color: var(--yellow); border-color: #665b2d; background: rgba(241,213,106,.05); }
.badge-low { color: var(--green); border-color: #255e4d; background: rgba(54,223,170,.05); }

.incident-id {
    color: #566d80;
    font-family: 'JetBrains Mono', monospace;
    font-size: 7px;
}

.incident-title {
    margin-top: 8px;
    font-size: 10px;
    font-weight: 700;
}

.incident-meta {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin-top: 8px;
    color: #6b8194;
    font-size: 8px;
}

.incident-meta b {
    color: #a8bdcc;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 500;
}

.chain {
    border: 1px solid #18334a;
    border-radius: 7px;
    padding: 12px;
    background: #091521;
    min-height: 150px;
    margin-bottom: 9px;
}

.chain-title {
    font-size: 10px;
    font-weight: 700;
    margin: 8px 0 5px;
}

.chain-score {
    font-family: 'JetBrains Mono', monospace;
    color: var(--red);
    font-size: 18px;
    font-weight: 600;
}

.chain-flow {
    color: #7c91a2;
    font-size: 8px;
    line-height: 1.55;
}

.chain-flow span {
    color: var(--cyan);
}

.ai-box {
    border: 1px solid #21445b;
    border-radius: 7px;
    background: linear-gradient(90deg, rgba(39,217,255,.035), rgba(39,217,255,.01));
    padding: 12px;
    margin-top: 8px;
}

.ai-box-title {
    color: var(--cyan);
    font-size: 8px;
    font-weight: 800;
    letter-spacing: 1.2px;
    text-transform: uppercase;
}

.ai-box-text {
    color: #91a6b6;
    font-size: 9px;
    line-height: 1.55;
    margin-top: 6px;
}

.table-wrap {
    border: 1px solid #173148;
    border-radius: 8px;
    overflow: hidden;
    background: #08131f;
}

.metric-mini {
    border: 1px solid #173148;
    border-radius: 7px;
    background: #091521;
    padding: 9px 11px;
}

.metric-mini-label {
    color: #5d7488;
    font-size: 7px;
    letter-spacing: 1px;
}

.metric-mini-value {
    color: #d9e9f4;
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    margin-top: 3px;
}

.footer {
    border-top: 1px solid #142a3d;
    margin-top: 22px;
    padding-top: 11px;
    color: #465d70;
    font-size: 8px;
    display: flex;
    justify-content: space-between;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #173148;
    border-radius: 8px;
    overflow: hidden;
}

button[kind="secondary"] {
    border: 1px solid #1d4960 !important;
    color: #a9d8e8 !important;
    background: #091722 !important;
}

@media (max-width: 900px) {
    .pipeline { flex-wrap: wrap; }
    .pipe { min-width: 29%; }
    .header-right { min-width: auto; }
}
</style>
""",
    unsafe_allow_html=True,
)


# Streamlit treats 4-space-indented Markdown as a code block.
# All custom SOC HTML is therefore dedented before rendering.
# ============================================================
# HELPERS
# ============================================================
@st.cache_data(ttl=5)
def load_security_data():

    frames = []

    # Historical AWS CloudTrail events
    if AWS_FILE.exists():
        try:
            aws_df = pd.read_csv(AWS_FILE)
            if not aws_df.empty:
                frames.append(aws_df)
        except Exception:
            pass

    # Real-time events generated by the FastAPI live ingestion service
    if LIVE_FILE.exists():
        try:
            live_df = pd.read_csv(LIVE_FILE)

            # Keep only successfully processed LIVE events.
            if "event_id" in live_df.columns:
                live_df = live_df[
                    live_df["event_id"]
                    .astype(str)
                    .str.startswith("LIVE-", na=False)
                ].copy()

            if not live_df.empty:
                frames.append(live_df)

        except Exception:
            pass

    # Combine historical + live events
    if frames:
        combined = pd.concat(frames, ignore_index=True, sort=False)
        return combined, "AWS CloudTrail + Live Security Events"

    # Fallback
    if SAMPLE_FILE.exists():
        try:
            return pd.read_csv(SAMPLE_FILE), "Sample Security Events"
        except Exception:
            pass

    return pd.DataFrame(), "No Data"

def ensure_dataframe(result, fallback):
    if isinstance(result, pd.DataFrame):
        return result.copy()

    if isinstance(result, tuple):
        for item in reversed(result):
            if isinstance(item, pd.DataFrame):
                return item.copy()

    if isinstance(result, list):
        if not result:
            return fallback.copy()
        try:
            return pd.DataFrame(result)
        except Exception:
            return fallback.copy()

    return fallback.copy()


def first_existing(df, names, default=None):
    for name in names:
        if name in df.columns:
            return name
    return default


def number_value(row, names, default=0):
    for name in names:
        if name in row.index:
            try:
                return float(row[name])
            except Exception:
                pass
    return float(default)


def text_value(row, names, default="—"):
    for name in names:
        if name in row.index:
            value = row[name]
            if pd.notna(value) and str(value).strip():
                return str(value)
    return default


def severity_from_score(score):
    score = float(score or 0)
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def score_from_row(row):
    return number_value(
        row,
        [
            "final_risk_score",
            "risk_score",
            "contextual_risk_score",
            "chain_score",
            "risk",
            "score",
        ],
        0,
    )


def status_from_row(row):
    status = text_value(row, ["severity", "threat_level", "risk_level"], "")
    if status:
        return status.upper()
    return severity_from_score(score_from_row(row))


def escape(value):
    return html.escape(str(value))


# ============================================================
# BACKEND PIPELINE
# ============================================================
raw_df, data_source = load_security_data()

if raw_df.empty:
    st.error("No security dataset was found in data/.")
    st.stop()

df = raw_df.copy()

# Run the existing project pipeline without replacing the backend.
try:
    ai_df = ensure_dataframe(detect_anomalies(df.copy()), df)
except Exception:
    ai_df = df.copy()

try:
    ai_df = ensure_dataframe(apply_behavior_analysis(ai_df.copy()), ai_df)
except Exception:
    pass

try:
    ai_df = ensure_dataframe(apply_contextual_risk(ai_df.copy()), ai_df)
except Exception:
    pass

try:
    ai_df = ensure_dataframe(apply_explanation_engine(ai_df.copy()), ai_df)
except Exception:
    pass

try:
    ai_df = ensure_dataframe(apply_response_engine(ai_df.copy()), ai_df)
except Exception:
    pass

try:
    incidents_df = ensure_dataframe(
        correlate_attack_chain(ai_df.copy()),
        pd.DataFrame(),
    )
except Exception:
    incidents_df = pd.DataFrame()

incident_records = (
    incidents_df.to_dict("records")
    if isinstance(incidents_df, pd.DataFrame)
    else []
)

# ============================================================
# METRICS
# ============================================================
total_events = len(df)
ai_events = len(ai_df)

status_col = first_existing(df, ["status", "Status", "event_status"])
failed_events = (
    int((df[status_col].astype(str).str.upper() == "FAILED").sum())
    if status_col else 0
)

critical_incidents = 0
high_incidents = 0

for item in incident_records:
    sev = str(item.get("severity", item.get("threat_level", ""))).upper()
    score = number_value(
        pd.Series(item),
        ["final_risk_score", "chain_score", "risk_score", "risk"],
        0,
    )
    if sev == "CRITICAL" or score >= 80:
        critical_incidents += 1
    elif sev == "HIGH" or score >= 60:
        high_incidents += 1

if incident_records:
    latest_incident = incident_records[-1]

    threat_score = number_value(
        pd.Series(latest_incident),
        ["final_risk_score", "chain_score", "risk_score", "risk"],
        0,
    )
elif not ai_df.empty:
    latest_row = ai_df.iloc[-1]
    threat_score = score_from_row(latest_row)
else:
    threat_score = 0
threat_score = int(round(threat_score))
threat_level = severity_from_score(threat_score)


# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    soc_markdown(
        """
        <div class="sidebar-brand">
            <div class="sidebar-logo">🛡</div>
            <div class="sidebar-title">AI CLOUD SECURITY</div>
            <div class="sidebar-sub">SECURITY OPERATIONS CENTER</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    soc_markdown('<div class="nav-label">COMMAND</div>', unsafe_allow_html=True)
    soc_markdown('<div class="nav-item active">◉  SOC Overview</div>', unsafe_allow_html=True)
    soc_markdown('<div class="nav-item">◈  Threat Detection</div>', unsafe_allow_html=True)
    soc_markdown('<div class="nav-item">⌁  Attack Chains</div>', unsafe_allow_html=True)
    soc_markdown('<div class="nav-item">◎  AI Intelligence</div>', unsafe_allow_html=True)
    soc_markdown('<div class="nav-item">▣  Cloud Events</div>', unsafe_allow_html=True)

    soc_markdown('<div class="nav-label">SYSTEM STATUS</div>', unsafe_allow_html=True)

    for name in [
        "AI Anomaly Detection",
        "Behavior Analysis",
        "Contextual Risk Engine",
        "Attack Correlation",
        "Security Response",
    ]:
        soc_markdown(
            f"""
            <div class="status-box">
                <div class="status-line">
                    <span class="status-name"><span class="dot"></span>{escape(name)}</span>
                    <span class="status-online">ONLINE</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    soc_markdown(
        f"""
        <div class="sidebar-source">
            <b>DATA SOURCE</b><br>
            {escape(data_source)}<br><br>
            <span style="color:#4f697d;">EVENTS</span>
            <span style="float:right;color:#b7cbd9;font-family:'JetBrains Mono';">{total_events}</span><br>
            <span style="color:#4f697d;">AI EVALUATED</span>
            <span style="float:right;color:#b7cbd9;font-family:'JetBrains Mono';">{ai_events}</span><br>
            <span style="color:#4f697d;">CORRELATED CHAINS</span>
            <span style="float:right;color:#b7cbd9;font-family:'JetBrains Mono';">{len(incident_records)}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    soc_markdown("<br>", unsafe_allow_html=True)
    if st.button("↻  REFRESH SECURITY DATA", use_container_width=True):
        st.cache_data.clear()
        st.rerun()


# ============================================================
# HEADER
# ============================================================
now_text = datetime.now().strftime("%d %b %Y  •  %H:%M:%S")

soc_markdown(
    f"""
    <div class="soc-header">
        <div class="header-row">
            <div>
                <div class="header-kicker">SECURITY OPERATIONS COMMAND CENTER</div>
                <div class="soc-title">AI CLOUD CYBERSECURITY</div>
                <div class="soc-subtitle">
                    Intelligent Threat Detection  •  Behavioral Analytics  •  Attack-Chain Correlation  •  Adaptive Response
                </div>
            </div>
            <div class="header-right">
                <div class="system-live">● SYSTEM OPERATIONAL &nbsp;|&nbsp; AI ENGINES ONLINE</div>
                <div style="color:#50687b;font-family:'JetBrains Mono';font-size:8px;margin-top:6px;">
                    {escape(now_text)}
                </div>
                <div class="sim-badge">⚠ SIMULATION MODE — RESPONSE ACTIONS ARE RECOMMENDATIONS</div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# KPI ROW
# ============================================================
k1, k2, k3, k4, k5 = st.columns(5)

cards = [
    (k1, "THREAT SCORE", str(threat_score), threat_level, ""),
    (k2, "CRITICAL INCIDENTS", str(critical_incidents), "CORRELATED", "attack chains"),
    (k3, "HIGH INCIDENTS", str(high_incidents), "CORRELATED", "attack chains"),
    (k4, "CLOUDTRAIL EVENTS", f"{total_events:,}", "INGESTED", "event history"),
    (k5, "ATTACK CHAINS", str(len(incident_records)), "CORRELATED", "multi-event incidents"),
]

for idx, (col, label, value, meta, desc) in enumerate(cards):
    cls = "kpi"
    if idx == 0:
        cls += " kpi-red"
    elif idx in (1, 2):
        cls += " kpi-orange"
    elif idx == 4:
        cls += " kpi-purple"
    else:
        cls += " kpi-green"

    with col:
        soc_markdown(
            f"""
            <div class="{cls}">
                <div class="kpi-label">{escape(label)}</div>
                <div class="kpi-value">{escape(value)}</div>
                <div class="kpi-meta">{escape(meta)} <span style="float:right">{escape(desc)}</span></div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ============================================================
# THREAT POSTURE + AI SECURITY INTELLIGENCE
# ============================================================
soc_markdown(
    """
    <div class="section-head">
        <div class="section-title">Threat Posture & AI Security Intelligence</div>
        <div class="section-note">DECISION LAYER / CONTEXTUAL RISK</div>
    </div>
    """,
    unsafe_allow_html=True,
)

left, right = st.columns([1.05, 1.45])

with left:
    score_css = max(0, min(100, threat_score))
    score_color = "#ff5364" if threat_score >= 80 else "#ffb454" if threat_score >= 60 else "#f1d56a" if threat_score >= 40 else "#36dfaa"

    soc_markdown(
        f"""
        <div class="panel">
            <div class="panel-title">Threat Posture</div>
            <div class="panel-sub">Aggregated security posture from correlated signals</div>
            <div class="posture-wrap">
                <div class="ring" style="--score:{score_css}%;--ring-color:{score_color};background:conic-gradient({score_color} var(--score), #132a3e 0);">
                    <div class="ring-inner">
                        <div class="ring-score">{threat_score}</div>
                        <div class="ring-label">/ 100</div>
                    </div>
                </div>
                <div>
                    <div class="posture-level" style="color:{score_color};">{escape(threat_level)} RISK</div>
                    <div class="posture-copy">
                        Risk posture is derived from anomaly, behavioral, contextual and attack-chain signals.
                        The response layer remains in simulation mode.
                    </div>
                </div>
            </div>
            <div class="signal-grid">
                <div class="signal-pill"><div class="signal-name">Cloud Events</div><div class="signal-val">{total_events}</div></div>
                <div class="signal-pill"><div class="signal-name">Failed Ops</div><div class="signal-val">{failed_events}</div></div>
                <div class="signal-pill"><div class="signal-name">AI Evaluated</div><div class="signal-val">{ai_events}</div></div>
                <div class="signal-pill"><div class="signal-name">Attack Chains</div><div class="signal-val">{len(incident_records)}</div></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with right:
    intelligence = [
        ("◉", "Cloud telemetry ingestion", "AWS CloudTrail event history loaded"),
        ("◇", "ML anomaly detection", "Events evaluated against anomaly patterns"),
        ("◌", "Behavior analysis", "User activity compared with observed behavior"),
        ("⌁", "Contextual risk engine", "Multiple security signals combined"),
        ("⛓", "Attack-chain correlation", "Related events grouped into incidents"),
        ("⚡", "Security response", "Recommended response generated in simulation"),
    ]

    rows = ""
    for icon, name, desc in intelligence:
        rows += f"""
        <div class="intel-row">
            <div class="intel-left">
                <div class="intel-icon">{icon}</div>
                <div>
                    <div class="intel-name">{escape(name)}</div>
                    <div class="intel-desc">{escape(desc)}</div>
                </div>
            </div>
            <div class="online">● ONLINE</div>
        </div>
        """

    soc_markdown(
        f"""
        <div class="panel">
            <div class="panel-title">AI Security Intelligence</div>
            <div class="panel-sub">Multi-layer decision pipeline currently active</div>
            {rows}
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# PIPELINE
# ============================================================
soc_markdown(
    """
    <div class="section-head">
        <div class="section-title">AI Security Intelligence Pipeline</div>
        <div class="section-note">END-TO-END ANALYSIS FLOW</div>
    </div>
    """,
    unsafe_allow_html=True,
)

pipeline = [
    ("☁", "CLOUDTRAIL", "INGEST"),
    ("◈", "ANOMALY", "ML MODEL"),
    ("◌", "BEHAVIOR", "ANALYSIS"),
    ("⌁", "CONTEXTUAL RISK", "SCORING"),
    ("⛓", "ATTACK CORRELATION", "INCIDENT"),
    ("⚡", "RESPONSE", "SIMULATION"),
]

pipe_html = '<div class="panel"><div class="pipeline">'
for icon, name, status in pipeline:
    pipe_html += f"""
    <div class="pipe">
        <div class="pipe-icon">{icon}</div>
        <div class="pipe-name">{escape(name)}</div>
        <div class="pipe-status">● {escape(status)}</div>
    </div>
    """
pipe_html += "</div></div>"
soc_markdown(pipe_html, unsafe_allow_html=True)


# ============================================================
# EVENT ACTIVITY + DISTRIBUTION
# ============================================================
soc_markdown(
    """
    <div class="section-head">
        <div class="section-title">Security Telemetry</div>
        <div class="section-note">EVENT ACTIVITY / STATUS DISTRIBUTION</div>
    </div>
    """,
    unsafe_allow_html=True,
)

chart_left, chart_right = st.columns([1.65, 1])

time_col = first_existing(ai_df, ["timestamp", "event_time", "time", "datetime"])
if time_col:
    times = pd.to_datetime(ai_df[time_col], errors="coerce")
    activity = (
        pd.DataFrame({"timestamp": times})
        .dropna()
        .set_index("timestamp")
        .resample("1h")
        .size()
        .rename("events")
        .reset_index()
    )
else:
    activity = pd.DataFrame({"timestamp": range(len(ai_df)), "events": 1})

with chart_left:
    soc_markdown('<div class="chart-panel"><div class="panel-title">Event Activity</div><div class="panel-sub">Cloud security events over time</div>', unsafe_allow_html=True)
    if PLOTLY_OK and len(activity) > 1:
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=activity["timestamp"],
            y=activity["events"],
            mode="lines",
            line=dict(width=2),
            fill="tozeroy",
            hovertemplate="%{x|%d %b %H:%M}<br>Events: %{y}<extra></extra>",
        ))
        fig.update_layout(
            height=230,
            margin=dict(l=8, r=8, t=8, b=8),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(7,17,29,0.55)",
            font=dict(color="#9db0c1", size=10),
            xaxis=dict(showgrid=False, zeroline=False, linecolor="#19324a"),
            yaxis=dict(showgrid=True, gridcolor="#173047", zeroline=False, title=None),
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    elif PLOTLY_OK:
        fig = go.Figure(go.Bar(x=activity["timestamp"], y=activity["events"]))
        fig.update_layout(
            height=230, margin=dict(l=8,r=8,t=8,b=8),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(7,17,29,0.55)",
            font=dict(color="#9db0c1"), showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    elif len(activity) > 1:
        st.line_chart(activity.set_index("timestamp"), height=230, use_container_width=True)
    else:
        st.bar_chart(activity.set_index("timestamp"), height=230, use_container_width=True)
    soc_markdown("</div>", unsafe_allow_html=True)

with chart_right:
    soc_markdown('<div class="chart-panel"><div class="panel-title">Event Distribution</div><div class="panel-sub">Successful vs failed operations</div>', unsafe_allow_html=True)

    if status_col:
        status_counts = df[status_col].astype(str).str.upper().value_counts()
    else:
        status_counts = pd.Series({"UNKNOWN": len(df)})

    if PLOTLY_OK:
        fig = go.Figure(
            data=[
                go.Pie(
                    labels=status_counts.index.tolist(),
                    values=status_counts.values.tolist(),
                    hole=.68,
                    textinfo="label+percent",
                    textfont=dict(size=9),
                )
            ]
        )
        fig.update_layout(
            height=230,
            margin=dict(l=5, r=5, t=5, b=5),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#9db0c1"),
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.bar_chart(status_counts, height=230, use_container_width=True)

    soc_markdown("</div>", unsafe_allow_html=True)


# ============================================================
# ACTIVE ATTACK CHAINS
# ============================================================
soc_markdown(
    """
    <div class="section-head">
        <div class="section-title">Attack Chain Detection</div>
        <div class="section-note">MULTI-EVENT CORRELATION</div>
    </div>
    """,
    unsafe_allow_html=True,
)

if incident_records:
    chain_cols = st.columns(min(3, len(incident_records[:6])))

    for idx, item in enumerate(incident_records[:6]):
        with chain_cols[idx % len(chain_cols)]:
            sev = str(item.get("severity", item.get("threat_level", ""))).upper()
            score = int(round(number_value(pd.Series(item), ["final_risk_score", "chain_score", "risk_score", "risk"], 0)))
            if not sev:
                sev = severity_from_score(score)

            sev_class = sev.lower()
            assessment = text_value(
                pd.Series(item),
                ["assessment", "attack_pattern", "description", "threat_type"],
                "Suspicious correlated cloud activity",
            )
            incident_id = text_value(pd.Series(item), ["incident_id", "id"], f"CHAIN-{idx+1:03d}")
            user = text_value(pd.Series(item), ["user", "username", "principal"], "—")
            ip = text_value(pd.Series(item), ["source_ip", "src_ip", "ip"], "—")
            events_count = text_value(pd.Series(item), ["event_count", "events", "chain_length"], "—")

            soc_markdown(
                f"""
                <div class="chain">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                        <span class="badge badge-{sev_class}">{escape(sev)}</span>
                        <span class="incident-id">{escape(incident_id)[:18]}</span>
                    </div>
                    <div class="chain-title">{escape(assessment)}</div>
                    <div class="chain-score">{score}<span style="font-size:8px;color:#61788b;"> / CHAIN SCORE</span></div>
                    <div class="chain-flow" style="margin-top:9px;">
                        USER <span>{escape(user)}</span><br>
                        SOURCE <span>{escape(ip)}</span><br>
                        EVENTS <span>{escape(events_count)}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
else:
    soc_markdown(
        """
        <div class="panel">
            <div class="panel-title">No correlated attack chains</div>
            <div class="panel-sub">The correlation engine did not return an incident record for the current dataset.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# ADAPTIVE RESPONSE + BEHAVIORAL INTELLIGENCE
# ============================================================
soc_markdown(
    """
    <div class="section-head">
        <div class="section-title">Adaptive Response & Behavioral Intelligence</div>
        <div class="section-note">RECOMMENDATIONS / SIMULATION</div>
    </div>
    """,
    unsafe_allow_html=True,
)

resp_col, behavior_col = st.columns([1, 1])

response_col = first_existing(
    ai_df,
    [
        "recommended_response",
        "response_action",
        "recommended_action",
        "adaptive_response",
        "response",
        "action_recommendation",
    ],
)

with resp_col:
    if response_col:
        responses = ai_df[response_col].fillna("NO ACTION").astype(str).replace("", "NO ACTION")
        response_counts = responses.value_counts().head(6)
    else:
        response_counts = pd.Series(
            {
                "MONITOR": max(total_events - critical_incidents - high_incidents, 0),
                "ALERT": high_incidents,
                "RESTRICT + ALERT": critical_incidents,
            }
        )
        response_counts = response_counts[response_counts > 0]

    soc_markdown('<div class="chart-panel"><div class="panel-title">Adaptive Response Distribution</div><div class="panel-sub">Recommended actions — no automatic blocking is performed</div>', unsafe_allow_html=True)
    if not response_counts.empty:
        if PLOTLY_OK:
            fig = go.Figure(go.Bar(
                x=response_counts.index.tolist(),
                y=response_counts.values.tolist(),
                text=response_counts.values.tolist(),
                textposition="outside",
                hovertemplate="%{x}<br>Events: %{y}<extra></extra>",
            ))
            fig.update_layout(
                height=210,
                margin=dict(l=8, r=8, t=18, b=8),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(7,17,29,0.55)",
                font=dict(color="#9db0c1", size=10),
                xaxis=dict(showgrid=False, zeroline=False, linecolor="#19324a"),
                yaxis=dict(showgrid=True, gridcolor="#173047", zeroline=False, title=None),
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            st.bar_chart(response_counts, height=210, use_container_width=True)
    soc_markdown("</div>", unsafe_allow_html=True)

with behavior_col:
    behavior_cols = [
        ("Users observed", str(df["user"].nunique()) if "user" in df.columns else "—"),
        ("Source IPs", str(df["source_ip"].nunique()) if "source_ip" in df.columns else "—"),
        ("Actions", str(df["action"].nunique()) if "action" in df.columns else "—"),
        ("Failed operations", str(failed_events)),
        ("Correlated chains", str(len(incident_records))),
        ("Simulation", "ENABLED"),
    ]

    rows = ""
    for name, value in behavior_cols:
        rows += f"""
        <div class="intel-row">
            <div class="intel-name">{escape(name)}</div>
            <div class="signal-val">{escape(value)}</div>
        </div>
        """

    soc_markdown(
        f"""
        <div class="panel">
            <div class="panel-title">Behavioral Intelligence</div>
            <div class="panel-sub">Observed telemetry characteristics</div>
            {rows}
            <div class="ai-box">
                <div class="ai-box-title">AI Decision Layer</div>
                <div class="ai-box-text">
                    The system combines anomaly detection, behavior analysis, contextual risk and
                    attack-chain evidence before generating a response recommendation.
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# DETAILED SECURITY EVENTS
# ============================================================
soc_markdown(
    """
    <div class="section-head">
        <div class="section-title">Detailed Security Events</div>
        <div class="section-note">LATEST TELEMETRY / AI ENRICHED</div>
    </div>
    """,
    unsafe_allow_html=True,
)

display_df = ai_df.copy()

# Sort by timestamp where possible.
if time_col:
    display_df["_sort_time"] = pd.to_datetime(display_df[time_col], errors="coerce")
    display_df = display_df.sort_values("_sort_time", ascending=False).drop(columns=["_sort_time"])

# Prefer suspicious events first, while retaining recent normal events.
display_score = display_df.apply(score_from_row, axis=1)
display_failed = (
    display_df[status_col].astype(str).str.upper().eq("FAILED")
    if status_col
    else pd.Series(False, index=display_df.index)
)
display_df["_priority"] = display_score + display_failed.astype(int) * 20
display_df = display_df.sort_values("_priority", ascending=False).drop(columns=["_priority"]).head(20)

preferred = [
    "timestamp",
    "user",
    "source_ip",
    "action",
    "status",
    "bytes_transferred",
    "risk_score",
    "final_risk_score",
    "contextual_risk_score",
    "chain_score",
    "error_code",
]

available = [c for c in preferred if c in display_df.columns]

# Add any useful AI-generated fields if present.
for c in display_df.columns:
    low = c.lower()
    if (
        c not in available
        and any(k in low for k in ["anomaly", "behavior", "risk", "response", "assessment"])
    ):
        available.append(c)

if available:
    shown = display_df[available].copy()

    rename_map = {
        "timestamp": "Timestamp",
        "user": "User",
        "source_ip": "Source IP",
        "action": "Action",
        "status": "Status",
        "bytes_transferred": "Bytes",
        "risk_score": "Risk Score",
        "final_risk_score": "Final Risk",
        "contextual_risk_score": "Contextual Risk",
        "chain_score": "Chain Score",
        "error_code": "Error",
    }
    shown = shown.rename(columns={k: v for k, v in rename_map.items() if k in shown.columns})

    st.dataframe(
        shown,
        use_container_width=True,
        hide_index=True,
        height=420,
    )
else:
    st.dataframe(display_df.head(20), use_container_width=True, hide_index=True, height=420)


# ============================================================
# SYSTEM STATUS FOOTER
# ============================================================
soc_markdown(
    """
    <div class="section-head">
        <div class="section-title">System Status</div>
        <div class="section-note">SOC COMPONENT HEALTH</div>
    </div>
    """,
    unsafe_allow_html=True,
)

s1, s2, s3, s4, s5, s6 = st.columns(6)

status_items = [
    ("CLOUDTRAIL", "DATA LOADED"),
    ("ANOMALY ENGINE", "ONLINE"),
    ("BEHAVIOR ENGINE", "ONLINE"),
    ("RISK ENGINE", "ONLINE"),
    ("CORRELATION", "ONLINE"),
    ("RESPONSE", "SIMULATION"),
]

for col, (name, value) in zip([s1, s2, s3, s4, s5, s6], status_items):
    with col:
        color = "#ffb454" if value == "SIMULATION" else "#36dfaa"
        soc_markdown(
            f"""
            <div class="metric-mini">
                <div class="metric-mini-label">{escape(name)}</div>
                <div class="metric-mini-value" style="color:{color};">● {escape(value)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

soc_markdown(
    f"""
    <div class="footer">
        <span>AI CLOUD CYBERSECURITY SOC • AWS CLOUDTRAIL EVENT HISTORY • DEFENSIVE SECURITY ANALYTICS</span>
        <span>SIMULATION MODE • {escape(now_text)}</span>
    </div>
    """,
    unsafe_allow_html=True,
)
