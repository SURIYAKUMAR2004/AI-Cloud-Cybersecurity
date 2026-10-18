import streamlit as st

st.set_page_config(
    page_title="AI Cloud Cybersecurity",
    layout="wide"
)

st.title("🛡️ AI Cloud Cybersecurity")
st.success("Streamlit dashboard is working!")

st.metric("System Status", "ONLINE")
st.metric("AI Pipeline", "READY")
st.metric("AWS Integration", "CONNECTED")

st.write("Dashboard rendering test successful.")
