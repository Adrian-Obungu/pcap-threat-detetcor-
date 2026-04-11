def show():
    import streamlit as st
    st.header("Live Overview (Simulated)")
    st.info("In a real deployment, this page would show real‑time charts of packet rates, top talkers, and anomaly scores.")
    # Placeholder for future charts
    col1, col2 = st.columns(2)
    col1.metric("Packets/sec", "0")
    col2.metric("Top Source IP", "None")
    st.line_chart({"Anomaly Score": []})
