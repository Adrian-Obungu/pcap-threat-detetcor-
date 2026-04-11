def show():
    import streamlit as st
    import json
    st.header("Alert History")
    # For now, load from a static JSON file (if exists)
    try:
        with open("alerts_history.json", "r") as f:
            alerts = json.load(f)
    except FileNotFoundError:
        alerts = []
    if not alerts:
        st.write("No alerts yet. Run the detector to generate alerts.")
    else:
        st.dataframe(alerts)
