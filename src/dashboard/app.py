"""
Streamlit dashboard for real‑time alert viewing and whitelist management.
"""
import streamlit as st
import json
import sys
import os

# Add src to path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from whitelist.manager import load_whitelist, add_whitelist_entry, remove_whitelist_entry

st.set_page_config(page_title="Hybrid IDS Dashboard", layout="wide")
st.title("Hybrid IDS – Real‑time Threat Detection")

# Sidebar navigation
page = st.sidebar.selectbox("Navigate", ["Live Overview", "Alert History", "Whitelist Manager"])

if page == "Live Overview":
    from pages import live
    live.show()
elif page == "Alert History":
    from pages import alerts
    alerts.show()
elif page == "Whitelist Manager":
    from pages import whitelist
    whitelist.show()
