"""
Streamlit dashboard for real-time alert viewing and whitelist management.
"""
import streamlit as st
import sys
import os
import time
import pandas as pd

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from whitelist.manager import load_whitelist, add_whitelist_entry, remove_whitelist_entry
from dashboard.realtime import engine

st.set_page_config(page_title="PCAP Threat Detector", layout="wide", initial_sidebar_state="expanded")

# Custom CSS for "Vibe Coder" / Modern Dark Aesthetic
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
        color: #fafafa;
    }
    .stMetric {
        background-color: #161b22;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #30363d;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
        background-color: #238636;
        color: white;
        border: none;
    }
    .stButton>button:hover {
        background-color: #2ea043;
    }
    .stAlert {
        background-color: #161b22;
        border: 1px solid #30363d;
        color: #fafafa;
    }
    </style>
    """, unsafe_allow_html=True)

# Initialize engine in background if not already running
if 'engine_started' not in st.session_state:
    # Default to replay for Codespaces environment
    engine.start(replay_pcap="test_pcaps/exfil.pcap")
    st.session_state['engine_started'] = True
    st.session_state['alerts'] = []

st.title("🛡️ PCAP Threat Detector")
st.sidebar.title("Navigation")
page = st.sidebar.selectbox("Go to", ["Live Monitor", "Whitelist Manager", "System Logs"])

if page == "Live Monitor":
    st.header("📡 Real-time Traffic Analysis")
    
    # Update alerts from engine
    while not engine.alert_queue.empty():
        st.session_state['alerts'].insert(0, engine.alert_queue.get())
        # Keep only last 100 alerts
        if len(st.session_state['alerts']) > 100:
            st.session_state['alerts'].pop()

    col1, col2, col3 = st.columns(3)
    col1.metric("Packets Processed", f"{engine.stats['packets_processed']:,}")
    col2.metric("Active Alerts", f"{len(st.session_state['alerts'])}")
    uptime = int(time.time() - engine.stats['start_time'])
    col3.metric("Uptime", f"{uptime}s")
    
    st.subheader("Recent Alerts")
    if not st.session_state['alerts']:
        st.info("Monitoring active... No threats detected yet.")
    else:
        for alert in st.session_state['alerts'][:10]:
            with st.container():
                st.markdown(f"**[{alert['type']}]** {alert['description']} *(at {time.ctime(alert['time'])})*")
                st.divider()
    
    # Auto-refresh
    time.sleep(2)
    st.rerun()
    
elif page == "Whitelist Manager":
    st.header("📝 Whitelist Management")
    
    with st.expander("Add New Entry", expanded=True):
        col1, col2 = st.columns([3, 1])
        new_entry = col1.text_input("Entry (e.g., 192.168.1.1, google.com, 192.168.1.1:00:11:22:33:44:55)")
        if col2.button("Add Entry"):
            if add_whitelist_entry(new_entry):
                st.success(f"Added: {new_entry}")
                st.rerun()
            else:
                st.error("Invalid entry format.")

    st.subheader("Current Whitelist")
    entries = load_whitelist()
    if not entries:
        st.write("No entries found.")
    else:
        for entry in entries:
            c1, c2 = st.columns([4, 1])
            c1.code(entry)
            if c2.button("Remove", key=entry):
                if remove_whitelist_entry(entry):
                    st.success(f"Removed: {entry}")
                    st.rerun()

elif page == "System Logs":
    st.header("📋 System Audit Logs")
    log_path = "logs/detector.log"
    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            logs = f.readlines()
            st.text_area("detector.log (Last 50 lines)", "".join(logs[-50:]), height=400)
    else:
        st.warning(f"No logs found at {log_path}.")
