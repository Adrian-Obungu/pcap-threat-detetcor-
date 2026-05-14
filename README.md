# pcap-threat-detetcor
Lightweight PCAP analyzer detecting ARP spoofing, port scans, DNS tunneling, and data exfiltration.

## Real‑time Dashboard (Phase 1)

The project now includes a Streamlit dashboard for real‑time monitoring and whitelist management.

### Running the Dashboard

```bash
streamlit run src/dashboard/app.py
```

The dashboard will be available at http://localhost:8501 (Codespaces forwards this port).

Live Packet Capture

Due to Codespaces limitations, live capture from physical network interfaces is not supported. Use the PCAP replay mode instead. In the future, you can run the sniffer on a local machine and forward PCAPs.

Whitelist Management

The dashboard includes a page to view, add, and remove whitelist entries. Entries are stored in data/whitelist/whitelist.txt.
