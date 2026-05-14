# Strategic Roadmap: Hybrid IDS Evolution 🚀

This roadmap outlines the transition from a PCAP-based research tool to a real-time, hybrid AI-driven detection system. It is specifically designed for a **solo developer** workflow using an **iPad Pro (via GitHub Codespaces)** for agile development and a **Lenovo X280** for compute-intensive tasks.

---

## 🏗️ Phase 1: Real-Time Observability (iPad & Codespaces)
*Focus: Transitioning from static PCAP analysis to live monitoring with a web-based UI.*

### **1. Web-Based Dashboard (Streamlit)**
- **Feature:** A reactive dashboard to visualize network traffic and alerts in real-time.
- **Why:** Streamlit is lightweight, Python-native, and renders perfectly in the Codespaces browser on iPad.
- **Implementation:**
    - Use `streamlit` to build the UI.
    - Integrate `scapy.sniff()` in a background thread to feed a `pandas` DataFrame.
    - Display real-time charts (packets/sec, top talkers, anomaly score trends).

### **2. Live Packet Ingestion**
- **Feature:** Moving beyond `test_pcaps/` to live interface sniffing.
- **Why:** Essential for a functional IDS.
- **Implementation:** Refactor `src/detector/ai_runner.py` to support `iface` as an input argument using Scapy's `AsyncSniffer`.

### **3. Dynamic Whitelisting UI**
- **Feature:** An interactive table to manage `data/whitelist/whitelist.txt` directly from the dashboard.
- **Why:** Reduces friction when tuning the engine to your specific network environment.

---

## 🧠 Phase 2: Advanced AI & Feature Engineering (Lenovo X280)
*Focus: Leveraging the X280's local compute power for heavy lifting and model refinement.*

### **1. Lightweight Autoencoders (AE)**
- **Feature:** Complement the Isolation Forest with a Reconstruction-based Anomaly Engine.
- **Why:** Autoencoders are superior at learning the "compressed" representation of normal traffic. High reconstruction error = Anomaly.
- **Implementation:** Use `PyTorch` or `TensorFlow` (on the X280) to train a small AE on your baseline traffic. Export the model to `.onnx` or `.pkl` for inference on the iPad.

### **2. High-Fidelity Feature Extraction**
- **Feature:** Expanding the 5-tuple flow to include temporal and statistical features (e.g., inter-arrival time variance, TCP flag distribution).
- **Why:** More features = better AI accuracy, but requires more CPU to calculate in real-time.
- **Implementation:** Optimize `src/detector/feature_extractor.py` using `numpy` vectorization to handle higher throughput.

### **3. Large-Scale Dataset Training**
- **Feature:** Retraining the "brain" on the full **CSE-CIC-IDS2018** dataset.
- **Why:** Your current model is trained on synthetic data; real-world datasets provide the "gritty" noise needed for production-grade robustness.
- **Implementation:** Perform the multi-GB training on the Lenovo X280 and sync the resulting `.pkl` to GitHub for the iPad to use.

---

## 🚀 Phase 3: Deployment & Hardening (Hybrid Workflow)
*Focus: Making the tool useful for others and secure for yourself.*

### **1. Containerization (Docker)**
- **Feature:** A single `docker-compose.yml` to launch the detector, dashboard, and database.
- **Why:** Ensures "it works on my machine" (or iPad) works everywhere.
- **Implementation:** Create a multi-stage Dockerfile to keep the image lightweight.

### **2. Alert Persistence (SQLite)**
- **Feature:** Moving from JSON logs to a structured database.
- **Why:** Enables historical analysis and "time-travel" debugging of past threats.
- **Implementation:** Use Python's built-in `sqlite3`—zero configuration required.

### **3. Export to PCAP/Report**
- **Feature:** One-click download of the suspicious traffic segments for forensic analysis.
- **Why:** Bridges the gap between detection and response.

---

## 📋 Task Allocation Matrix

| Feature | Primary Device | Rationale |
| :--- | :--- | :--- |
| **Streamlit GUI** | iPad Pro | Web-based, lightweight, visual. |
| **Rule Tuning** | iPad Pro | Quick logic edits in Codespaces. |
| **Live Sniffing** | iPad Pro | Testing on the go via Codespaces. |
| **AE Model Training** | Lenovo X280 | Requires significant RAM/CPU/GPU. |
| **Big Data Processing** | Lenovo X280 | Handling multi-GB datasets (e.g., CIC-IDS). |
| **Container Builds** | Lenovo X280 | Docker builds can be heavy on system resources. |

---

## 🛠️ Recommended Tech Stack for v2.0
- **GUI:** [Streamlit](https://streamlit.io/) (The gold standard for Python data apps).
- **Inference:** [ONNX Runtime](https://onnxruntime.ai/) (For running AE models efficiently).
- **Data:** [Polars](https://pola.rs/) (Faster than Pandas for real-time flow aggregation).
- **Database:** [SQLite](https://www.sqlite.org/) (Built-in, zero-latency for solo devs).

---
*Roadmap curated for Adrian S. Obungu by HackTricks Assistant.*
