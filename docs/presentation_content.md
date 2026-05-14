# Hybrid AI-Driven IDS: Bridging the Gap in Network Threat Detection

## Slide 1: Title Slide

### **Hybrid AI-Driven IDS: Bridging the Gap in Network Threat Detection**

**Adrian S. Obungu**

[LinkedIn](https://www.linkedin.com/in/adrian-o-9b4856260)
[GitHub](https://github.com/Adrian-Obungu)

---

## Slide 2: The Evolving Threat Landscape

### **Traditional PCAP Analysis Falls Short Against Modern Threats**

*   **Encrypted Traffic:** Over 95% of internet traffic is now encrypted, rendering deep packet inspection ineffective [1].
*   **Zero-Day Exploits:** Signature-based IDS cannot detect novel attacks for which no signatures exist.
*   **Living Off the Land (LotL):** Attackers use legitimate tools and credentials, blending with normal activity.
*   **Blind Spots:** Traditional rules struggle with subtle, behavioral anomalies that don't trigger explicit alerts.

---

## Slide 3: Introducing the Hybrid Approach

### **Combining Deterministic Rules with AI for Comprehensive Coverage**

*   **Dual-Engine Architecture:** A robust solution integrating two parallel detection pipelines.
*   **High-Confidence Alerts:** Leveraging established rules for known attack patterns.
*   **Behavioral Anomaly Detection:** Utilizing AI to identify deviations from normal network behavior.
*   **Enhanced Visibility:** Bridging the gap between what we know and what we don't yet understand.

---

## Slide 4: Deterministic Rule Engine

### **Rapid & Reliable Detection of Known Attack Patterns**

*   **ARP Spoofing:** Tracks MAC-IP bindings with time-based aging and flapping thresholds [2].
*   **Port Scanning:** Employs an $O(n)$ sliding window to detect rapid SYN scans per destination [3].
*   **DNS Tunneling:** Analyzes subdomain length, Shannon entropy, and query frequency for suspicious activity [4].
*   **Data Exfiltration:** Monitors cumulative flow bytes and payload sizes for outbound traffic [5].

---

## Slide 5: AI Anomaly Engine

### **Unsupervised Learning for Novel Threat Identification**

*   **Isolation Forest:** A lightweight, effective algorithm for isolating anomalies in high-dimensional data [6].
*   **Flow-Level Metrics:** Focuses on behavioral patterns rather than packet content.
*   **No Prior Attack Knowledge:** Learns "normal" and flags anything that deviates significantly.
*   **AI Suspicion Score:** Quantifies how anomalous a network flow is, aiding in prioritization.

---

## Slide 6: Feature Extraction: From Packets to Insights

### **Transforming Raw PCAP Data into Actionable Features**

*   **Flow Aggregation:** Grouping packets into 5-tuple flows (src_ip, dst_ip, src_port, dst_port, protocol).
*   **Key Features:** Extracting duration, packet count, total bytes, packets/sec, bytes/sec, mean packet size, and variance [7].
*   **`feature_extractor.py`:** The module responsible for this critical data engineering step.
*   **Input for AI:** Providing the structured data necessary for the Isolation Forest model.

---

## Slide 7: Training the AI Model

### **Defining "Normal" with Synthetic & Real-World Data**

*   **Synthetic Normal Flows:** Generating benign traffic to establish a baseline of expected behavior.
*   **CSE-CIC-IDS2018 Dataset:** Utilizing a comprehensive dataset for realistic training scenarios [8].
*   **`train_ai_model.py`:** Script for training and saving the `anomaly_model.pkl` using scikit-learn.
*   **Contamination Parameter:** Configuring the Isolation Forest to expect a small percentage of anomalies in the training data.

---

## Slide 8: Testing & Validation: Exfiltration Example

### **Dual Detection of a Synthetic Data Exfiltration Attempt**

*   **Scenario:** Five large ICMP packets (1400 bytes each) sent outbound.
*   **Rule Engine Alert:** Immediately flagged as "Data Exfiltration" due to large payload size.
*   **AI Anomaly Score:** The flow received a score of **-0.1475**, indicating a significant deviation from normal.
*   **Unified Alert:** Both engines independently confirmed the suspicious activity, enhancing confidence.

---

## Slide 9: Hybrid Architecture Overview

### **A Unified Pipeline for Comprehensive Threat Detection**

![Architecture Diagram](docs/architecture.png)

*   **Network Traffic Ingestion:** PCAP or live capture feeds the system.
*   **Parallel Processing:** Feature extraction feeds both rule-based and AI engines.
*   **Integrated Reporting:** Combining high-confidence alerts with AI suspicion scores for a holistic view.

---

## Slide 10: Limitations & Future Work

### **Addressing Challenges and Expanding Capabilities**

*   **Encrypted Traffic:** Current limitations in inspecting encrypted payloads without decryption.
*   **Model Refinement:** Need for more diverse and larger real-world training datasets.
*   **Live Capture:** Implementing real-time packet processing for immediate threat response.
*   **Web Interface:** Developing a user-friendly dashboard for visualization and interaction.
*   **Advanced AI:** Exploring Autoencoders for deeper insights into encrypted traffic anomalies [9].

---

## Slide 11: Conclusion

### **The Future of IDS: A Synergistic Blend of Rules and AI**

*   **Beyond Signatures:** Moving from reactive detection to proactive behavioral analysis.
*   **Resilience Against Novel Threats:** AI provides a crucial layer against zero-days and LotL attacks.
*   **Cloud-Native Development:** Building on platforms like GitHub Codespaces enables agile security innovation.
*   **Continuous Evolution:** Network security demands constant adaptation and integration of new technologies.

---

## Slide 12: Attribution & Contact

### **Thank You! Questions?**

**Adrian S. Obungu**

[LinkedIn](https://www.linkedin.com/in/adrian-o-9b4856260)
[GitHub](https://github.com/Adrian-Obungu)

---

## References
1.  **Google Transparency Report on HTTPS encryption:** [https://transparencyreport.google.com/https/overview](https://transparencyreport.google.com/https/overview)
2.  **Scapy Documentation:** [https://scapy.readthedocs.io/](https://scapy.readthedocs.io/)
3.  **SANS 2024 Network Anomaly Detection Paper:** [https://www.sans.org/white-papers/36762/](https://www.sans.org/white-papers/36762/)
4.  **Sharafaldin, I., et al. (2018). Toward a Reliable Dataset for IDS Evaluation. ICISSP.** [https://www.unb.ca/cic/datasets/ids-2018.html](https://www.unb.ca/cic/datasets/ids-2018.html)
5.  **NIST Guide to Intrusion Detection and Prevention Systems (IDPS):** [https://csrc.nist.gov/publications/detail/sp/800-94/final](https://csrc.nist.gov/publications/detail/sp/800-94/final)
6.  **Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. IEEE ICDM.** [https://ieeexplore.ieee.org/document/4781136](https://ieeexplore.ieee.ieee.org/document/4781136)
7.  **Adrian-Obungu/pcap-threat-detector: `feature_extractor.py`:** [https://github.com/Adrian-Obungu/pcap-threat-detector/blob/main/src/detector/feature_extractor.py](https://github.com/Adrian-Obungu/pcap-threat-detector/blob/main/src/detector/feature_extractor.py)
8.  **CSE-CIC-IDS2018 Dataset:** [https://www.unb.ca/cic/datasets/ids-2018.html](https://www.unb.ca/cic/datasets/ids-2018.html)
9.  **Mirsky, Y., et al. (2018). Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection. NDSS.** [https://www.ndss-symposium.org/ndss2018/ndss2018-papers/kitsune-ensemble-autoencoders-online-network-intrusion-detection/](https://www.ndss-symposium.org/ndss2018/ndss2018-papers/kitsune-ensemble-autoencoders-online-network-intrusion-detection/)
