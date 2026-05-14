## Prompt for DeepSeek LLM: Phase 1 - Real-Time Observability for Hybrid IDS

**Context:**
I am a solo developer building a **Hybrid AI-Driven Intrusion Detection System (IDS)**. My development environment is primarily an **iPad Pro via GitHub Codespaces**, with a Lenovo X280 available for heavier compute tasks (though for this phase, we aim to stay within the iPad/Codespaces).

The project repository is located at `https://github.com/Adrian-Obungu/pcap-threat-detector-` and has recently undergone a significant refactor to a professional structure, including `src/`, `scripts/`, `data/`, `docs/`, and `models/` directories. The core `detector.py` and `ai_runner.py` are in `src/detector/`.

My goal is to evolve this system from static PCAP analysis to **real-time network observability**.

**Specific Request - Phase 1: Real-Time Observability**
I need to implement the following features within the iPad Pro / GitHub Codespaces environment:

1.  **Web-Based Dashboard (Streamlit):** A reactive dashboard to visualize network traffic and alerts in real-time.
    *   **Requirements:** Must be Python-native, lightweight, and render effectively in the Codespaces browser on iPad.
    *   **Functionality:** Display real-time charts (packets/sec, top talkers, anomaly score trends) and alerts.
2.  **Live Packet Ingestion:** Refactor `src/detector/ai_runner.py` to support live interface sniffing using Scapy.
    *   **Requirements:** Must handle `iface` as an input argument and integrate Scapy's `AsyncSniffer` for non-blocking capture.
3.  **Dynamic Whitelisting UI:** An interactive component within the Streamlit dashboard to manage `data/whitelist/whitelist.txt`.
    *   **Requirements:** Allow users to add/remove entries and persist changes to the file.

**Feasibility Question:**
Given the constraints of an iPad Pro and GitHub Codespaces (web-based IDE, potentially limited direct hardware access for sniffing, resource limitations), is it genuinely feasible to implement **all three** of these Phase 1 features successfully and robustly? Please provide a detailed assessment, highlighting potential challenges and recommended workarounds.

**Self-Validated Protocol for Project Continuity:**
If deemed feasible, please outline a step-by-step protocol for implementing Phase 1, ensuring project continuity, code quality, and maintainability. This protocol should include:

1.  **Modular Design Principles:** How should new components (e.g., Streamlit app, live sniffer module) be structured within the existing `src/` directory to maintain separation of concerns and reusability?
2.  **Testing Strategy:** What unit/integration tests should be prioritized for the Streamlit components, live sniffer, and whitelist management to ensure reliability?
3.  **Documentation Standards:** What level of inline comments, docstrings, and `README.md` updates are necessary for each new module?
4.  **Version Control Best Practices:** How should Git branches, commit messages, and pull requests be managed for this phase?
5.  **Performance Considerations:** Specific recommendations for optimizing Streamlit and Scapy for a Codespaces environment (e.g., efficient data handling, non-blocking operations).
6.  **Security Best Practices:** Any specific considerations for handling network interfaces and user input in a web-based security tool.

Your response should be technically detailed, actionable, and directly address the feasibility and protocol for successful implementation of Phase 1.
