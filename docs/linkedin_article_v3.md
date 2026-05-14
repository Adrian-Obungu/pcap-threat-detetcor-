I was sat at home covering yet another certification—the **Cyber Risk Professional (CRPO)** by the **ICTTF**—and I found myself in the middle of the "Understanding Cyber Threats" module. It felt like another round of basics and fundamentals. I realized that traditional note-taking and reading papers just wasn't cutting it anymore. I started thinking about how I could use this opportunity to actually build something, rather than just absorbing theory.

That’s when I decided to launch a small-scale project directly from my **iPad Pro**. I wanted a minimal environment, a short path to deployment, and a way to learn in public. Since the course touched heavily on ransomware protection, I narrowed my focus to the threat detection domain. My deep dive eventually landed me on **Packet Capture (PCAP) analysis**.

Threat detection is often the "canary in the coal mine" for security teams. By inspecting raw network traffic, you can catch the subtle traces of an adversary before they establish a foothold. However, I quickly realized that traditional PCAP analysis—relying on static signatures and known patterns—is increasingly blind to modern, stealthy attacks.

### **The iPad Challenge & The Pivot to Hybrid AI**

Building a network security tool on an iPad isn't exactly standard practice. I relied on **GitHub Codespaces** to provide the Linux environment I needed, using **Scapy [1]** for the heavy lifting of packet parsing. My initial goal was simple: build a rule-based engine to catch the "usual suspects" like ARP spoofing, port scans, and DNS tunneling [2].

But as I dug deeper into the research, I saw the industry-wide shift. Traditional rules are great for high-confidence alerts, but they fail against zero-day exploits and "Living Off the Land" (LotL) techniques where attackers use legitimate tools to hide in plain sight. I didn't want to scrap my rule engine; I wanted to use it as a foundation for something more resilient.

I decided to pivot to a **Hybrid AI-Driven approach**. I integrated an unsupervised machine learning model—an **Isolation Forest [3]**—to run alongside my deterministic rules.

### **How the Hybrid Engine Works**

The system now functions as a dual-pipeline. First, it aggregates raw packets into "flows" (5-tuple) using a custom feature extractor I built in Python. These flows are then fed into two engines:

1.  **The Rule Engine:** This catches known threats like a 1400-byte ICMP packet being used for data exfiltration [4].
2.  **The AI Anomaly Engine:** This assigns an "AI Suspicion Score" based on behavioral metadata like packet inter-arrival times and flow duration. It doesn't need to know what an attack looks like; it just needs to know what *normal* traffic looks like [5].

In one of my recent tests, I simulated a large ICMP exfiltration flow. The rule engine flagged it immediately based on payload size, but the AI model also independently assigned it a score of **-0.1475**, confirming it was a mathematical outlier [6]. This dual-validation is exactly the kind of "defense in depth" I was aiming for.

### **Lessons from the Cloud-Native Lab**

This project taught me more than any textbook could. Developing on an iPad forced me to think in the cloud and rely on automation. It also highlighted the reality of modern security: we are moving away from "What is this file?" toward "Does this behavior belong here?" [7].

The tool isn't production-ready—it still needs more diverse training data and struggles with encrypted traffic analysis—but it’s a working proof-of-concept for how we can bridge the gap between signature-based and behavioral-based detection [8].

If you’re stuck in a cycle of certifications, my advice is to pick a "minimal" environment and just start building. The friction of the constraints is often where the best learning happens.

---

**References**
[1] Scapy Documentation: https://scapy.readthedocs.io/
[2] SANS 2024 Network Anomaly Detection Paper: https://www.sans.org/white-papers/36762/
[3] Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. IEEE ICDM: https://ieeexplore.ieee.org/document/4781136
[4] Adrian-Obungu/pcap-threat-detector: `detector.py`: https://github.com/Adrian-Obungu/pcap-threat-detector/blob/main/src/detector/detector.py
[5] Sharafaldin, I., et al. (2018). Toward a Reliable Dataset for IDS Evaluation. ICISSP: https://www.unb.ca/cic/datasets/ids-2018.html
[6] NIST Guide to Intrusion Detection and Prevention Systems (IDPS): https://csrc.nist.gov/publications/detail/sp/800-94/final
[7] Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection. NDSS: https://www.ndss-symposium.org/ndss2018/ndss2018-papers/kitsune-ensemble-autoencoders-online-network-intrusion-detection/
[8] CSE-CIC-IDS2018 Dataset: https://www.unb.ca/cic/datasets/ids-2018.html

---
*Authored by Adrian S. Obungu | Built on iPad Pro via GitHub Codespaces*
