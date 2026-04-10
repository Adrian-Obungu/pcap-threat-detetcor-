I was sat at home covering yet another certification—the **Cyber Risk Professional (CRPO)** by the **ICTTF**—and I found myself in the middle of the "Understanding Cyber Threats" module. It felt like another round of basics and fundamentals. I realized that traditional note-taking and reading papers just wasn't cutting it anymore. I started thinking about how I could use this opportunity to actually explore what's possible, rather than just absorbing theory and taking notes.

That’s when I decided to launch a small-scale project inspired by the course, working directly from my **iPad Pro**. I wanted a minimal environment, a short path to deployment, and a way to learn in public. Since the course touched heavily on ransomware protection, I narrowed my focus to the threat detection domain. My deep dive eventually landed me on **Packet Capture (PCAP) analysis**.

### **The iPad Challenge & The Core Engine**

Building a security tool on an iPad isn’t the standard path, but **GitHub Codespaces** provided a full Linux environment in the cloud, allowing me to run complex packet analysis without a local high-performance machine. I started by writing `detector.py`, a core engine that uses **Scapy [1]** to parse raw traffic and track state. 

My initial logic focused on high-confidence, signature-like detections: tracking MAC-IP bindings for ARP spoofing with time-based aging and using an **$O(n)$ sliding window** to flag rapid port scans [2]. These rules are great because they are fast and definitive, but they are inherently reactive. They can’t see what they haven’t been told to look for, especially in an era where 95% of traffic is encrypted [3].

### **Bridging the Gap with Hybrid AI**

To bridge this gap, I decided to add a parallel AI pipeline. Instead of just looking at individual packets, I began aggregating traffic into **“flows”**—conversations between two points defined by their 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol). I wrote a dedicated `feature_extractor.py` to turn these flows into mathematical vectors: packet counts, total bytes, duration, and inter-arrival times. 

This transformed raw network data into a structured format that an **Isolation Forest [4]** model could understand. The goal wasn’t to replace my rules, but to use them as a foundation for a conceptual approach on integrating AI-driven detection. I wanted to augment them with a behavioral layer that could flag “weird” traffic even if it didn’t trigger a specific alert.

### **Defining "Normal" and The "Aha" Moment**

Training the model was an exercise in defining “normal.” I used the **CSE-CIC-IDS2018 dataset [5]** as a reference and generated synthetic benign traffic that mimicked typical DNS and HTTP flows to teach the model what a quiet network looks like. The beauty of the Isolation Forest algorithm is that it doesn’t need to know what an attack looks like; it just needs to know what doesn’t belong. When a flow deviates from the baseline—perhaps it’s too long, too frequent, or has an unusual byte-to-packet ratio—the model assigns it a negative anomaly score, flagging it for investigation.

I put this to the test with a synthetic data exfiltration scenario. I generated a PCAP containing five large ICMP packets, each carrying a 1400-byte payload. My rule engine caught it immediately as a potential exfiltration event based on the packet size. Simultaneously, the AI model flagged the flow with an **anomaly score of -0.1475**. Seeing both systems fire at once was the “aha” moment. The rules provided the immediate context (“This is a large ICMP packet”), while the AI provided the behavioral confirmation (“This flow is mathematically distinct from anything we’ve seen before”) [6].

### **Looking Forward**

Of course, this is still a lab tool. It can’t inspect encrypted payloads without a decryption mirror, and the model needs much more diverse training data to be production-ready. My next steps involve adding live capture capabilities and a web interface to visualize these threats in real-time. I’m also looking into **Autoencoders [7]** to see if they can provide even more granular anomaly detection for encrypted traffic.

Building this on an iPad forced me to think differently. It stripped away the comfort of a local machine and made me focus on core logic and cloud-based automation. Blending deterministic rules with machine learning taught me that the future of network security isn’t about choosing one over the other; it’s about the hybrid approach where they work in tandem to cover each other’s blind spots. It’s about moving from **“What is this?”** to **“Does this belong here?” [8]**.

If you’re stuck in a cycle of certifications, my advice is to pick a "minimal" environment and just start building. The friction of the constraints is often where the best learning happens.

---

**References**
[1] Scapy Documentation: https://scapy.readthedocs.io/
[2] Adrian-Obungu/pcap-threat-detector: `detector.py`: https://github.com/Adrian-Obungu/pcap-threat-detector/blob/main/src/detector/detector.py
[3] Google Transparency Report on HTTPS encryption: https://transparencyreport.google.com/https/overview
[4] Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. IEEE ICDM: https://ieeexplore.ieee.org/document/4781136
[5] CSE-CIC-IDS2018 Dataset: https://www.unb.ca/cic/datasets/ids-2018.html
[6] NIST Guide to Intrusion Detection and Prevention Systems (IDPS): https://csrc.nist.gov/publications/detail/sp/800-94/final
[7] Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection. NDSS: https://www.ndss-symposium.org/ndss2018/ndss2018-papers/kitsune-ensemble-autoencoders-online-network-intrusion-detection/
[8] SANS 2024 Network Anomaly Detection Paper: https://www.sans.org/white-papers/36762/

---
*Authored by Adrian S. Obungu | Built on iPad Pro via GitHub Codespaces*
