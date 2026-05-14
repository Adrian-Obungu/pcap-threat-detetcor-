#!/usr/bin/env python3
"""
feature_extractor.py – Extract per-flow statistical features from a PCAP file.

Each flow is identified by a 5-tuple: (src_ip, dst_ip, src_port, dst_port, proto).
Returns a list of feature dicts compatible with the Isolation Forest model.

Feature columns (must match training order in train_ai_model.py):
  packet_count, total_bytes, duration_sec, packets_per_sec,
  bytes_per_sec, mean_packet_size, variance_packet_size, stddev_packet_size
"""

import math
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP


def extract_features(pcap_file: str) -> list:
    """
    Read a PCAP file and return a list of per-flow feature dicts.

    Each dict contains:
      src_ip, dst_ip, src_port, dst_port, protocol,
      packet_count, total_bytes, duration_sec,
      packets_per_sec, bytes_per_sec,
      mean_packet_size, variance_packet_size, stddev_packet_size
    """
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP {pcap_file}: {e}")
        return []

    # Flow accumulator: key -> {sizes: [], timestamps: []}
    flows = defaultdict(lambda: {"sizes": [], "timestamps": []})

    for pkt in packets:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.proto
        src_port = None
        dst_port = None

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        key = (src_ip, dst_ip, src_port, dst_port, proto)
        ts = float(pkt.time)
        size = len(pkt)

        flows[key]["sizes"].append(size)
        flows[key]["timestamps"].append(ts)

    features = []
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}

    for (src_ip, dst_ip, src_port, dst_port, proto_num), data in flows.items():
        sizes = data["sizes"]
        timestamps = data["timestamps"]
        n = len(sizes)

        if n == 0:
            continue

        total_bytes = sum(sizes)
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration_sec = max(end_time - start_time, 1e-6)  # avoid division by zero

        packets_per_sec = n / duration_sec
        bytes_per_sec = total_bytes / duration_sec
        mean_size = total_bytes / n

        # Variance and stddev of packet sizes
        if n > 1:
            variance = sum((s - mean_size) ** 2 for s in sizes) / n
        else:
            variance = 0.0
        stddev = math.sqrt(variance)

        features.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_map.get(proto_num, str(proto_num)),
            "packet_count": n,
            "total_bytes": total_bytes,
            "duration_sec": duration_sec,
            "packets_per_sec": packets_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "mean_packet_size": mean_size,
            "variance_packet_size": variance,
            "stddev_packet_size": stddev,
        })

    return features


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python feature_extractor.py <pcap_file>")
        sys.exit(1)

    feats = extract_features(sys.argv[1])
    print(f"Extracted {len(feats)} flows.")
    if feats:
        print(json.dumps(feats[:3], indent=2))
