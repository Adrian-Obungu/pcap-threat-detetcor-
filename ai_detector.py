#!/usr/bin/env python3
"""
ai_detector.py – Load trained Isolation Forest and score flows from PCAP.
Usage: python ai_detector.py <pcap_file>
"""

import argparse
import json
import joblib
from feature_extractor import extract_features

def main():
    parser = argparse.ArgumentParser(description='AI anomaly detection on PCAP flows')
    parser.add_argument('pcap_file', help='Path to PCAP file')
    args = parser.parse_args()
    # Load model
    model = joblib.load('models/anomaly_model.pkl')
    # Extract features (list of dicts)
    features_list = extract_features(args.pcap_file)
    if not features_list:
        print("No flows found.")
        return
    # Convert to array (order must match training columns)
    # Use same column order as in training: packet_count, total_bytes, duration_sec, packets_per_sec, bytes_per_sec, mean_packet_size, variance_packet_size, stddev_packet_size
    X = []
    for f in features_list:
        X.append([
            f['packet_count'],
            f['total_bytes'],
            f['duration_sec'],
            f['packets_per_sec'],
            f['bytes_per_sec'],
            f['mean_packet_size'],
            f['variance_packet_size'],
            f['stddev_packet_size']
        ])
    scores = model.decision_function(X)
    predictions = model.predict(X)  # -1 = anomaly, 1 = normal
    for i, f in enumerate(features_list):
        status = "ANOMALY" if predictions[i] == -1 else "normal"
        print(f"Flow {i+1}: {f['src_ip']} -> {f['dst_ip']} ({f['protocol']}) | Score: {scores[i]:.4f} | {status}")

if __name__ == '__main__':
    main()
