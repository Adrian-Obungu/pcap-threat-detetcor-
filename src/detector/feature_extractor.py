#!/usr/bin/env python3
"""
ai_runner.py – Combined rule‑based and AI anomaly detection.
Usage: python ai_runner.py <pcap_file> [--ai]
"""

import argparse
import subprocess
import json
import sys
import os
from feature_extractor import extract_features
import joblib

def run_rule_detector(pcap_file):
    """Run the original detector.py and return its alerts as a list."""
    # Use subprocess to capture JSON output
    result = subprocess.run(
        ['python', 'detector.py', pcap_file, '--json'],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Rule detector error: {result.stderr}", file=sys.stderr)
        return []
    try:
        alerts = json.loads(result.stdout)
        return alerts
    except json.JSONDecodeError:
        return []

def run_ai_detector(pcap_file):
    """Load AI model and return anomaly alerts."""
    model_path = 'models/anomaly_model.pkl'
    if not os.path.exists(model_path):
        print("AI model not found. Train it first with python train_ai_model.py", file=sys.stderr)
        return []
    model = joblib.load(model_path)
    features_list = extract_features(pcap_file)
    if not features_list:
        return []
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
    predictions = model.predict(X)  # -1 = anomaly
    ai_alerts = []
    for i, pred in enumerate(predictions):
        if pred == -1:
            f = features_list[i]
            ai_alerts.append({
                'type': 'AI Anomaly',
                'description': f"Flow {f['src_ip']} -> {f['dst_ip']} ({f['protocol']}) | Score: {scores[i]:.4f}",
                'time': None
            })
    return ai_alerts

def main():
    parser = argparse.ArgumentParser(description='Hybrid threat detector (rules + AI)')
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('--ai', action='store_true', help='Enable AI anomaly detection')
    args = parser.parse_args()
    alerts = []
    # Always run rule detector
    alerts.extend(run_rule_detector(args.pcap_file))
    if args.ai:
        alerts.extend(run_ai_detector(args.pcap_file))
    # Output
    print(f"[+] Total alerts: {len(alerts)}")
    for alert in alerts:
        time_str = f" (time: {alert['time']})" if alert['time'] else ""
        print(f"[!] {alert['type']}: {alert['description']}{time_str}")

if __name__ == '__main__':
    main()
