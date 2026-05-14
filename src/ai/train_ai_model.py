#!/usr/bin/env python3
"""
train_ai_model.py – Train an Isolation Forest on synthetic normal flow data.
Saves model to 'models/anomaly_model.pkl'.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

def generate_normal_flows(n=1000):
    """Generate synthetic flow features that mimic normal traffic."""
    np.random.seed(42)
    # Normal flow characteristics:
    # - packet_count: 1-50
    # - total_bytes: 60-5000
    # - duration_sec: 0.001 - 5.0
    # - packets_per_sec: 10 - 1000
    # - bytes_per_sec: 100 - 50000
    # - mean_packet_size: 60 - 1500
    # - variance_packet_size: 0 - 2000
    # - stddev_packet_size: 0 - 45
    data = []
    for _ in range(n):
        packet_count = np.random.randint(1, 50)
        total_bytes = np.random.randint(60, 5000)
        duration = np.random.uniform(0.001, 5.0)
        packets_per_sec = packet_count / duration
        bytes_per_sec = total_bytes / duration
        mean_packet_size = total_bytes / packet_count
        variance = np.random.uniform(0, 2000)
        stddev = np.sqrt(variance)
        data.append([
            packet_count, total_bytes, duration,
            packets_per_sec, bytes_per_sec,
            mean_packet_size, variance, stddev
        ])
    columns = [
        'packet_count', 'total_bytes', 'duration_sec',
        'packets_per_sec', 'bytes_per_sec',
        'mean_packet_size', 'variance_packet_size', 'stddev_packet_size'
    ]
    return pd.DataFrame(data, columns=columns)

def main():
    print("Generating synthetic normal flows...")
    df = generate_normal_flows(2000)
    print(f"Generated {len(df)} flows.")
    # Isolation Forest
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(df)
    # Create models directory if not exists
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/anomaly_model.pkl')
    print("Model saved to models/anomaly_model.pkl")
    # Test on a known anomaly (exfiltration-like)
    # We'll test later in detector.py

if __name__ == '__main__':
    main()
