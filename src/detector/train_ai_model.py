#!/usr/bin/env python3
"""
train_ai_model.py – Train Isolation Forest on real benign flow features (CSV).
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os
import sys

def main():
    csv_file = "benign_features.csv"
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found. Run feature_extractor first.")
        sys.exit(1)

    print(f"Loading features from {csv_file}...")
    df = pd.read_csv(csv_file)
    print(f"Loaded {len(df)} flows.")

    # Use only numeric columns for training (exclude src_ip, dst_ip, protocol, ports)
    feature_cols = ['packet_count', 'total_bytes', 'duration_sec', 'packets_per_sec',
                    'bytes_per_sec', 'mean_packet_size', 'variance_packet_size', 'stddev_packet_size']
    X = df[feature_cols]

    # Train Isolation Forest
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(X)

    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/anomaly_model.pkl')
    print("Model saved to models/anomaly_model.pkl")

if __name__ == '__main__':
    main()
