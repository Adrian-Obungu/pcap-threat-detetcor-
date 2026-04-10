#!/usr/bin/env python3
"""
feature_extractor.py – Compute statistical features from PCAP flows.
Usage: python feature_extractor.py <pcap_file> [--csv] [--output <file>]
"""

import argparse
import json
import csv
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP
import statistics

def packet_to_flow_key(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    proto = ip.proto
    src = ip.src
    dst = ip.dst
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        proto_name = "tcp"
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        proto_name = "udp"
    else:
        sport = None
        dport = None
        proto_name = "other"
    return (src, dst, sport, dport, proto, proto_name)

def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    # We'll collect all packet sizes per flow to compute variance
    flows = defaultdict(lambda: {
        'packet_sizes': [],
        'start_time': None,
        'end_time': None,
        'proto_name': None,
        'src': None,
        'dst': None,
        'sport': None,
        'dport': None
    })
    for pkt in packets:
        key = packet_to_flow_key(pkt)
        if not key:
            continue
        src, dst, sport, dport, proto, proto_name = key
        ts = float(pkt.time)
        size = len(pkt)
        flow = flows[key]
        if flow['start_time'] is None or ts < flow['start_time']:
            flow['start_time'] = ts
        if flow['end_time'] is None or ts > flow['end_time']:
            flow['end_time'] = ts
        flow['packet_sizes'].append(size)
        flow['proto_name'] = proto_name
        flow['src'] = src
        flow['dst'] = dst
        flow['sport'] = sport
        flow['dport'] = dport

    # Compute aggregate features
    features_list = []
    for key, flow in flows.items():
        sizes = flow['packet_sizes']
        count = len(sizes)
        if count == 0:
            continue
        total_bytes = sum(sizes)
        duration = flow['end_time'] - flow['start_time']
        if duration <= 0:
            duration = 0.000001  # avoid division by zero
        mean_size = total_bytes / count
        # Use sample variance if more than 1 packet, else 0
        if count > 1:
            variance = statistics.variance(sizes)
            stdev = statistics.stdev(sizes)
        else:
            variance = 0.0
            stdev = 0.0
        features = {
            'src_ip': flow['src'],
            'dst_ip': flow['dst'],
            'protocol': flow['proto_name'],
            'src_port': flow['sport'] if flow['sport'] else 0,
            'dst_port': flow['dport'] if flow['dport'] else 0,
            'packet_count': count,
            'total_bytes': total_bytes,
            'duration_sec': duration,
            'packets_per_sec': count / duration,
            'bytes_per_sec': total_bytes / duration,
            'mean_packet_size': mean_size,
            'variance_packet_size': variance,
            'stddev_packet_size': stdev,
        }
        features_list.append(features)
    return features_list

def main():
    parser = argparse.ArgumentParser(description='Extract flow features from PCAP')
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('--csv', action='store_true', help='Output as CSV')
    parser.add_argument('--output', help='Output file (default: stdout)')
    args = parser.parse_args()
    features = extract_features(args.pcap_file)
    if args.csv:
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=features[0].keys())
        writer.writeheader()
        writer.writerows(features)
        content = output.getvalue()
    else:
        content = json.dumps(features, indent=2)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(content)
    else:
        print(content)

if __name__ == '__main__':
    main()
