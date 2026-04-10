#!/usr/bin/env python3
"""
flow_analyzer.py – Aggregate packets into flows and compute basic metrics.
Usage: python flow_analyzer.py <pcap_file> [--output <file>]
"""

import argparse
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import json

def packet_to_flow_key(pkt):
    """Extract 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)."""
    if IP not in pkt:
        return None
    ip = pkt[IP]
    proto = ip.proto
    src = ip.src
    dst = ip.dst
    src_port = None
    dst_port = None
    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    # For non-TCP/UDP (e.g., ICMP), ports remain None
    return (src, dst, src_port, dst_port, proto)

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    flows = defaultdict(lambda: {
        'packet_count': 0,
        'byte_count': 0,
        'start_time': None,
        'end_time': None
    })
    for pkt in packets:
        key = packet_to_flow_key(pkt)
        if not key:
            continue
        ts = float(pkt.time)          # Convert EDecimal to float
        size = len(pkt)
        flow = flows[key]
        flow['packet_count'] += 1
        flow['byte_count'] += size
        if flow['start_time'] is None or ts < flow['start_time']:
            flow['start_time'] = ts
        if flow['end_time'] is None or ts > flow['end_time']:
            flow['end_time'] = ts
    return flows

def main():
    parser = argparse.ArgumentParser(description='Extract flow metrics from PCAP')
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('--output', help='Output JSON file (default: stdout)')
    args = parser.parse_args()
    flows = analyze_pcap(args.pcap_file)
    # Convert keys to strings for JSON; also ensure any None values remain None (they are fine)
    output = {str(k): v for k, v in flows.items()}
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
    else:
        print(json.dumps(output, indent=2))

if __name__ == '__main__':
    main()
