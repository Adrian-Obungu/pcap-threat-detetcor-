#!/usr/bin/env python3
"""
pcap-threat-detector – Enhanced Network PCAP Analyzer
Detects ARP spoofing, port scans, DNS tunneling, and data exfiltration.
"""

import argparse
import ipaddress
import json
import math
import re
from collections import defaultdict, deque, Counter
from scapy.all import rdpcap, ARP, IP, TCP, UDP, ICMP, DNS, PcapReader
from scapy.error import Scapy_Exception
import sys
import joblib
import numpy as np

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    for count in freq.values():
        p = count / len(s)
        ent -= p * math.log2(p)
    return ent


def load_whitelist(filepath):
    """Load whitelist from file. Each line: ip:mac for ARP, ip for port scan, domain for DNS, or ip:port:proto for exfil."""
    whitelist = set()
    if not filepath:
        return whitelist
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    whitelist.add(line)
    except FileNotFoundError:
        print(f"Warning: Whitelist file {filepath} not found.", file=sys.stderr)
    return whitelist


def load_internal_subnets(filepath):
    """Load internal subnets from file (CIDR notation)."""
    subnets = []
    if not filepath:
        return subnets
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        subnets.append(ipaddress.ip_network(line))
                    except ValueError as e:
                        print(f"Warning: Invalid subnet {line}: {e}", file=sys.stderr)
    except FileNotFoundError:
        print(f"Warning: Internal subnets file {filepath} not found.", file=sys.stderr)
    return subnets


def is_internal(ip, internal_nets):
    """Check if IP belongs to any internal subnet."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in internal_nets:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return False


# ----------------------------------------------------------------------
# Detection functions (enhanced)
# ----------------------------------------------------------------------
def detect_arp_spoofing(packets, aging_sec=300, change_window_sec=60,
                        flap_threshold=3, whitelist=None):
    """Enhanced ARP spoofing detection with time-based aging and flapping."""
    ip_history = defaultdict(list)   # ip -> deque of (mac, timestamp)
    alerts = []
    reported = set()

    whitelist_set = set()
    if whitelist:
        whitelist_set = {f"{line.split(':')[0]}:{line.split(':')[1]}" for line in whitelist if ':' in line}

    for pkt in packets:
        if ARP not in pkt:
            continue
        # Handle malformed packets
        try:
            op = pkt[ARP].op
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ts = float(pkt.time)
        except (AttributeError, IndexError):
            continue

        # Check Ethernet vs ARP MAC
        eth_src = pkt.src
        if eth_src != mac:
            key = (ip, mac, 'eth-mismatch')
            if key not in reported:
                alerts.append({
                    'type': 'ARP Spoofing',
                    'description': f'Ethernet src {eth_src} != ARP sender MAC {mac} for IP {ip}',
                    'time': ts
                })
                reported.add(key)
            continue

        # Skip whitelisted pairs
        pair = f"{ip}:{mac}"
        if pair in whitelist_set:
            continue

        # Clean expired entries
        current = [(m, t) for (m, t) in ip_history[ip] if ts - t <= aging_sec]
        ip_history[ip] = current

        # Check for existing MAC
        existing = next(((m, t) for (m, t) in ip_history[ip] if m == mac), None)
        if existing:
            # Update timestamp
            ip_history[ip] = [(m, ts) if m == mac else (m, t) for (m, t) in ip_history[ip]]
            continue

        # New MAC for this IP
        ip_history[ip].append((mac, ts))

        # If there is a previous MAC, check time difference
        if len(ip_history[ip]) >= 2:
            last_mac, last_time = ip_history[ip][-2]
            time_diff = ts - last_time
            if time_diff <= change_window_sec:
                # Rapid change – suspicious
                key = (ip, mac, 'rapid-change')
                if key not in reported:
                    alerts.append({
                        'type': 'ARP Spoofing',
                        'description': f'IP {ip} changed MAC from {last_mac} to {mac} in {time_diff:.2f}s',
                        'time': ts
                    })
                    reported.add(key)

        # Flapping detection
        if len(ip_history[ip]) > flap_threshold:
            key = (ip, 'flap')
            if key not in reported:
                alerts.append({
                    'type': 'ARP Spoofing',
                    'description': f'IP {ip} flapped MAC {len(ip_history[ip])} times in {aging_sec}s',
                    'time': ts
                })
                reported.add(key)
                # Reset history to avoid repeated alerts
                ip_history[ip] = [(mac, ts)]

    return alerts


def detect_port_scan(packets, window_sec=1, threshold=20, whitelist=None):
    """Enhanced port scan detection with sliding window O(n)."""
    # Group by (src_ip, dst_ip) to detect scans on single host
    scan_flows = defaultdict(list)  # (src, dst) -> list of (timestamp, dport)
    alerts = []
    reported = set()

    whitelist_set = set()
    if whitelist:
        whitelist_set = {line for line in whitelist if ':' not in line}  # simple IP whitelist

    # First pass: collect SYN packets
    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        # SYN flag set (0x02) – optionally also include SYN-ACK (0x12)
        tcp_flags = pkt[TCP].flags
        if not (tcp_flags & 0x02):
            continue
        # Skip packets with ACK (i.e., SYN-ACK) if you want only pure SYNs, but we'll keep them for now
        src = pkt[IP].src
        dst = pkt[IP].dst
        if src in whitelist_set:
            continue
        dport = pkt[TCP].dport
        ts = float(pkt.time)
        key = (src, dst)
        scan_flows[key].append((ts, dport))

    # Second pass: sliding window per (src, dst)
    for (src, dst), packets_list in scan_flows.items():
        # Packets should be in order; if not, sort (though expensive)
        if any(packets_list[i][0] > packets_list[i+1][0] for i in range(len(packets_list)-1)):
            packets_list.sort(key=lambda x: x[0])

        window = deque()
        ports = set()
        for ts, dport in packets_list:
            window.append((ts, dport))
            ports.add(dport)

            # Remove old packets outside window
            while window and window[0][0] < ts - window_sec:
                old_ts, old_dport = window.popleft()
                if old_dport not in [p[1] for p in window]:
                    ports.discard(old_dport)

            if len(ports) >= threshold:
                key = (src, dst, 'scan')
                if key not in reported:
                    alerts.append({
                        'type': 'Port Scan',
                        'description': f'Source IP {src} contacted {len(ports)} distinct ports to {dst} in {window_sec}s',
                        'time': ts
                    })
                    reported.add(key)
                    # Optionally clear window to avoid repeated alerts for same burst
                    window.clear()
                    ports.clear()

    return alerts


def detect_dns_tunneling(packets, len_threshold=30, window_sec=10, freq_threshold=20,
                         entropy_threshold=4.5, whitelist=None):
    """Enhanced DNS tunneling detection with sliding window frequency and entropy."""
    alerts = []
    reported = set()

    whitelist_set = set()
    if whitelist:
        whitelist_set = {line for line in whitelist if line}  # domain whitelist

    # Store queries per (src_ip, domain) for sliding window
    query_queues = defaultdict(deque)  # (src, domain) -> deque of timestamps
    # Also store for response size (optional)
    # response_sizes = defaultdict(list)  # (src, domain) -> list of (ts, size)

    for pkt in packets:
        if DNS not in pkt:
            continue
        # Extract query or response
        if pkt[DNS].qr == 0:  # query
            try:
                domain = pkt[DNS].qd.qname.decode().rstrip('.').lower()
            except (AttributeError, IndexError):
                continue

            src = pkt[IP].src if IP in pkt else None
            if not src:
                continue

            # Whitelist
            if domain in whitelist_set:
                continue

            ts = float(pkt.time)

            # 1. Long domain detection (without break)
            subdomain = '.'.join(domain.split('.')[:-1]) if '.' in domain else domain
            if len(subdomain) > len_threshold:
                key = (src, domain, 'long')
                if key not in reported:
                    alerts.append({
                        'type': 'DNS Tunneling',
                        'description': f'Long subdomain ({len(subdomain)} chars): {domain}',
                        'time': ts
                    })
                    reported.add(key)

            # 2. Entropy detection
            if subdomain and shannon_entropy(subdomain) > entropy_threshold:
                key = (src, domain, 'entropy')
                if key not in reported:
                    alerts.append({
                        'type': 'DNS Tunneling',
                        'description': f'High entropy ({shannon_entropy(subdomain):.2f}) in {domain}',
                        'time': ts
                    })
                    reported.add(key)

            # 3. Character set detection (base64-like)
            if re.match(r'^[A-Za-z0-9+/=]+$', subdomain):
                key = (src, domain, 'base64')
                if key not in reported:
                    alerts.append({
                        'type': 'DNS Tunneling',
                        'description': f'Base64-like pattern in {domain}',
                        'time': ts
                    })
                    reported.add(key)

            # 4. Frequency sliding window
            key = (src, domain)
            dq = query_queues[key]
            dq.append(ts)
            # Remove old timestamps
            while dq and dq[0] < ts - window_sec:
                dq.popleft()
            if len(dq) >= freq_threshold:
                key_alert = (src, domain, 'freq')
                if key_alert not in reported:
                    alerts.append({
                        'type': 'DNS Tunneling',
                        'description': f'High query frequency ({len(dq)} queries) to {domain} from {src} in {window_sec}s',
                        'time': ts
                    })
                    reported.add(key_alert)
                    # Clear to avoid repeated alerts for same burst
                    dq.clear()

        # Optional: response size analysis
        # else: response – could track large TXT records
        # (omitted for brevity, but can be added)

    return alerts


def detect_data_exfiltration(packets, payload_threshold=1000, flow_window_sec=60,
                             flow_bytes_threshold=1_000_000, internal_subnets=None,
                             entropy_threshold=None, whitelist=None):
    """Enhanced data exfiltration detection with flow-based cumulative tracking."""
    alerts = []
    reported = set()

    whitelist_set = set()
    if whitelist:
        whitelist_set = whitelist  # expects entries like "192.168.1.1:443:tcp"

    # Flow tracking: (src, dst, proto) -> deque of (ts, bytes)
    flow_queues = defaultdict(deque)

    for pkt in packets:
        if IP not in pkt:
            continue
        src = pkt[IP].src
        dst = pkt[IP].dst
        ts = float(pkt.time)

        # Determine protocol and payload size
        proto = None
        payload_len = 0
        if TCP in pkt:
            proto = 'tcp'
            payload_len = len(pkt[TCP].payload) if pkt[TCP].payload else 0
        elif UDP in pkt:
            proto = 'udp'
            payload_len = len(pkt[UDP].payload) if pkt[UDP].payload else 0
        elif ICMP in pkt:
            proto = 'icmp'
            # Filter ICMP types: Echo Request (8), Timestamp (13), Address Mask Request (17)
            icmp_type = pkt[ICMP].type
            if icmp_type not in [8, 13, 17]:
                continue
            payload_len = len(pkt[ICMP].payload) if pkt[ICMP].payload else 0

        if not proto:
            continue

        # Direction check: only outbound traffic if internal subnets provided
        if internal_subnets:
            src_internal = is_internal(src, internal_subnets)
            dst_internal = is_internal(dst, internal_subnets)
            is_outbound = src_internal and not dst_internal
            if not is_outbound:
                continue

        # Whitelist check (simple: IP:port:proto)
        whitelist_key = f"{src}:{dst}:{proto}"
        if whitelist_key in whitelist_set:
            continue

        # Single-packet large payload
        if payload_len > payload_threshold:
            key = (src, dst, proto, 'single')
            if key not in reported:
                alerts.append({
                    'type': 'Data Exfiltration',
                    'description': f'Large {proto} packet of {payload_len} bytes from {src} to {dst}',
                    'time': ts
                })
                reported.add(key)

        # Flow-based cumulative tracking
        flow_key = (src, dst, proto)
        dq = flow_queues[flow_key]
        dq.append((ts, payload_len))

        # Remove old entries
        while dq and dq[0][0] < ts - flow_window_sec:
            dq.popleft()

        total_bytes = sum(entry[1] for entry in dq)
        if total_bytes > flow_bytes_threshold:
            key = (src, dst, proto, 'flow')
            if key not in reported:
                alerts.append({
                    'type': 'Data Exfiltration',
                    'description': f'High {proto} flow: {total_bytes} bytes from {src} to {dst} in {flow_window_sec}s',
                    'time': ts
                })
                reported.add(key)
                # Optionally clear the queue to avoid repeated alerts for same flow
                dq.clear()

        # Optional: entropy analysis on payload
        if entropy_threshold and payload_len > 100:  # only if significant payload
            try:
                payload = bytes(pkt[proto].payload) if pkt[proto].payload else b''
                if payload:
                    ent = shannon_entropy(payload)
                    if ent > entropy_threshold:
                        key = (src, dst, proto, 'entropy')
                        if key not in reported:
                            alerts.append({
                                'type': 'Data Exfiltration',
                                'description': f'High entropy ({ent:.2f}) {proto} payload from {src} to {dst}',
                                'time': ts
                            })
                            reported.add(key)
            except Exception:
                pass

    return alerts


# ----------------------------------------------------------------------
# Main processing
# ----------------------------------------------------------------------
def process_pcap(filepath, args):
    """Stream PCAP and run detectors, returning aggregated alerts."""
    alerts = []
    try:
        packets = rdpcap(filepath)  # loads all into memory; could also use PcapReader for streaming
        # (For large files, we could use PcapReader and pass generator to detectors, but many detectors need full packet list)
        # For simplicity we load all. For memory efficiency, consider using PcapReader and storing only necessary info.
        # We'll leave as is for now.
    except Exception as e:
        print(f"Error reading PCAP: {e}", file=sys.stderr)
        return []

    # Load whitelist and internal subnets if provided
    whitelist = None
    if args.whitelist:
        whitelist = load_whitelist(args.whitelist)
    internal_nets = None
    if args.internal_subnets:
        internal_nets = load_internal_subnets(args.internal_subnets)

    # Run detectors
    alerts.extend(detect_arp_spoofing(packets,
                                      aging_sec=args.arp_aging_sec,
                                      change_window_sec=args.arp_change_window_sec,
                                      flap_threshold=args.arp_flap_threshold,
                                      whitelist=whitelist))

    alerts.extend(detect_port_scan(packets,
                                   window_sec=args.port_window_sec,
                                   threshold=args.port_threshold,
                                   whitelist=whitelist))

    alerts.extend(detect_dns_tunneling(packets,
                                       len_threshold=args.dns_len_threshold,
                                       window_sec=args.dns_window_sec,
                                       freq_threshold=args.dns_freq_threshold,
                                       entropy_threshold=args.dns_entropy_threshold,
                                       whitelist=whitelist))

    alerts.extend(detect_data_exfiltration(packets,
                                           payload_threshold=args.exfil_payload_threshold,
                                           flow_window_sec=args.exfil_flow_window_sec,
                                           flow_bytes_threshold=args.exfil_flow_bytes_threshold,
                                           internal_subnets=internal_nets,
                                           entropy_threshold=args.exfil_entropy_threshold,
                                           whitelist=whitelist))

    return alerts


def main():
    parser = argparse.ArgumentParser(description='Enhanced PCAP threat detector')
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--whitelist', help='Whitelist file (format depends on detector)')
    parser.add_argument('--internal-subnets', help='File with CIDR subnets for internal networks')

    # ARP detection parameters
    parser.add_argument('--arp-aging-sec', type=int, default=300, help='ARP aging window (seconds)')
    parser.add_argument('--arp-change-window-sec', type=int, default=60, help='Time window for rapid MAC change')
    parser.add_argument('--arp-flap-threshold', type=int, default=3, help='Flapping MAC count threshold')

    # Port scan detection parameters
    parser.add_argument('--port-window-sec', type=int, default=1, help='Port scan time window (seconds)')
    parser.add_argument('--port-threshold', type=int, default=20, help='Number of distinct ports in window to alert')

    # DNS detection parameters
    parser.add_argument('--dns-len-threshold', type=int, default=30, help='Subdomain length threshold')
    parser.add_argument('--dns-window-sec', type=int, default=10, help='DNS frequency time window')
    parser.add_argument('--dns-freq-threshold', type=int, default=20, help='DNS query frequency threshold')
    parser.add_argument('--dns-entropy-threshold', type=float, default=4.5, help='Shannon entropy threshold')

    # Exfiltration detection parameters
    parser.add_argument('--exfil-payload-threshold', type=int, default=1000, help='Single packet payload size threshold')
    parser.add_argument('--exfil-flow-window-sec', type=int, default=60, help='Flow time window for cumulative bytes')
    parser.add_argument('--exfil-flow-bytes-threshold', type=int, default=1_000_000, help='Cumulative bytes threshold')
    parser.add_argument('--exfil-entropy-threshold', type=float, default=None, help='Payload entropy threshold (optional)')

    args = parser.parse_args()

    alerts = process_pcap(args.pcap_file, args)

    if args.json:
        print(json.dumps(alerts, indent=2))
    else:
        print(f"[+] Total alerts: {len(alerts)}")
        for alert in alerts:
            print(f"[!] {alert['type']}: {alert['description']} (time: {alert['time']})")


if __name__ == '__main__':
    main()