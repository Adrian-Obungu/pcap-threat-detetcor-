#!/usr/bin/env python3
"""
pcap-threat-detector – Enhanced Network PCAP Analyzer
Detects ARP spoofing, port scans, DNS tunneling, data exfiltration, beaconing, and UA spoofing.
"""

import argparse
import ipaddress
import json
import math
import re
import sys
from collections import defaultdict, deque, Counter
from scapy.all import rdpcap, ARP, IP, TCP, UDP, ICMP, DNS, PcapReader
from scapy.error import Scapy_Exception

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    ent = 0.0
    for count in freq.values():
        p = count / len(s)
        ent -= p * math.log2(p)
    return ent

def get_ngrams(s, n=3):
    """Generate n-grams from a string."""
    return [s[i:i+n] for i in range(len(s)-n+1)]

def load_whitelist(filepath):
    """Load whitelist from file."""
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
        pass
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
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
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
# Detection functions
# ----------------------------------------------------------------------

def detect_arp_spoofing(packets, aging_sec=300, change_window_sec=60, flap_threshold=3, whitelist=None):
    """Enhanced ARP spoofing detection."""
    ip_history = defaultdict(list)
    alerts = []
    reported = set()
    whitelist_set = {f"{line.split(':')[0]}:{line.split(':')[1]}" for line in whitelist if ':' in line} if whitelist else set()

    for pkt in packets:
        if ARP not in pkt: continue
        try:
            ip, mac, ts = pkt[ARP].psrc, pkt[ARP].hwsrc, float(pkt.time)
        except: continue

        if pkt.src != mac:
            key = (ip, mac, 'eth-mismatch')
            if key not in reported:
                alerts.append({'type': 'ARP Spoofing', 'description': f'Ethernet src {pkt.src} != ARP sender MAC {mac} for IP {ip}', 'time': ts, 'severity': 'HIGH'})
                reported.add(key)
            continue

        if f"{ip}:{mac}" in whitelist_set: continue

        ip_history[ip] = [(m, t) for (m, t) in ip_history[ip] if ts - t <= aging_sec]
        existing = next(((m, t) for (m, t) in ip_history[ip] if m == mac), None)
        if existing:
            ip_history[ip] = [(m, ts) if m == mac else (m, t) for (m, t) in ip_history[ip]]
            continue

        ip_history[ip].append((mac, ts))
        if len(ip_history[ip]) >= 2:
            last_mac, last_time = ip_history[ip][-2]
            if ts - last_time <= change_window_sec:
                key = (ip, mac, 'rapid-change')
                if key not in reported:
                    alerts.append({'type': 'ARP Spoofing', 'description': f'IP {ip} changed MAC from {last_mac} to {mac} in {ts-last_time:.2f}s', 'time': ts, 'severity': 'HIGH'})
                    reported.add(key)

        if len(ip_history[ip]) > flap_threshold:
            key = (ip, 'flap')
            if key not in reported:
                alerts.append({'type': 'ARP Spoofing', 'description': f'IP {ip} flapped MAC {len(ip_history[ip])} times', 'time': ts, 'severity': 'CRITICAL'})
                reported.add(key)
                ip_history[ip] = [(mac, ts)]
    return alerts

def detect_port_scan(packets, window_sec=1, threshold=20, whitelist=None):
    """Enhanced port scan detection."""
    scan_flows = defaultdict(list)
    alerts = []
    reported = set()
    whitelist_set = {line for line in whitelist if ':' not in line} if whitelist else set()

    for pkt in packets:
        if IP not in pkt or TCP not in pkt: continue
        if not (pkt[TCP].flags & 0x02): continue
        src, dst, ts = pkt[IP].src, pkt[IP].dst, float(pkt.time)
        if src in whitelist_set: continue
        scan_flows[(src, dst)].append((ts, pkt[TCP].dport))

    for (src, dst), p_list in scan_flows.items():
        p_list.sort()
        window = deque()
        ports = set()
        for ts, dport in p_list:
            window.append((ts, dport))
            ports.add(dport)
            while window and window[0][0] < ts - window_sec:
                old_ts, old_dport = window.popleft()
                if old_dport not in [p[1] for p in window]: ports.discard(old_dport)
            if len(ports) >= threshold:
                key = (src, dst, 'scan')
                if key not in reported:
                    alerts.append({'type': 'Port Scan', 'description': f'Source {src} scanned {len(ports)} ports on {dst}', 'time': ts, 'severity': 'MEDIUM'})
                    reported.add(key)
                    window.clear(); ports.clear()
    return alerts

def detect_dns_tunneling(packets, len_threshold=30, entropy_threshold=4.5, whitelist=None):
    """Advanced DNS Tunneling & DGA Detection."""
    alerts = []
    reported = set()
    whitelist_set = set(whitelist) if whitelist else set()

    for pkt in packets:
        if DNS not in pkt or pkt[DNS].qr != 0: continue
        try:
            domain = pkt[DNS].qd.qname.decode().rstrip('.').lower()
            src, ts = pkt[IP].src, float(pkt.time)
        except: continue

        if domain in whitelist_set: continue
        subdomain = '.'.join(domain.split('.')[:-1]) if '.' in domain else domain
        
        # 1. Entropy & Length
        ent = shannon_entropy(subdomain)
        if len(subdomain) > len_threshold or ent > entropy_threshold:
            key = (src, domain, 'dns-anomaly')
            if key not in reported:
                desc = f"DNS Anomaly: {domain} (Len: {len(subdomain)}, Entropy: {ent:.2f})"
                alerts.append({'type': 'DNS Tunneling', 'description': desc, 'time': ts, 'severity': 'HIGH'})
                reported.add(key)

        # 2. DGA-like Character Distribution
        if len(subdomain) > 10:
            digits = sum(c.isdigit() for c in subdomain)
            if digits / len(subdomain) > 0.3:
                key = (src, domain, 'dga-digits')
                if key not in reported:
                    alerts.append({'type': 'DGA Detection', 'description': f"High digit ratio in domain: {domain}", 'time': ts, 'severity': 'MEDIUM'})
                    reported.add(key)
    return alerts

def detect_beaconing(packets, window_sec=60, min_count=5, max_jitter=0.2):
    """Behavioral Beaconing Detection (C2 Heartbeats)."""
    flows = defaultdict(list)
    alerts = []
    reported = set()

    for pkt in packets:
        if IP not in pkt: continue
        proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else None
        if not proto: continue
        src, dst, ts = pkt[IP].src, pkt[IP].dst, float(pkt.time)
        dport = pkt[proto].dport
        flows[(src, dst, dport, proto)].append(ts)

    for flow_key, timestamps in flows.items():
        if len(timestamps) < min_count: continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < 0.1: continue # Ignore high-speed flows
        
        jitter = sum(abs(i - avg_interval) for i in intervals) / len(intervals)
        if jitter / avg_interval <= max_jitter:
            src, dst, dport, proto = flow_key
            key = (src, dst, dport, 'beacon')
            if key not in reported:
                alerts.append({
                    'type': 'Beaconing',
                    'description': f'C2 Beacon detected: {src} -> {dst}:{dport} ({proto}) every {avg_interval:.2f}s (Jitter: {jitter/avg_interval:.2%})',
                    'time': timestamps[-1],
                    'severity': 'CRITICAL'
                })
                reported.add(key)
    return alerts

def detect_user_agent_spoofing(packets):
    """Protocol-Specific Deep Inspection: UA Spoofing."""
    alerts = []
    reported = set()
    suspicious_uas = ['sqlmap', 'nmap', 'nikto', 'gobuster', 'python-requests/2.']

    for pkt in packets:
        if TCP not in pkt or pkt[TCP].dport != 80: continue
        try:
            payload = bytes(pkt[TCP].payload).decode('utf-8', errors='ignore')
            if 'User-Agent:' in payload:
                ua_line = [l for l in payload.split('\r\n') if 'User-Agent:' in l][0]
                ua = ua_line.split(':', 1)[1].strip()
                src, ts = pkt[IP].src, float(pkt.time)
                
                for suspect in suspicious_uas:
                    if suspect.lower() in ua.lower():
                        key = (src, suspect, 'ua-spoof')
                        if key not in reported:
                            alerts.append({'type': 'UA Spoofing', 'description': f'Suspicious User-Agent from {src}: {ua}', 'time': ts, 'severity': 'HIGH'})
                            reported.add(key)
        except: continue
    return alerts

def detect_data_exfiltration(packets, threshold=1_000_000, internal_nets=None):
    """Flow-based Data Exfiltration Detection."""
    flows = defaultdict(int)
    alerts = []
    reported = set()

    for pkt in packets:
        if IP not in pkt: continue
        src, dst, ts = pkt[IP].src, pkt[IP].dst, float(pkt.time)
        if internal_nets and (not is_internal(src, internal_nets) or is_internal(dst, internal_nets)): continue
        
        size = len(pkt)
        flows[(src, dst)] += size
        if flows[(src, dst)] > threshold:
            key = (src, dst, 'exfil')
            if key not in reported:
                alerts.append({'type': 'Data Exfiltration', 'description': f'High volume flow: {src} -> {dst} ({flows[(src, dst)]/1e6:.2f} MB)', 'time': ts, 'severity': 'CRITICAL'})
                reported.add(key)
    return alerts

# ----------------------------------------------------------------------
# Main Execution
# ----------------------------------------------------------------------
def process_pcap(filepath, args):
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return [{'type': 'System Error', 'description': f'Failed to read PCAP: {str(e)}', 'time': 0, 'severity': 'LOW'}]

    whitelist = load_whitelist(args.whitelist)
    internal_nets = load_internal_subnets(args.internal_subnets)
    
    alerts = []
    alerts.extend(detect_arp_spoofing(packets, whitelist=whitelist))
    alerts.extend(detect_port_scan(packets, threshold=args.port_threshold, whitelist=whitelist))
    alerts.extend(detect_dns_tunneling(packets, whitelist=whitelist))
    alerts.extend(detect_beaconing(packets))
    alerts.extend(detect_user_agent_spoofing(packets))
    alerts.extend(detect_data_exfiltration(packets, internal_nets=internal_nets))
    
    # Correlation Hook: Add correlation_id to all alerts
    for alert in alerts:
        alert['correlation_id'] = f"corr_{int(alert['time'])}"
        
    return alerts

def main():
    parser = argparse.ArgumentParser(description='Enterprise PCAP Threat Detector')
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--whitelist', help='Whitelist file')
    parser.add_argument('--internal-subnets', help='Internal subnets file')
    parser.add_argument('--port-threshold', type=int, default=20)
    args = parser.parse_args()

    alerts = process_pcap(args.pcap_file, args)
    if args.json:
        print(json.dumps(alerts, indent=2))
    else:
        for a in alerts:
            print(f"[{a['severity']}] {a['type']}: {a['description']}")

if __name__ == '__main__':
    main()
