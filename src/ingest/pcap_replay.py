"""
Replay a PCAP file as if it were live traffic.
Yields packets at the original inter‑packet timing.
"""
import time
from scapy.all import rdpcap

def replay_pcap(pcap_path: str, speed_factor: float = 1.0):
    """Generator: yields packets with original timestamps, optionally scaled."""
    packets = rdpcap(pcap_path)
    if not packets:
        return
    prev_time = packets[0].time
    for pkt in packets:
        now = pkt.time
        delta = now - prev_time
        if delta > 0:
            time.sleep(delta / speed_factor)
        yield pkt
        prev_time = now
