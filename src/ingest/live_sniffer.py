"""
Live packet capture using Scapy's AsyncSniffer.
Fallback to PCAP replay if interface is not available (e.g., Codespaces).
"""
import sys
from scapy.all import AsyncSniffer, conf
from .pcap_replay import replay_pcap

def sniff_live(iface=None, packet_filter=None, timeout=None, prn=None, store=False):
    """
    Start an AsyncSniffer. If iface is None or loopback, use replay from a test PCAP.
    """
    # In Codespaces, we typically cannot capture from real interfaces.
    # We'll check if the interface exists and if we have permissions.
    if iface and iface != 'lo':
        try:
            # Quick probe: see if we can open the interface
            test = AsyncSniffer(iface=iface, count=1, timeout=1)
            test.start()
            test.stop()
        except Exception as e:
            print(f"Live capture not possible on {iface}: {e}. Falling back to PCAP replay.", file=sys.stderr)
            return replay_pcap("test_pcaps/exfil.pcap")  # fallback
    # For loopback, attempt live capture
    if iface == 'lo':
        sniffer = AsyncSniffer(iface=iface, filter=packet_filter, timeout=timeout, prn=prn, store=store)
        sniffer.start()
        return sniffer
    # No interface specified – use replay
    return replay_pcap("test_pcaps/exfil.pcap")
