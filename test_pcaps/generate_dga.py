from scapy.all import IP, UDP, DNS, DNSQR, wrpcap
import time

packets = []
src = "192.168.1.100"
dst = "8.8.8.8"
ts = time.time()

# DGA-like domain with high digit ratio
dga_domain = "v3r1fyc4t10n-s3rv1c3-99.com"

pkt = IP(src=src, dst=dst)/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname=dga_domain))
pkt.time = ts
packets.append(pkt)

wrpcap("/home/ubuntu/pcap-threat-detetcor-/test_pcaps/dga.pcap", packets)
print("Generated dga.pcap")
