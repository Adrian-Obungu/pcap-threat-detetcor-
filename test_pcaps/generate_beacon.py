from scapy.all import IP, TCP, wrpcap
import time

packets = []
src = "192.168.1.100"
dst = "10.0.0.5"
dport = 4444
start_time = time.time()

# Generate 10 packets with 5s interval (very low jitter)
for i in range(10):
    pkt = IP(src=src, dst=dst)/TCP(sport=12345, dport=dport)
    pkt.time = start_time + (i * 5)
    packets.append(pkt)

wrpcap("/home/ubuntu/pcap-threat-detetcor-/test_pcaps/beacon.pcap", packets)
print("Generated beacon.pcap")
