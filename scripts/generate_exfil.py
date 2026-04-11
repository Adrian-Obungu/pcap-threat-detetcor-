from scapy.all import IP, ICMP, Raw, wrpcap
packets = []
for i in range(5):
    pkt = IP(src="192.168.1.100", dst="8.8.8.8")/ICMP(type=8)/Raw(load=b"X"*1400)
    packets.append(pkt)
wrpcap("test_pcaps/exfil.pcap", packets)
print("Generated test_pcaps/exfil.pcap with 5 large ICMP packets (1400 bytes each)")
