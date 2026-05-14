from scapy.all import IP, TCP, wrpcap
target_ip = "192.168.1.100"
ports = [22, 80, 443, 8080, 3389, 445, 139, 21, 25, 110, 143, 993, 995, 3306, 5432]
packets = []
for port in ports:
    pkt = IP(src="10.0.0.5", dst=target_ip)/TCP(dport=port, flags="S")
    packets.append(pkt)
wrpcap("test_pcaps/nmap_scan.pcap", packets)
print("Generated test_pcaps/nmap_scan.pcap with SYN packets to 15 ports")
