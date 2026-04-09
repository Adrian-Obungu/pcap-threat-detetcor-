from scapy.all import ARP, Ether, wrpcap
# Victim IP and real MAC
victim_ip = "192.168.1.10"
real_mac = "00:11:22:33:44:55"
attacker_mac = "aa:bb:cc:dd:ee:ff"
gateway_ip = "192.168.1.1"

# Spoofed ARP reply: gateway IP with attacker MAC
pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=gateway_ip, hwsrc=attacker_mac, pdst=victim_ip)
wrpcap("test_pcaps/arpspoof.pcap", [pkt])
print("Generated test_pcaps/arpspoof.pcap with a single ARP spoof attempt")
