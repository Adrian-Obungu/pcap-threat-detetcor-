from scapy.all import Ether, ARP, wrpcap

# Legitimate gateway MAC
gateway_ip = "192.168.1.1"
real_gateway_mac = "00:11:22:33:44:55"
attacker_mac = "aa:bb:cc:dd:ee:ff"
victim_ip = "192.168.1.10"

# Legitimate ARP reply (from real gateway)
legit = Ether(dst="ff:ff:ff:ff:ff:ff", src=real_gateway_mac)/ARP(op=2, psrc=gateway_ip, hwsrc=real_gateway_mac, pdst=victim_ip)

# Spoofed ARP reply (from attacker)
spoof = Ether(dst="ff:ff:ff:ff:ff:ff", src=attacker_mac)/ARP(op=2, psrc=gateway_ip, hwsrc=attacker_mac, pdst=victim_ip)

wrpcap("test_pcaps/arpspoof_full.pcap", [legit, spoof])
print("Generated test_pcaps/arpspoof_full.pcap with legitimate then spoofed ARP reply")
