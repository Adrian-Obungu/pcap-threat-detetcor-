from scapy.all import IP, UDP, DNS, DNSQR, wrpcap
import time
src_ip = "192.168.1.50"
dns_server = "8.8.8.8"
base_domain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.attacker.com"
packets = []
# Generate 25 queries with long subdomains
for i in range(25):
    sub = f"{i:05d}" + "x" * 30
    domain = f"{sub}.{base_domain}"
    pkt = IP(src=src_ip, dst=dns_server)/UDP(sport=54321, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
    packets.append(pkt)
wrpcap("test_pcaps/dns-tunnel.pcap", packets)
print("Generated test_pcaps/dns-tunnel.pcap with 25 long‑subdomain DNS queries")
