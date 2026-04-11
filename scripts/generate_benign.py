from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

packets = []

# Simulate a normal HTTP GET request
src = "192.168.1.100"
dst = "93.184.216.34"  # example.com
http_get = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
pkt = IP(src=src, dst=dst)/TCP(sport=54321, dport=80, flags="PA")/Raw(load=http_get)
packets.append(pkt)

# Simulate a DNS query
dns_query = IP(src=src, dst="8.8.8.8")/UDP(sport=54322, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
packets.append(dns_query)

wrpcap("benign_extra.pcap", packets)
print("Generated benign_extra.pcap with HTTP and DNS flows")
