from scapy.all import IP, TCP, Raw, wrpcap
import time

packets = []
src = "192.168.1.100"
dst = "10.0.0.5"
ts = time.time()

# HTTP GET with sqlmap User-Agent
http_payload = (
    "GET /index.php?id=1 HTTP/1.1\r\n"
    "Host: 10.0.0.5\r\n"
    "User-Agent: sqlmap/1.4.12#stable (http://sqlmap.org)\r\n"
    "Accept: */*\r\n\r\n"
)

pkt = IP(src=src, dst=dst)/TCP(sport=12345, dport=80, flags="PA")/Raw(load=http_payload)
pkt.time = ts
packets.append(pkt)

wrpcap("/home/ubuntu/pcap-threat-detetcor-/test_pcaps/ua_spoof.pcap", packets)
print("Generated ua_spoof.pcap")
