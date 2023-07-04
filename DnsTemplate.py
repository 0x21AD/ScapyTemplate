from scapy.all import *

encodedflag = ""

# Read the pcap file
packets = rdpcap('ctf.pcap.pcapng')

# Filter DNS traffic with the specified source and destination IP addresses
filtered_packets = [pkt for pkt in packets if
                    DNS in pkt and
                    pkt.getlayer(IP) and pkt[IP].src == '172.168.40.2' and
                    pkt.getlayer(IP) and pkt[IP].dst == '192.168.1.130']

# Process the filtered packets
for pkt in filtered_packets:
    dns = pkt[DNS]
    if dns.qd:
        qname = dns.qd.qname.decode('utf-8')
        encodedflag+=qname# Add your custom processing logic here


with open("flag", "w") as f:
    enc = encodedflag.replace("-.","")
    f.write(f"{encodedflag}")
