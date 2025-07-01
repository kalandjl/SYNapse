from scapy.all import * 

def packet_callback(packet):
    packet.show()

results = sniff(filter="icmp", prn=packet_callback)
