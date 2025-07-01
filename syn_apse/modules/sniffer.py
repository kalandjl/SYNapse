from scapy.all import * 

results = sniff(count = 10)

print(results[3].show())
