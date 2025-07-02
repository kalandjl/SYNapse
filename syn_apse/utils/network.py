
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
    
# Allow for testable CLI
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="MAC Address Fetcher Utility")
    parser.add_argument("-t", "--target", dest="target_ip", help="IP address of the target to find.")
    options = parser.parse_args()

    if not options.target_ip:
        parser.error("[-] Please specify a target IP address, use --help for more info.")

    mac = get_mac(options.target_ip)
    
    if mac:
        print(f"[+] MAC address for {options.target_ip} is {mac}")
    else:
        print(f"[-] Could not get MAC address for {options.target_ip}. The host may be down or on a different network.")