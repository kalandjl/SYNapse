import scapy.all as scapy
import traceback # Import the traceback module for detailed errors
import netfilterqueue

def process_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        
        if scapy_packet.haslayer(scapy.TCP):
            tcp_layer = scapy_packet[scapy.TCP]
            
            # Only process packets on port 80 (HTTP)
            if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                print(f"[HTTP] TCP packet: {tcp_layer.sport} -> {tcp_layer.dport}")
                print(f"[HTTP] Flags: {tcp_layer.flags}")
                
                if scapy_packet.haslayer(scapy.Raw):
                    raw_data = scapy_packet[scapy.Raw].load
                    print(f"[HTTP] *** HAS PAYLOAD! Length: {len(raw_data)} ***")
                    
                    # Print first 200 bytes to see what we got
                    try:
                        data_str = raw_data.decode('latin-1', errors='ignore')
                        print(f"[HTTP] Data preview: {data_str[:200]}")
                    except:
                        print(f"[HTTP] Binary data: {raw_data[:50]}")
                        
                else:
                    print(f"[HTTP] Empty packet (handshake/control)")
            
    except Exception as e:
        print(f"[ERROR] {e}")
        traceback.print_exc()
    
    packet.accept()
    
    print(f"[DEBUG] Packet received! Length: {len(packet.get_payload())}")
    
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        print(f"[DEBUG] Parsed packet: {scapy_packet.summary()}")
        
        # Check if it has TCP layer
        if scapy_packet.haslayer(scapy.TCP):
            tcp_layer = scapy_packet[scapy.TCP]
            print(f"[DEBUG] TCP packet - Sport: {tcp_layer.sport}, Dport: {tcp_layer.dport}")
            
            # Check if it has Raw layer (payload)
            if scapy_packet.haslayer(scapy.Raw):
                raw_data = scapy_packet[scapy.Raw].load
                print(f"[DEBUG] Has Raw data, length: {len(raw_data)}")
                
                # Check if it's HTTP
                if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                    print("[DEBUG] HTTP traffic detected!")
                    print(f"[DEBUG] First 100 bytes: {raw_data[:100]}")
                else:
                    print(f"[DEBUG] Non-HTTP TCP traffic: {tcp_layer.sport} -> {tcp_layer.dport}")
            else:
                print("[DEBUG] No Raw layer (no payload)")
        else:
            print("[DEBUG] Not a TCP packet")
            
    except Exception as e:
        print(f"[DEBUG] Error parsing packet: {e}")
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
