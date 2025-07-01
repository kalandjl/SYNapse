# syn_apse/modules/sniffer.py
import scapy.all as scapy

def _packet_callback(packet):
    """
    Callback function for every new sniffed packet.
    .show() provides a detailed, multi-line breakdown.
    """
    packet.show()

def start_sniffing(interface, filter_str=None, count=0):
    """
    Main function for sniffer module
    """

    print(f"[*] Starting sniffer on interface '{interface}'...")
    
    try:
        scapy.sniff(
            iface=interface,
            filter=filter_str,
            prn=_packet_callback,
            count=count,
            store=False
        )
    except Exception as e:
        print(f"[ERROR] Sniffer failed to start: {e}")