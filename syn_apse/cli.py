# syn_apse/cli.py

import argparse
from .modules import sniffer  # We import the whole modules package

def main():
    parser = argparse.ArgumentParser(
        prog="syn-apse",
        description="A modular Man-in-the-Middle toolkit for network analysis.",
        epilog="Use 'syn-apse <command> --help' for more information on a specific command."
    )
    
    # This creates the sub-command system
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    # Sniffer Command
    parser_sniff = subparsers.add_parser('sniff', help='Run the network packet sniffer.')
    parser_sniff.add_argument(
        '-i', '--interface', 
        required=True, 
        help="The network interface to sniff on (e.g., eth0, en0)."
    )
    parser_sniff.add_argument(
        '-f', '--filter', 
        help="BPF filter for sniffing (e.g., 'tcp port 80')."
    )
    parser_sniff.add_argument(
        '-c', '--count', 
        type=int, 
        default=0, 
        help="Number of packets to capture (0 for unlimited)."
    )

    # For ARP spoofing
    parser_spoof = subparsers.add_parser('spoof', help='Run an ARP spoofing attack.')


    # Parse the arguments provided by the user
    args = parser.parse_args()

    # Execute the appropriate function based on the command
    if args.command == 'sniff':
        try:
            # Call the function from our sniffer module
            sniffer.start_sniffing(args.interface, args.filter, args.count)
        except PermissionError:
            print("[ERROR] Permission denied. Packet sniffing requires root privileges. Try running with 'sudo'.")
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred: {e}")
            
    elif args.command == 'spoof':
        print("Spoof module not yet implemented.")