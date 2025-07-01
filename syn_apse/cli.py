# syn_apse/cli.py

import argparse
from .modules import sniffer

def main():
    parser = argparse.ArgumentParser(
        prog="SYNapse",
        description="A modular Man-in-the-Middle toolkit."
    )
    
    # Main command for selecting the mode
    parser.add_argument(
        '-m', '--mode', 
        required=True, 
        choices=['sniff', 'spoof'], # We'll add 'spoof' in Phase 2
        help="The mode of operation."
    )

    # Arguments for the 'sniff' mode
    parser.add_argument('-i', '--interface', help="The network interface to use.")
    parser.add_argument('-f', '--filter', help="BPF filter for sniffing (e.g., 'tcp port 80').")
    parser.add_argument('-c', '--count', type=int, default=0, help="Number of packets to capture (0 for unlimited).")

    args = parser.parse_args()

    if args.mode == 'sniff':
        if not args.interface:
            parser.error("--interface is required for sniff mode.")
        sniffer.start_sniffing(args.interface, args.filter, args.count)
    
    # add the logic for 'spoof' mode later
    # elif args.mode == 'spoof':
    #     ...