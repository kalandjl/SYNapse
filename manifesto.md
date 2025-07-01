# Preamble

This document outlines the technical requirements and development phases for Syn-apse, a modular network security toolkit built in Python. The primary objective is to implement core network attack vectors from first principles to gain a fundamental understanding of network protocol security.

# Core Architecture

The project will adhere to a modular, package-based structure to ensure clean separation of concerns and maintainability.

syn-apse/
├── syn_apse/
│   ├── __init__.py
│   ├── cli.py
│   ├── core/
│   │   └── engine.py
│   ├── modules/
│   │   ├── sniffer.py
│   │   └── arp_spoofer.py
│   └── utils/
│       └── network.py
├── .gitignore
├── README.md
├── requirements.txt
└── setup.py

Development Objectives

# Phase 1: Packet Sniffing & Analysis

    Objective: Implement a module to capture and parse live network traffic from a specified network interface.

    Key Tasks:

        Develop a sniffer module utilizing scapy.sniff.

        Implement a packet processing callback function to dissect packet layers.

        Add logic to identify and parse key data from IP, TCP, UDP, and application-layer protocols (DNS, HTTP).

        Integrate with the cli.py entry point to accept command-line arguments for network interface and BPF filters.

# Phase 2: ARP Cache Poisoning (ARP Spoofing)

    Objective: Implement a module to perform an ARP spoofing attack to redirect the flow of traffic between a target and a gateway on a local network.

    Key Tasks:

        Create a utility function to resolve an IP address to a MAC address using ARP requests.

        Develop a core function to construct and transmit forged ARP reply packets (op=2) to arbitrary targets.

        Implement a main attack loop to periodically re-broadcast ARP replies to maintain the poisoned state of the victims' ARP caches.

        Ensure a robust cleanup mechanism is in place to transmit corrective ARP packets, restoring the network to its original state upon script termination (KeyboardInterrupt).

        Integrate with the CLI to accept --target and --gateway IP addresses.

# Phase 3: Real-time Packet Interception & Modification

    Objective: Develop the capability to intercept forwarded packets in real-time and alter their payloads before they reach their destination.

    Key Tasks:

        Enable system-level IP forwarding.

        Implement packet queuing by interfacing with the system's firewall (e.g., iptables on Linux and the NetfilterQueue library).

        Develop a callback function that receives queued packets from the kernel.

        Add logic to parse intercepted packets, modify their payload (e.g., inject data into plaintext HTTP), and ensure IP/TCP checksums and lengths are recalculated.

        Forward the modified packet by accepting it from the queue.

# Phase 4: DNS Spoofing & HTTPS Downgrade

    Objective: Create a module to perform DNS spoofing as a primary component of an SSL stripping attack.

    Key Tasks:

        Intercept DNS Query Request packets for a specified target domain.

        Construct and send a forged DNS Query Response packet, mapping the target domain to a controlled IP address (i.e., the Syn-apse machine).

        Integrate the DNS spoofing module with the ARP spoofing and packet modification modules to create a full, orchestrated attack chain for downgrading HTTPS connections.