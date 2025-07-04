# SYNapse

[![PyPI version](https://badge.fury.io/py/synapse-toolkit.svg)](https://badge.fury.io/py/synapse-toolkit)

> A modular Man-in-the-Middle (MitM) toolkit built in Python for advanced network analysis and protocol manipulation.

## Description
SYNapse is a powerful, educational toolkit designed to provide hands-on experience with fundamental network security concepts. It moves beyond high-level frameworks to allow for the direct crafting and manipulation of network packets, providing deep insight into how protocols like ARP, DNS, and HTTP function—and how they can be subverted.

This tool is built with a clean, modular architecture and is intended for security researchers, students, and network professionals in controlled lab environments. It has native support for Linux-based systems.


## Features
### Version 0.1.0:
 - Functional ARP Spoofer (`spoof` mode)
 - Integrated MitM attack framework (`mitm` mode)
 - Working DNS Spoofer (`dns_spoof` mode)

 ## Installation
 It is highly recommended to run this tool inside a dedicated Linux virtual machine (e.g., Kali Linux).
 SYNapse works in tandem with linux's ```netfilterqueue``` library, along with linux system ```iptables```.

```bash
# Clone the repository
git clone [https://github.com/kalandjl/SYNapse.git](https://github.com/kalandjl/SYNapse.git)
cd SYNapse

# Set up a Python virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install system-level dependencies required for NetfilterQueue
sudo apt update && sudo apt install -y build-essential python3-dev libnfnetlink-dev libnetfilter-queue-dev

# Install Python package dependencies
pip install -r requirements.txt

# Install the tool in editable mode to make the `syn-apse` command available
pip install -e .

```

## System Prerequisites (Linux)
To enable packet interception and modification, SYNapse requires specific kernel and firewall configurations.

### 1. Enable IP Forwarding
This allows your machine to act as a router for intercepted traffic.

```
sudo sysctl -w net.ipv4.ip_forward=1
```

### 2. Set up ```iptables``` Queue
This rule forwards packets to the ```NFQUEUE``` so your script can process them.
```
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

### 3. (Optional) Advanced iptables Setup
For a smoother experience on modern networks, this ruleset is recommended:
```
# Allow established connections to bypass the queue
sudo iptables -I FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Clamp TCP MSS to prevent MTU issues
sudo iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

### IMPORTANT: Cleaning Up
The iptables rules are temporary and will reset on reboot. To clear them manually after you are done, run:
```
sudo iptables --flush
```

## Usage & Commands

All commands require root priviledges. It is recommended to run them with ```sudo -E``` to preserve your environement.

### ```mitm``` 
 
Runs a full Man-in-the-Middle attack, performing an ARP spoof while sniffing traffic.

### Arguments:
 
```-t```, ```--target```: The IP address of the target device.

```-g```, ```--gateway```: The IP address of the network gateway/router.

```-i```, ```--interface```: The network interface to use.

### Example

```
sudo -E syn-apse mitm --target 10.0.0.83 --gateway 10.0.0.1 --interface eth0
```

### ```dns_spoof``` 
 
Performs an ARP spoof to intercept traffic, and then provides forged DNS responses for a target domain.

### Arguments:

```-t```, ```--target```: The IP address of the target device.

```-g```, ```--gateway```: The IP address of the network gateway/router.

```-i```, ```--interface```: The network interface to use.

```-d```, ```--domain``` The domain to spoof.

### Example

```
sudo -E syn-apse dns-spoof -t 10.0.0.83 -g 10.0.0.1 -i eth0 -d example.com --spoof-ip 10.0.0.1

```

### ```sniff```
 
  Captures and displays live packets on a specified network interface.

### Arguments:

```-i```, ```--interface```: The network interface to use.
```-f```, ```--filter```: BPF filter for sniffing (e.g., 'tcp port 80').
```-c```, ```--count```: Number of packets to capture (0 for unlimited).

### Example

```
sudo -E syn-apse sniff --interface eth0 --filter "udp port 53" --count 10
```

## Disclaimer
SYNapse is a tool created for educational and research purposes only. It is intended to be used in controlled lab environments on networks where you have explicit authorization. The user is responsible for obeying all applicable laws. The author assumes no liability for any misuse or damage caused by this program.

## License 
This project is licensed under the MIT License.