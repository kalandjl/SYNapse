# SYNapse
## Description
SYNapse is a python-based network toolkit which provides attacking capabilities in the form of DNS spoofing, ARP cache poisoning and MiTM positioning. Native support for linux.

## Features
### Version 0.1.0:
 - Functional ARP Spoofer (`spoof` mode)
 - Integrated MitM attack framework (`mitm` mode)
 - Working DNS Spoofer (`dns_spoof` mode)

 ## Linux Environment Config
 SYNapse works in tandem with linux's ```netfilterqueue``` library, along with linux system ```iptables```.

 **In order to configure these tools to enable IP forwarding, the running the following commands is neccessary;** 

This enables system IP forwarding
```
sudo sysctl -w net.ipv4.ip_forward=1
```

Forward packets into netfilterqueue's queue of packets, making them accesssable by the package
```
sudo iptables -I FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
```

For MiTM - when sites use max network packet size
```
sudo iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

## Commands
Currently SYNapse supports three main commands: ```mitm```, ```dns_spoof``` and ```sniff```

 ### ```mitm``` runs Man in the Middle attack.

 ### Arguments:
 
```-t```, ```--target```: The IP address of the target device.

```-g```, ```--gateway```: The IP address of the network gateway/router.

```-i```, ```--interface```: The network interface to use.


 ### ```dns_spoof``` runs DNS spoofing attack.

 ### Arguments:

```-t```, ```--target```: The IP address of the target device.

```-g```, ```--gateway```: The IP address of the network gateway/router.

```-i```, ```--interface```: The network interface to use.

```-d```, ```--domain``` The domain to spoof.


 ### ```sniff``` sniffs packages on host device.

 ### Arguments:

```-i```, ```--interface```: The network interface to use.

