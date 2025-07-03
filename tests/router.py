from scapy.all import conf

# Get default route
default_route = conf.route.route("0.0.0.0")
gateway_ip = default_route[2]
print(f"Router IP: {gateway_ip}")