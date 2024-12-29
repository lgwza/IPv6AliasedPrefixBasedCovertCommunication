import random
import string
from scapy.all import *
import time

# Step 1: Generate random text of length 5000
def generate_random_text(length=10000):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

random_text = generate_random_text()

# Step 2: Convert the random text to hexadecimal
hex_representation = random_text.encode('utf-8').hex()

# Step 3: Split the hex data into 64-bit (8 bytes) groups
# Each group corresponds to 16 hex characters (8 bytes * 2 hex characters per byte)
hex_groups = [hex_representation[i:i+16] for i in range(0, len(hex_representation), 16)]

# Step 4: Construct ICMPv6 packets with destination address 2001:db8:2::/64 + generated 64 bits
icmpv6_packets = []
# prefix = "2001:db8:2:"  # The fixed IPv6 prefix (first 64 bits)
prefix = "2001:252:188:fe0"

for i, group in enumerate(hex_groups):
    # Construct the full IPv6 destination address (prefix + the generated 64 bits)
    # We insert ':' every 4 characters to correctly format the IPv6 address
    formatted_group = ':'.join([group[j:j+4] for j in range(0, len(group), 4)])
    destination_ip = prefix + ':' + formatted_group
    # print(f"Destination IP {i+1}: {destination_ip}")
    # Create ICMPv6 Echo Request packet
    icmpv6_packet = IPv6(dst=destination_ip) / ICMPv6EchoRequest()
    icmpv6_packet = Ether() / icmpv6_packet
    # Append the packet to the list
    
    icmpv6_packets.append(icmpv6_packet)

# Step 5: Send all ICMPv6 packets
# Note: root privileges may be required to send ICMP packets

# 计时
start_time = time.time()

# send(icmpv6_packets)
sendp(icmpv6_packets)

end_time = time.time()
print(f"Time taken to send all packets: {end_time - start_time:.2f} seconds")
print(len(random_text))
print(f"BANDWIDTH: {len(random_text) / (end_time - start_time) * 8} bit/s")
print(f"speed: {len(icmpv6_packets) / (end_time - start_time)} packets/s")