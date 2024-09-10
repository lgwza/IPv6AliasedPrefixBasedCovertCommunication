from scapy.all import IPv6, ICMPv6EchoRequest, send

# 伪造源地址发送 ping 包
spoofed_source_address = "2401:c080:1000:4662:1234:3413:555e:ef23"
dst_address = "2a09:7c41:0:15::1"

IP_layer = IPv6(src=spoofed_source_address, dst=dst_address)
ICMP_layer = ICMPv6EchoRequest()
packet = IP_layer / ICMP_layer

for i in range(10):
    send(packet)