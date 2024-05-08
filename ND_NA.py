from scapy.all import ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, Ether, IPv6, sendp, sniff
import ipaddress
from config import *

def is_ipv6_in_subnet(ipv6_address, subnet):
    ipv6_network = ipaddress.IPv6Network(subnet)
    ipv6_addr = ipaddress.IPv6Address(ipv6_address)
    return ipv6_addr in ipv6_network

def handle_icmpv6_neighbor_solicitation(packet):
    
    if ICMPv6ND_NS in packet and is_ipv6_in_subnet(packet[ICMPv6ND_NS].tgt, source_subnet):  # 判断是否为 IPv6 邻居发现请求
        print(packet[ICMPv6ND_NS].tgt)
        print(is_ipv6_in_subnet(packet[ICMPv6ND_NS].tgt, source_subnet))
        # 构造 IPv6 邻居发现响应包
        icmpv6_response = Ether(dst=packet[Ether].src) / IPv6(dst=packet[IPv6].src) / ICMPv6ND_NA(tgt=packet[ICMPv6ND_NS].tgt, R=1) / ICMPv6NDOptDstLLAddr(lladdr=source_mac)
        # 发送 IPv6 邻居发现响应包
        sendp(icmpv6_response, iface = source_iface)

def v6_prefix_subnet_extract(v6_address):
    v6_address = v6_address.split(":")[:4]
    v6_address = ":".join(v6_address)
    # print("v6_prefix_extract:", v6_address)
    return v6_address + "::/64"


source_subnet = v6_prefix_subnet_extract(source_address)
# 监听 IPv6 邻居发现请求
sniff(prn = handle_icmpv6_neighbor_solicitation,
      filter = "icmp6 and ip6[40] == 135",
      store = 0)
