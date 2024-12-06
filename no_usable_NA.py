from scapy.all import *

target_ip = "2001:db8:1::1342"
target_mac = "96:c9:39:e4:05:03"
interface = "veth0"

# 创建 NA 消息
na = IPv6(dst=target_ip) / ICMPv6ND_NA(tgt=target_ip, R=0, S=1, O=1) / ICMPv6NDOptDstLLAddr(lladdr=target_mac)

# 发送消息
sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / na, iface=interface)
