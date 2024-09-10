import ipaddress

def extract_ipv6_prefix(ipv6_address, prefix_length):
    # 将输入的字符串转换为 IPv6 对象
    ipv6 = ipaddress.IPv6Address(ipv6_address)
    
    # 创建一个 IPv6 网络对象，使用输入地址和前缀长度
    ipv6_network = ipaddress.IPv6Network((ipv6, prefix_length), strict=False)
    
    # 提取并返回前缀
    return str(ipv6_network.network_address)

# 示例
ipv6_address = '2001:0db8:85a3::8a2e:0370:7334'
prefix_length = 64
prefix = extract_ipv6_prefix(ipv6_address, prefix_length)
print(f'IPv6 地址 {ipv6_address} 的前 {prefix_length} 位前缀是: {prefix}')
