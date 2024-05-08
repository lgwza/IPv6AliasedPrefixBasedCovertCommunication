from scapy.all import sniff, IPv6, ICMPv6EchoRequest, send, Raw, UDP, TCP
from Crypto.Cipher import CAST
import ipaddress
import threading
from Timer import Timer
from config import *
import random

Timer1 = Timer()


def expand_ipv6_address(address):
    ipv6_obj = ipaddress.IPv6Address(address)
    expanded_address = str(ipv6_obj.exploded)
    # print(expanded_address)
    return expanded_address

def cast_encrypt_blocks(key, plaintext_blocks):
    cipher = CAST.new(key, CAST.MODE_ECB)
    ciphertext_blocks = [cipher.encrypt(block) for block in plaintext_blocks]
    return ciphertext_blocks

def cast_decrypt_block(key, ciphertext_block, block_size = 8):
    try:
        cipher = CAST.new(key, CAST.MODE_ECB)
        plain_text = cipher.decrypt(ciphertext_block)
        return plain_text
    except ValueError as e:
        print("Decryption error:", str(e))
        return None

def handle_packet(packet):
    # print("Destination IPv6 address: ", packet[IPv6].dst)
    # 提取目的地址后 64 位: 倒数第四个冒号后的内容
    ciphertext = expand_ipv6_address(packet[IPv6].dst).split(":")[-4 :]
    ciphertext = "".join(ciphertext)
    # print(ciphertext)
    # 将 16 进制字符串转换为字节串
    ciphertext = bytes.fromhex(ciphertext)
    # print(ciphertext)
    # 将密文分组解密
    
    plain_text = cast_decrypt_block(key, ciphertext)
    return plain_text

# 定义回调函数处理接收到的IPv6和ICMPv6包
def packet_handler(packet):
    global status, source_address, dst_address
    print("Source IPv6 address: ", packet[IPv6].src)
    print("status: ", status)

    if handle_packet(packet) == SYN_text and status == LISTEN:
        print("SYN_RECEIVED")
        status = SYN_RECEIVED
        # 发送 SYN_ACK
        # print(packet[IPv6].src)
        dst_address = packet[IPv6].src
        # print("dst_address: ", dst_address)
        send_message(packet[IPv6].src, SYN_ACK_text)
        
    elif handle_packet(packet) == ACK_text and status == SYN_RECEIVED:
        print("ESTABLISHED")
        # TODO 需要更严谨的逻辑
        status = ESTABLISHED
        # print("dst_address: ", dst_address)
        send_handler = threading.Thread(target = send_input, args = (dst_address,))
        send_handler.start()
    elif status == ESTABLISHED:
        plain_text = handle_packet(packet)
        print("received message:", plain_text.decode('latin-1'))
            
def receive_message():
    # 启动嗅探器并调用回调函数
    if mode == 'I':
        sniff(prn = packet_handler,
              filter = "icmp6 and icmp6[0] == 128 and \
                  src host " + dst_address,
              store = 0)
    elif mode == 'T':
        sniff(prn = packet_handler,
              filter = "tcp and ip6[6] & 0x2 != 0 and \
                  src host " + dst_address,
              store = 0)
    elif mode == 'U':
        sniff(prn = packet_handler,
              filter = "udp and ip6 and \
                  src host " + dst_address,
              store = 0)
    else:
        print(f"ERROR! MODE {mode} IS NOT DEFINED!")
        exit(-1)

def pad_pkcs7(data, block_size = 8):
    padding_length = block_size - (len(data) % block_size)
    if padding_length == block_size:
        padding_length = 0
    padding = bytes([padding_length] * padding_length)
    return data + padding

def send_packet(encrypted_blocks_hex, dstv6_prefix, block_size = 8):
    # print(encrypted_blocks_hex)
    # TODO 自动获取源地址
    global source_address
    src_addr_prefix = source_address.split(":")[:4]
    src_addr_prefix = ":".join(src_addr_prefix)
    # 将密文附着于 IPv6 目的地址后 64 位，依次发送
    for i in range(len(encrypted_blocks_hex)):
        dstv6 = dstv6_prefix
        for j in range(0, len(encrypted_blocks_hex[i]), 4):
            dstv6 = dstv6 + ":" + encrypted_blocks_hex[i][j : j + 4]
        ipv6_packet = IPv6(src = source_address, dst = dstv6)
        if mode == 'I':
            complete_packet = ipv6_packet / ICMPv6EchoRequest()
        elif mode == 'T':
            complete_packet = IPv6(dst = dstv6) / \
            TCP(sport = random.randint(4096, 65535),
                dport = random.randint(1, 65535),
                flags = "S")
        elif mode == 'U':
            complete_packet = IPv6(dst = dstv6) / \
            UDP(sport = random.randint(4096, 65535),
                dport = random.randint(1, 65535)) / \
            Raw(load = b'Hello, UDP')
        else:
            print(f"ERROR! MODE {mode} IS NOT DEFINED!")
            exit(-1)            

        send(complete_packet)

def send_message(dst_addr, message):
    plain_text = message
    if isinstance(message, str):
        plain_text = message.encode()
    plain_text = pad_pkcs7(plain_text)
    plaintext_blocks = [plain_text[i : i + 8] for i in range(0, len(plain_text), 8)]
    encrypted_blocks = cast_encrypt_blocks(key, plaintext_blocks)
    encrypted_blocks_hex = [block.hex() for block in encrypted_blocks]
    # 提取 IPv6 地址的前 64 位
    dstv6_prefix = dst_addr.split(":")[:4]
    dstv6_prefix = ":".join(dstv6_prefix)
    send_packet(encrypted_blocks_hex, dstv6_prefix) # change dstv6_prefix to dst_addr

def send_input(dst_addr):
    while True:
        Input = input("Please input your message: ")
        send_message(dst_addr, Input)


if __name__ == "__main__":
    # subprocess.Popen(["python3", "ND_NA.py"])
    listen_handler = threading.Thread(target = receive_message)
    listen_handler.start()
    # send_handler = threading.Thread(target = send_message)
    # send_handler.start()