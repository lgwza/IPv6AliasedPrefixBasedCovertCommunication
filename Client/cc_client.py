from scapy.all import IPv6, send, ICMPv6EchoRequest, sniff, TCP, UDP, Raw
from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad, unpad
from config import *
import threading
import ipaddress
import time
import warnings
import random


# 忽略所有警告
warnings.filterwarnings("ignore")

status = CLOSED


def expand_ipv6_address(address):
    ipv6_obj = ipaddress.IPv6Address(address)
    expanded_address = str(ipv6_obj.exploded)
    # print(expanded_address)
    return expanded_address

def cast_encrypt_blocks(key, plaintext_blocks):
    cipher = CAST.new(key, CAST.MODE_ECB)
    ciphertext_blocks = [cipher.encrypt(block) for block in plaintext_blocks]
    return ciphertext_blocks

def cast_decrypt_blocks(key, ciphertext_blocks):
    cipher = CAST.new(key, CAST.MODE_ECB)
    # print(ciphertext_blocks)
    plaintext_blocks = [cipher.decrypt(block) for block in ciphertext_blocks]
    return plaintext_blocks

def cast_decrypt_block(key, ciphertext_block, block_size = 8):
    try:
        cipher = CAST.new(key, CAST.MODE_ECB)
        plain_text = cipher.decrypt(ciphertext_block)
        return plain_text
    except ValueError as e:
        print("Decryption error:", str(e))
        return None
        

def pad_pkcs7(data, block_size = 8):
    padding_length = block_size - (len(data) % block_size)
    if padding_length == block_size:
        padding_length = 0
    padding = bytes([padding_length] * padding_length)
    return data + padding

def handle_packet(packet):
    global source_saddr_spoofable, source_daddr_spoofable, \
        dst_saddr_spoofable, dst_daddr_spoofable
    # print("Destination IPv6 address: ", packet[IPv6].dst)
    all_plain_text = b''
    if dst_daddr_spoofable:
        # 提取目的地址后 64 位: 倒数第四个冒号后的内容
        ciphertext = expand_ipv6_address(packet[IPv6].dst).split(":")[-4 :]
        ciphertext = "".join(ciphertext)
        # print(ciphertext)
        # 将 16 进制字符串转换为字节串
        ciphertext = bytes.fromhex(ciphertext)
        # print(ciphertext)
        # 将密文分组解密
        plain_text = cast_decrypt_block(key, ciphertext)
        all_plain_text += plain_text
    if dst_saddr_spoofable:
        # 提取源地址后 64 位
        ciphertext = expand_ipv6_address(packet[IPv6].src).split(":")[-4 :]
        ciphertext = "".join(ciphertext)
        ciphertext = bytes.fromhex(ciphertext)
        plain_text = cast_decrypt_block(key, ciphertext)
        all_plain_text += plain_text
    return all_plain_text

def send_packet(encrypted_blocks_hex, dstv6_prefix = None, srcv6_prefix = None, block_size = 8):
    # TODO 自动获取源地址
    global source_address, mode
    # 将密文附着于 IPv6 目的地址后 64 位，依次发送
    for i in range(len(encrypted_blocks_hex)):
        # 添加 ':'
        dstv6 = dstv6_prefix
        srcv6 = srcv6_prefix
        if dstv6_prefix != None and srcv6_prefix == None:
            for j in range(0, len(encrypted_blocks_hex[i]), 4):
                dstv6 = dstv6 + ":" + encrypted_blocks_hex[i][j : j + 4]
            srcv6 = source_address
        elif dstv6_prefix == None and srcv6_prefix != None:
            for j in range(0, len(encrypted_blocks_hex[i]), 4):
                srcv6 = srcv6 + ":" + encrypted_blocks_hex[i][j : j + 4]
            dstv6 = dst_address
        elif dstv6_prefix != None and srcv6_prefix != None:
            for j in range(0, len(encrypted_blocks_hex[i]) // 2, 4):
                srcv6 = srcv6 + ":" + encrypted_blocks_hex[i][j : j + 4]
            for j in range(len(encrypted_blocks_hex[i]) // 2, len(encrypted_blocks_hex[i]), 4):
                dstv6 = dstv6 + ":" + encrypted_blocks_hex[i][j : j + 4]
        else:
            print(f"ERROR! BOTH ADDRESSES ARE NOT SPOOFABLE!")
            exit(-1)
        
        ipv6_layer = IPv6(src = srcv6, dst = dstv6)
        if mode == 'I':
            complete_packet = ipv6_layer / ICMPv6EchoRequest()
        elif mode == 'T':
            complete_packet = ipv6_layer / \
            TCP(sport = random.randint(4096, 65535),
                dport = random.randint(1, 65535),
                flags = "S")
        elif mode == 'U':
            complete_packet = ipv6_layer / \
            UDP(sport = random.randint(4096, 65535),
                dport = random.randint(1, 65535)) / \
            Raw(load = b'Hello, UDP')
        else:
            print(f"ERROR! MODE {mode} IS NOT DEFINED!")
            exit(-1)
        
        # print(dstv6)
        send(complete_packet)

def v6_prefix_extract(v6_address):
    v6_address = v6_address.split(":")[:4]
    v6_address = ":".join(v6_address)
    # print("v6_prefix_extract:", v6_address)
    return v6_address

def send_message(message):
    # 如果编码了就不再编码
    plain_text = message
    if isinstance(message, str):
        plain_text = message.encode()
    # print(plain_text)
    dstv6_prefix = None
    srcv6_prefix = None
    if source_daddr_spoofable and not source_saddr_spoofable:
        dstv6_prefix = dst_address.split(":")[: 4]
        dstv6_prefix = ":".join(dstv6_prefix)
        block_size = 8
    elif not source_daddr_spoofable and source_saddr_spoofable:
        srcv6_prefix = source_address.split(":")[: 4]
        srcv6_prefix = ":".join(srcv6_prefix)
        block_size = 8
    elif source_daddr_spoofable and source_saddr_spoofable:
        dstv6_prefix = dst_address.split(":")[: 4]
        dstv6_prefix = ":".join(dstv6_prefix)
        srcv6_prefix = source_address.split(":")[: 4]
        srcv6_prefix = ":".join(srcv6_prefix)
        block_size = 16
    else:
        print(f"ERROR! BOTH ADDRESSES ARE NOT SPOOFABLE!")
        exit(-1)
    plain_text = pad_pkcs7(plain_text, block_size)
    plaintext_blocks = [plain_text[i : i + block_size] for i in range(0, len(plain_text), block_size)]
    encrypted_blocks = cast_encrypt_blocks(key, plaintext_blocks)
    encrypted_blocks_hex = [block.hex() for block in encrypted_blocks]
    # print(dstv6_prefix)
    send_packet(encrypted_blocks_hex, dstv6_prefix, srcv6_prefix, block_size)
    

# 定义回调函数处理接收到的IPv6和ICMPv6包
def packet_handler(packet):
    global status
    print(packet[IPv6].src, packet[IPv6].dst)
    print(f"status: {status}")
    if handle_packet(packet) == SYN_ACK_text and status == SYN_SENT:
        print("ESTABLISHED")
        status = ESTABLISHED
        send_message(dst_address, ACK_text)
        send_handler = threading.Thread(target = send_input)
        send_handler.start()
    elif status == ESTABLISHED:
        plain_text = handle_packet(packet)
        print(plain_text.decode('latin-1'))

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
              filter = "udp and \
                  src host " + dst_address,
              store = 0)
    else:
        print(f"ERROR! MODE {mode} IS NOT DEFINED!")
        exit(-1)

def send_input():
    # print("working")
    while True:
        Input = input("Please input your message: ")
        send_message(Input)

def init():
    global status
    if status == CLOSED:
        status = SYN_SENT
        print("SYN_SENT")
        send_message(dst_address, SYN_text)
        
if __name__ == "__main__":
    # subprocess.Popen(["python3", "ND_NA.py"])
    receive_handler = threading.Thread(target = receive_message)
    receive_handler.start()
    time.sleep(1)
    # print("working")
    init()
    # print("wza")
    # print(dst_address)
    