from scapy.all import sniff, IPv6, ICMPv6EchoRequest,\
    send, Raw, UDP, TCP, SCTP, SCTPChunkData

from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad, unpad
import ipaddress
import threading
from Timer import Timer
import sys
import os
from datetime import datetime, timedelta, timezone

# 获取当前文件的目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 获取父目录
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))

# 将父目录添加到sys.path
sys.path.insert(0, parent_dir)
from config import *
import random

Timer1 = Timer()

status = LISTEN

last_mode = ''
next_mode = {}

received_messages = b""

def gen_next_mode_dict():
    global proto_list, next_mode
    for i in range(len(proto_list)):
        next_mode[proto_list[i]] = proto_list[(i + 1) % len(proto_list)]
    next_mode[''] = proto_list[0]



def save_to_file():
    global received_messages
    if isinstance(received_messages, bytes):
        received_messages = received_messages.decode('latin-1')
    # 设置时区东八区
    now_utc = datetime.now()
    # 设置东八区时区
    east_8 = timezone(timedelta(hours=8))
    # 转换为东八区时间并格式化为YYYYMMDDHHMM
    now_east_8 = now_utc.astimezone(east_8)
    formatted_time = now_east_8.strftime('%Y%m%d%H%M%S')
    with open(f"received_messages_{formatted_time}.txt", "w") as f:
        f.write(received_messages)


def extract_ipv6_prefix(ipv6_address, prefix_length):
    # 将输入的字符串转换为 IPv6 对象
    ipv6 = ipaddress.IPv6Address(ipv6_address)
    
    # 创建一个 IPv6 网络对象，使用输入地址和前缀长度
    ipv6_network = ipaddress.IPv6Network((ipv6, prefix_length), strict=False)
    
    # 提取并返回前缀
    return str(ipv6_network.network_address)
    # IPv6 地址 2001:0db8:85a3:0000:0000:8a2e:0370:7334 -> 2001:db8:85a3::
    
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
        # print(ciphertext)
        plain_text = cast_decrypt_block(key, ciphertext)
        # print(plain_text)
        try:
            plain_text = unpad(plain_text, 8)
        except ValueError:
            pass
        all_plain_text += plain_text
    if dst_saddr_spoofable:
        # 提取源地址后 64 位
        ciphertext = expand_ipv6_address(packet[IPv6].src).split(":")[-4 :]
        ciphertext = "".join(ciphertext)
        ciphertext = bytes.fromhex(ciphertext)
        plain_text = cast_decrypt_block(key, ciphertext)
        # print(plain_text)
        try:
            plain_text = unpad(plain_text, 8)
        except ValueError:
            pass
        all_plain_text += plain_text
    # print(all_plain_text)
    return all_plain_text

# 定义回调函数处理接收到的IPv6和ICMPv6包
def packet_handler(packet):
    global status, source_address, dst_address, \
        received_messages
    # print("Source IPv6 address: ", packet[IPv6].src)
    # print("status: ", status)

    if handle_packet(packet) == SYN_text and status == LISTEN:
        print("SYN_RECEIVED")
        status = SYN_RECEIVED
        # 发送 SYN_ACK
        # print(packet[IPv6].src)
        # print("dst_address: ", dst_address)
        send_message(SYN_ACK_text)
        
    elif handle_packet(packet) == ACK_text and status == SYN_RECEIVED:
        print("ESTABLISHED")
        # TODO 需要更严谨的逻辑
        status = ESTABLISHED
        send_handler = threading.Thread(target = send_input)
        send_handler.start()
        Timer1.start()
        print("Timer started")
    elif status == ESTABLISHED:
        plain_text = handle_packet(packet)
        print("received message:", plain_text.decode('latin-1'))
        received_messages += plain_text # 字节串
        if len(received_messages) >= 8 and received_messages[-8 :] == RST_text:
            print("FINISHED")
            received_messages = received_messages[:-8]
            save_to_file()
            Timer1.end()
            print("Timer stopped")
            print("Time elapsed:", Timer1.get_time())
            exit(0)
        
def receive_message():
    # 启动嗅探器并调用回调函数
    host_or_net = "host"
    dst_addr_or_net = dst_address
    if dst_saddr_spoofable:
        host_or_net = "net"
        dst_addr_or_net = extract_ipv6_prefix(dst_address, 64) + "/64"
    filter_condition = ""
    if mode != 'R' and mode != 'A':
        filter_condition = filter_condition_dict[mode]
    elif mode == 'R' or mode == 'A':
        for i in range(len(proto_list)):
            if i == 0:
                filter_condition = '(' + filter_condition_dict[proto_list[i]] + ')'
            else:
                filter_condition = " ".join \
                    ([filter_condition, 'or', '(' + filter_condition_dict[proto_list[i]] + ')'])
    else:
        print(f"ERROR! MODE {mode} IS NOT DEFINED!")
        exit(-1)
    if mode != 'NDP':
        filter_condition = " ".join \
            ([filter_condition, 'and src', host_or_net, dst_addr_or_net])
    
    sniff(filter = filter_condition,
          prn = packet_handler,
          store = 0)

def gen_packet(dstv6, srcv6, proto):
    ipv6_layer = IPv6(src = srcv6, dst = dstv6)
    if proto == 'I':
        complete_packet = ipv6_layer / ICMPv6EchoRequest()
    elif proto == 'T':
        complete_packet = ipv6_layer / \
        TCP(sport = random.randint(4096, 65535),
            dport = random.randint(1, 65535),
            flags = "S")
    elif proto == 'U':
        complete_packet = ipv6_layer / \
        UDP(sport = random.randint(4096, 65535),
            dport = random.randint(1, 65535)) / \
        Raw(load = b'Hello, UDP')
    elif proto == 'S':
        complete_packet = ipv6_layer / \
        SCTP(sport = random.randint(4096, 65535),
            dport = random.randint(1, 65535),
            tag = 1) / \
        SCTPChunkData(data = 'Hello, SCTP')
    elif proto == 'Raw':
        complete_packet = ipv6_layer / Raw(load = b'Hello, Raw')
    else:
        print(f"ERROR! MODE {proto} IS NOT DEFINED!")
        exit(-1)
    # print(complete_packet.summary())
    return complete_packet

def packet_assemble(dstv6, srcv6, mode):
    global proto_list
    if mode != 'R' and mode != 'A' and mode != 'NDP':
        complete_packet = gen_packet(dstv6, srcv6, mode)
    elif mode == 'R': # random mode
        mode = random.choice(proto_list)
        # print(mode)
        complete_packet = gen_packet(dstv6, srcv6, mode)
    elif mode == 'A' or mode == 'NDP': # Alternate mode
        global last_mode, next_mode
        now_mode = next_mode[last_mode]
        last_mode = now_mode
        complete_packet = gen_packet(dstv6, srcv6, now_mode)
    else:
        print(f"ERROR! MODE {mode} IS NOT DEFINED!")
        exit(-1)
    return complete_packet

def send_packet(encrypted_blocks_hex, dstv6_prefix = None, srcv6_prefix = None, block_size = 8):
    # TODO 自动获取源地址
    global source_address, mode
    # 将密文附着于 IPv6 目的地址后 64 位，依次发送
    # 一个 block 是 8 字节，每个 block 转换为 16 进制字符串后长度为 16
    if (dstv6_prefix != None and srcv6_prefix == None) or \
        (dstv6_prefix == None and srcv6_prefix != None):
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
            complete_packet = packet_assemble(dstv6, srcv6, mode)
            send(complete_packet)
    elif dstv6_prefix != None and srcv6_prefix != None:
        for i in range(0, len(encrypted_blocks_hex), 2):
            dstv6 = dstv6_prefix
            srcv6 = srcv6_prefix
            for j in range(0, len(encrypted_blocks_hex[i]), 4):
                dstv6 = dstv6 + ":" + encrypted_blocks_hex[i][j : j + 4]
            for j in range(0, len(encrypted_blocks_hex[i + 1]), 4):
                srcv6 = srcv6 + ":" + encrypted_blocks_hex[i + 1][j : j + 4]
            complete_packet = packet_assemble(dstv6, srcv6, mode)
            send(complete_packet)
    else:
        print(f"ERROR! BOTH ADDRESSES ARE NOT SPOOFABLE!")
        exit(-1)

def send_message(message):
    plain_text = message
    if isinstance(message, str):
        plain_text = message.encode()
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
        block_size = 8
    else:
        print(f"ERROR! BOTH ADDRESSES ARE NOT SPOOFABLE!")
        exit(-1)
    if len(plain_text) % block_size != 0:
        plain_text = pad(plain_text, block_size)
    if source_daddr_spoofable and source_saddr_spoofable and \
        len(plain_text) // block_size % 2 != 0:
        plain_text = pad(plain_text, block_size)
    plaintext_blocks = [plain_text[i : i + block_size] for i in range(0, len(plain_text), block_size)]
    # print(plaintext_blocks)
    encrypted_blocks = cast_encrypt_blocks(key, plaintext_blocks)
    encrypted_blocks_hex = [block.hex() for block in encrypted_blocks]
    # print(encrypted_blocks_hex)
    # print(dstv6_prefix)
    send_packet(encrypted_blocks_hex, dstv6_prefix, srcv6_prefix, block_size)

def send_input():
    while True:
        Input = input("Please input your message: ")
        send_message(Input)


if __name__ == "__main__":
    gen_next_mode_dict()
    # subprocess.Popen(["python3", "ND_NA.py"])
    listen_handler = threading.Thread(target = receive_message)
    listen_handler.start()
    # send_handler = threading.Thread(target = send_message)
    # send_handler.start()