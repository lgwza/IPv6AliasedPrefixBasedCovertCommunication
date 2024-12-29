import sys
import inspect
import os
# 获取当前文件的目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 获取父目录
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))

# 将父目录添加到sys.path
sys.path.insert(0, parent_dir)
from scapy.all import IPv6, send, ICMPv6EchoRequest, sniff, TCP, UDP,\
    Raw, SCTP, SCTPChunkData, Ether, sendp

from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad, unpad
import threading
from Timer import Timer
import ipaddress
import time
import warnings
import random

from datetime import datetime, timedelta, timezone


from config import *
from Common_Modules.error_handle import *
from timers import ResettableTimer
from store_messages import store_receive_cache
from Common_Modules.ack_send import send_ack
from Common_Modules.data_resend import resend_data
import queue

stop_event = threading.Event()
stop_event.clear()

packet_queue = queue.Queue()

# 忽略所有警告
warnings.filterwarnings("ignore")

status = CLOSED

# import inspect
# caller_name = inspect.stack()[1].filename
# print(inspect.stack())
# print(f"caller_name: {caller_name}")
print("调用 common_modules.py")
print("in common_modules.py, next_mode: ", next_mode)
received_messages = b""
expected_seq = 0

receive_cache = RECEIVE_CACHE(receive_cache_size)
send_cache = SEND_CACHE(send_cache_size)

Ack = ACK()
Seq = SEQ()

receive_window = RECEIVE_WINDOW(max_window_size = receive_window_max_size)
send_window = SEND_WINDOW(max_window_size = send_window_max_size)

# send_window.init_window(Seq.get_seq('U')) # TODO: 一定是 UDP 吗？

retransmit_flag = False
retransmit_seq_num = -1

timer = Timer()


receive_cache_lock = threading.Lock()
send_cache_lock = threading.Lock()

ack_event_timer = ResettableTimer(stop_event, ack_event_timer_interval, \
    receive_window.send_ack)
resend_data_event_timer = ResettableTimer(stop_event, resend_data_event_timer_interval, \
    resend_data, send_window, send_cache)
write_to_file_event_timer = ResettableTimer(stop_event, write_to_file_event_timer_interval, \
    store_receive_cache, receive_cache, receive_cache_lock, timer, stop_event,
    ack_event_timer, resend_data_event_timer)


def gen_next_mode_dict():
    global proto_list, next_mode
    for i in range(len(proto_list)):
        next_mode[proto_list[i]] = proto_list[(i + 1) % len(proto_list)]
    next_mode[''] = proto_list[0]
    # print(next_mode)
    
def save_to_file():
    global received_messages
    if isinstance(received_messages, bytes):
        received_messages = received_messages.decode('latin-1')
    now_utc = datetime.now()
    east_8 = timezone(timedelta(hours = 8))
    now_east_8 = now_utc.astimezone(east_8)
    formatted_time = now_east_8.strftime("%Y%m%d%H%M%S")
    with open(f"Received_Messages/received_messages_{formatted_time}.txt", "w") as f:
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
    # print("ENTER PACKET HANDLER")
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
        try:
            plain_text = unpad(plain_text, 8)
        except ValueError:
            pass
        all_plain_text += plain_text
    proto = packet_proto(packet)
    
    # 判定包类型
    # NEW_ACK_text = b'\x08\x07\x06\x05\x04\x03'
    # SACK_text = b'\x01\x02\x01\x02'
    if len(all_plain_text) == 8:
        # 后 6 个字节为
        if all_plain_text[-6 : ] == NEW_ACK_text:
            packet_seq_num = int.from_bytes(all_plain_text[ : 2], 'big')
            return all_plain_text, 'ACK', packet_seq_num, proto
        # 后 4 个字节为特征
        elif all_plain_text[-4 : ] == SACK_text:
            packet_seq_num = [(int.from_bytes(all_plain_text[ : 2], 'big'), \
                               int.from_bytes(all_plain_text[2 : 4], 'big'))]
    
    elif len(all_plain_text) == 16:
        if all_plain_text[-6 : ] == NEW_ACK_text:
            packet_seq_num = int.from_bytes(all_plain_text[ : 2], 'big')
            return all_plain_text, 'ACK', packet_seq_num, proto
        elif all_plain_text[4 : 8] == SACK_text:
            packet_seq_num = [(int.from_bytes(all_plain_text[ : 2], 'big'), \
                               int.from_bytes(all_plain_text[2 : 4], 'big'))]
            if all_plain_text[12 : ] == SACK_text:
                packet_seq_num.append((int.from_bytes(all_plain_text[8 : 10], 'big'), \
                                       int.from_bytes(all_plain_text[10 : 12], 'big')))
            return all_plain_text, 'SACK', packet_seq_num, proto
    
    # 处理 'DATA' 类型的包
    packet_seq_num = packet_seq(packet)
    packet_type = 'DATA'
    
    if all_plain_text[ : 8] in [SYN_text, SYN_ACK_text, ACK_text, RST_text]:
        packet_type = 'INFO'    
    return all_plain_text, packet_type, packet_seq_num, proto

def packet_seq(packet):
    if 'TCP' in packet:
        return packet['TCP'].seq
    elif 'ICMPv6EchoRequest' in packet:
        return packet['ICMPv6EchoRequest'].seq
    elif 'UDP' in packet:
        return packet['UDP'].sport
    else:
        return -1

def packet_proto(packet):
    if 'TCP' in packet:
        return 'T'
    elif 'ICMPv6EchoRequest' in packet:
        return 'I'
    elif 'UDP' in packet:
        return 'U'
    else:
        return ''
    
def receive_message():
    global packet_queue
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
    filter_condition = " ".join \
        ([filter_condition, 'and src', host_or_net, dst_addr_or_net])
    
    # print(caller_name)
    
    # 获取调用者模块
    # caller_module = sys.modules[caller_name]
    # print(f'caller_module: {caller_module}')
    # 动态获取调用者模块并调用它的 `func`
    print("FILTER CONDITION: ", filter_condition)
    
    def put_packet_into_queue(packet):
        global packet_queue
        packet_queue.put(packet)
        # print("packet_queue size =", packet_queue.qsize())
        if stop_event.is_set():
            ack_event_timer.stop()
            resend_data_event_timer.stop()
            write_to_file_event_timer.stop()
            exit(0)
    
    sniff(filter = filter_condition,
          prn = put_packet_into_queue,
          store = 0,
          iface = source_iface)
    
    
# proto: I ICMPv6, T TCP, U UDP, S SCTP, Raw Raw
# type: D Data, A ACK
def gen_packet(dstv6, srcv6, proto, type = 'DATA'):
    now_seq = random.randint(1, UDP_MAX)
    if type == 'DATA':
        now_seq = Seq.get_seq(proto)
    elif type == 'INFO':
        now_seq = Seq.get_seq(proto)
    elif type == 'ACK':
        # 随机
        now_seq = random.randint(1, UDP_MAX)
    elif type == 'SACK':
        # 随机
        now_seq = random.randint(1, UDP_MAX)
    ipv6_layer = IPv6(src = srcv6, dst = dstv6)
    if proto == 'I':
        complete_packet = ipv6_layer / \
            ICMPv6EchoRequest(seq = now_seq) # TODO 设计一个类
    elif proto == 'T':
        complete_packet = ipv6_layer / \
        TCP(sport = random.randint(4096, 65535),
            dport = random.randint(1, 65535),
            flags = "S",
            seq = now_seq)
    elif proto == 'U':
        complete_packet = ipv6_layer / \
        UDP(sport = now_seq,
            dport = random.randint(1, 65535)) / \
        Raw(load = b'Hello, UDP')
    elif proto == 'S':
        complete_packet = ipv6_layer / \
        SCTP(sport = now_seq,
             dport = random.randint(1, 65535),
             tag = 1) / \
        SCTPChunkData(data = 'Hello, SCTP')
    else:
        print(f"ERROR! MODE {proto} IS NOT DEFINED!")
        exit(-1)
    # print(complete_packet.summary())
    complete_packet = Ether() / complete_packet
    return complete_packet
    
def packet_assemble(dstv6, srcv6, mode, type = 'DATA'):
    global proto_list, last_mode, next_mode
    # print("in packet_assemble")
    # print(f"last_mode: {last_mode}")
    # print(f"next_mode: {next_mode}")
    if mode != 'R' and mode != 'A' and mode != 'NDP':
        complete_packet = gen_packet(dstv6, srcv6, mode, type)
    elif mode == 'R': # random mode
        mode = random.choice(proto_list)
        # print(mode)
        complete_packet = gen_packet(dstv6, srcv6, mode, type)
    elif mode == 'A' or mode == 'NDP': # Alternate mode
        now_mode = next_mode[last_mode]
        last_mode = now_mode
        complete_packet = gen_packet(dstv6, srcv6, now_mode, type)
    else:
        print(f"ERROR! MODE {mode} IS NOT DEFINED!")
        exit(-1)
    
    return complete_packet

def send_packet(encrypted_blocks_hex, dstv6_prefix = None, \
                srcv6_prefix = None, block_size = 8, \
                type = 'DATA', send_directly = False):
    global source_address, mode
    # 将密文附着于 IPv6 目的地址后 64 位，依次发送
    # 一个 block 是 8 字节，每个 block 转换为 16 进制字符串后长度为 16
    complete_packet = None
    if (dstv6_prefix != None and srcv6_prefix == None) or \
        (dstv6_prefix == None and srcv6_prefix != None):
        for i in range(len(encrypted_blocks_hex)):
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
            complete_packet = packet_assemble(dstv6, srcv6, mode, type)
            if not send_directly:
                while not send_cache.is_updatable():
                    # print("not updatable")
                    # time.sleep(sleep_time)
                    continue
                # print("WRITE SEND CACHE", complete_packet.summary())
                send_cache.update(complete_packet)
                # 尝试将发送窗口右边界右移
                # TODO: 一定是 UDP 吗？
                # send_window.extend_to_seq(Seq.get_seq('U'))
                Seq.seq_plus()
            else:
                # print(f"SENDING {type} PACKET DIRECTLY")
                sendp(complete_packet)
                if type == 'DATA':
                    Seq.seq_plus()
    elif dstv6_prefix != None and srcv6_prefix != None:
        for i in range(0, len(encrypted_blocks_hex), 2):
            dstv6 = dstv6_prefix
            srcv6 = srcv6_prefix
            for j in range(0, len(encrypted_blocks_hex[i]), 4):
                dstv6 = dstv6 + ":" + encrypted_blocks_hex[i][j : j + 4]
            for j in range(0, len(encrypted_blocks_hex[i + 1]), 4):
                srcv6 = srcv6 + ":" + encrypted_blocks_hex[i + 1][j : j + 4]
            complete_packet = packet_assemble(dstv6, srcv6, mode, type)
            if not send_directly:
                while not send_cache.is_updatable():
                    # print("not updatable")
                    # time.sleep(sleep_time)
                    continue
                # print("WRITE SEND CACHE", complete_packet.summary())
                send_cache.update(complete_packet)
                # 尝试将发送窗口右边界右移
                # TODO: 一定是 UDP 吗？
                # send_window.extend_to_seq(Seq.get_seq('U'))
                Seq.seq_plus()
            else:
                # print(f"SENDING {type} PACKET DIRECTLY")
                sendp(complete_packet)
                if type == 'DATA':
                    Seq.seq_plus()
    else:
        print(f"ERROR! BOTH ADDRESSES ARE NOT SPOOFABLE!")
        exit(-1)
    
    

def send_message(message, type = 'DATA', send_directly = False):
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
    encrypted_blocks = cast_encrypt_blocks(key, plaintext_blocks)
    encrypted_blocks_hex = [block.hex() for block in encrypted_blocks]
    if not send_directly:
        # print(f"READY TO WRITE PLAIN TEXT {plain_text} TO SEND CACHE")
        pass
    else:
        # print(f"READY TO SEND PLAIN TEXT {plain_text}")
        pass
    send_packet(encrypted_blocks_hex, dstv6_prefix, srcv6_prefix, block_size, type, send_directly)
    
