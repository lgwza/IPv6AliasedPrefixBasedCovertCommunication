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
import random
import time

# 获取当前文件的目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 获取父目录
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))

# 将父目录添加到sys.path
sys.path.insert(0, parent_dir)
sys.path.insert(0, os.path.join(parent_dir, "Common_Modules"))
from config import *
from error_handle import *
<<<<<<< HEAD
from Common_Modules.common_modules import *
=======

timer = Timer()

status = LISTEN

last_mode = ''
next_mode = {}

received_messages = b""
expected_seq = 0
receive_cache = CACHE(100)
send_cache = CACHE(100)
Ack = ACK()
Seq = SEQ()

send_packet_pause_event = threading.Event()
send_packet_pause_event.set()

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
    with open(f"Received_Messages/received_messages_{formatted_time}.txt", "w") as f:
        f.write(received_messages)


def extract_ipv6_prefix(ipv6_address, prefix_length):
    # 将输入的字符串转换为 IPv6 对象
    ipv6 = ipaddress.IPv6Address(ipv6_address)
>>>>>>> 0b7d551bf14385ca2199696829a100ea89482681
    
def retransmit_cache(ack_num):
    global send_cache
    time.sleep(sleep_time) # 触发重传事件后休眠 2 秒
    # 将发送缓存中的 seq_num 之后的数据包重传
    for packet in send_cache.iter():
        if packet_seq(packet) >= ack_num:
            send(packet)
            time.sleep(sleep_time)
            print("Retransmitting packet with seq_num:", packet_seq(packet))
            

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
    
def retransmit_cache(ack_num):
    global send_cache
    time.sleep(sleep_time) # 触发重传事件后休眠 2 秒
    # 将发送缓存中的 seq_num 之后的数据包重传
    for packet in send_cache.iter():
        if packet_seq(packet) >= ack_num:
            send(packet)
            time.sleep(sleep_time)
            print("Retransmitting packet with seq_num:", packet_seq(packet))
            

# 定义回调函数处理接收到的IPv6和ICMPv6包
def packet_handler(packet):
    global status, source_address, dst_address, \
        received_messages, expected_seq
    # print("Source IPv6 address: ", packet[IPv6].src)
    # print("status: ", status)
    if handle_packet(packet) == SYN_text and status == LISTEN:
        print("SYN_RECEIVED")
        status = SYN_RECEIVED
        # 发送 SYN_ACK
        # print(packet[IPv6].src)
        # print("dst_address: ", dst_address)
        send_message(SYN_ACK_text)
        Ack.set_ack(packet_seq(packet) + 1)
        receive_cache.update(packet)

    elif handle_packet(packet) == ACK_text and status == SYN_RECEIVED:
        print("ESTABLISHED")
        # TODO 需要更严谨的逻辑
        status = ESTABLISHED
        send_handler = threading.Thread(target = send_input)
        send_handler.start()
        timer.start()
        print("Timer started")
        Ack.ack_plus()
        receive_cache.update(packet)
    elif status == ESTABLISHED:
        packet_seq_num = packet_seq(packet)
        proto = packet_proto(packet)
        plain_text = handle_packet(packet)
        print("received message:", plain_text.decode('latin-1'))
        print(packet_seq_num, Ack.get_ack(proto), proto)
        if handle_packet(packet) == ACK_text:
            send_packet_pause_event.clear()
            retransmit_cache(packet_seq_num)
            send_packet_pause_event.set()
            return
        if packet_seq_num == Ack.get_ack(proto):
            Ack.ack_plus()
            receive_cache.update(packet)
        else:
            
            send_message(ACK_text, type = 'A')
            return
        
        received_messages += plain_text # 字节串
        print(f"received_message_length: {len(received_messages)}")
        if len(received_messages) >= 8 and received_messages[-8 :] == RST_text:
            print("FINISHED")
            received_messages = received_messages[:-8]
            save_to_file()
            timer.end()
            print("Timer stopped")
            print("Time elapsed:", timer.get_time())
            exit(0)
<<<<<<< HEAD

def cache_send():
    global retransmit_flag, retransmit_seq_num
    while 1:
        if retransmit_flag == True:
            retransmit_flag = False
            assert(send_cache.send_ptr_back(retransmit_seq_num) == True)
            print(f"Retransmitting {retransmit_seq_num}")
        # print(send_cache.cache)
        if send_cache.is_sendable():
            # packet = send_cache.get_packet()
            # print(packet.summary())
            packet_list = send_cache.get_packet_list()
            send(packet_list, inter = inter_time)
            # send_cache.send_ptr_plus()
        #     time.sleep(sleep_time)
        # else:
        #     time.sleep(sleep_time * 2)
=======


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

# proto: I ICMPv6, T TCP, U UDP, S SCTP, Raw Raw
# type: D Data, A ACK
def gen_packet(dstv6, srcv6, proto, type = 'D'):
    if type == 'D':
        now_seq = Seq.get_seq(proto)
    elif type == 'A':
        now_seq = Ack.get_ack(proto)
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
    return complete_packet

def packet_assemble(dstv6, srcv6, mode, type = 'D'):
    global proto_list
    if mode != 'R' and mode != 'A' and mode != 'NDP':
        complete_packet = gen_packet(dstv6, srcv6, mode, type)
    elif mode == 'R': # random mode
        mode = random.choice(proto_list)
        # print(mode)
        complete_packet = gen_packet(dstv6, srcv6, mode, type)
    elif mode == 'A' or mode == 'NDP': # Alternate mode
        global last_mode, next_mode
        now_mode = next_mode[last_mode]
        last_mode = now_mode
        complete_packet = gen_packet(dstv6, srcv6, now_mode, type)
    else:
        print(f"ERROR! MODE {mode} IS NOT DEFINED!")
        exit(-1)
    send_packet_pause_event.wait()
    Seq.seq_plus()
    send_cache.update(complete_packet)
    return complete_packet

def send_packet(encrypted_blocks_hex, dstv6_prefix = None, srcv6_prefix = None, block_size = 8, type = 'D'):
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
            complete_packet = packet_assemble(dstv6, srcv6, mode, type)
            send(complete_packet)
    elif dstv6_prefix != None and srcv6_prefix != None:
        for i in range(0, len(encrypted_blocks_hex), 2):
            dstv6 = dstv6_prefix
            srcv6 = srcv6_prefix
            for j in range(0, len(encrypted_blocks_hex[i]), 4):
                dstv6 = dstv6 + ":" + encrypted_blocks_hex[i][j : j + 4]
            for j in range(0, len(encrypted_blocks_hex[i + 1]), 4):
                srcv6 = srcv6 + ":" + encrypted_blocks_hex[i + 1][j : j + 4]
            complete_packet = packet_assemble(dstv6, srcv6, mode, type)
            send(complete_packet)
    else:
        print(f"ERROR! BOTH ADDRESSES ARE NOT SPOOFABLE!")
        exit(-1)

def send_message(message, type = 'D'):
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
    send_packet(encrypted_blocks_hex, dstv6_prefix, srcv6_prefix, block_size, type)
>>>>>>> 0b7d551bf14385ca2199696829a100ea89482681

def send_input():
    while True:
        Input = input("Please input your message: ")
        send_message(Input)

if __name__ == "__main__":
    status = LISTEN
    gen_next_mode_dict()
    # subprocess.Popen(["python3", "ND_NA.py"])
    listen_handler = threading.Thread(target = receive_message,
                                      args = (sys.modules[__name__],))
    listen_handler.start()
    # send_handler = threading.Thread(target = send_message)
    # send_handler.start()
    send_cache_thread = threading.Thread(target = cache_send)
    send_cache_thread.start()