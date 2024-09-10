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
from Common_Modules.common_modules import *
    
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