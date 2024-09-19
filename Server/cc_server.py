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
from Common_Modules.timers import *
from Common_Modules.ack_send import send_ack
from Common_Modules.data_resend import resend_data
from Common_Modules.set_flag import flag_set
from Common_Modules.store_messages import update_receive_cache, store_receive_cache
    
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
    plain_text, packet_type, packet_seq_num, proto = handle_packet(packet)
    print(f"plain_text: {plain_text}")
    print(f"packet_type: {packet_type}")
    print(f"packet_seq_num: {packet_seq_num}")
    print(f"proto: {proto}")
    if plain_text == SYN_text and status == LISTEN:
        print("SYN_RECEIVED")
        status = SYN_RECEIVED
        # 发送 SYN_ACK
        # print(packet[IPv6].src)
        # print("dst_address: ", dst_address)
        send_message(SYN_ACK_text)
        # receive_cache.update(plain_text, packet_seq_num)
    elif plain_text == ACK_text and status == SYN_RECEIVED:
        print("ESTABLISHED")
        # TODO 需要更严谨的逻辑
        status = ESTABLISHED
        send_handler = threading.Thread(target = send_input)
        send_handler.start()
        timer.start()
        print("Timer started")

        # receive_cache.update(plain_text, packet_seq_num)
        receive_window.init_window(packet_seq_num + 1)
        ack_event_timer.start()
        write_to_file_event_timer.start()
    elif status == ESTABLISHED:
        ack_event_timer.reset() # 收到包后计时重置
        # print(f"plain_text: {plain_text}")
        # print(f"packet_type: {packet_type}")
        # print(f"packet_seq_num: {packet_seq_num}")
        # print(f"proto: {proto}")
        # print(packet_seq_num, receive_window.left, \
        #       receive_window.right, proto)
        if packet_type == 'ACK' or packet_type == 'SACK':
            resend_data_event_timer.reset()
            # 对端已接收，需要在发送窗口中标记对端已接收
            flag_set(send_window, packet_seq_num, packet_type)
            resend_data(send_window, send_cache, packet_seq_num, packet_type)
        elif packet_type == 'DATA':
            if not receive_window.is_in_window(packet_seq_num):
                send_ack(receive_window)
            else:
                # 收到的包在接收窗口内
                # 在接收窗口中标记已接收
                flag_set(receive_window, packet_seq_num, packet_type)
                # TODO: 更新接收缓存，并且在合适的时候写入文件
                update_receive_cache(receive_cache, plain_text.decode(), packet_seq_num, receive_cache_lock)

        
        
        # received_messages += plain_text # 字节串
        # print(f"received_message_length: {len(received_messages)}")
        # if len(received_messages) >= 8 and received_messages[-8 :] == RST_text:
        #     print("FINISHED")
        #     received_messages = received_messages[:-8]
        #     save_to_file()
        #     timer.end()
        #     print("Timer stopped")
        #     print("Time elapsed:", timer.get_time())
        #     exit(0)

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
    # print('main')
    # print(next_mode)
    # subprocess.Popen(["python3", "ND_NA.py"])
    listen_handler = threading.Thread(target = receive_message,
                                      args = (sys.modules[__name__],))
    listen_handler.start()
    # send_handler = threading.Thread(target = send_message)
    # send_handler.start()
    send_cache_thread = threading.Thread(target = cache_send)
    send_cache_thread.start()