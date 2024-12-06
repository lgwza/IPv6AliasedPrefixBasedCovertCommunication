
from datetime import datetime, timedelta, timezone
import sys
import os
# 获取当前文件的目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 获取父目录
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))

# 将父目录添加到sys.path
sys.path.insert(0, parent_dir)
sys.path.insert(0, os.path.join(parent_dir, "Common_Modules"))


from scapy.all import IPv6, send, ICMPv6EchoRequest, sniff, TCP, UDP,\
    Raw, SCTP, SCTPChunkData

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

from Common_Modules.common_modules import *
from Common_Modules.timers import *
from Common_Modules.ack_send import send_ack
from Common_Modules.data_resend import resend_data
from Common_Modules.set_flag import flag_set
from Common_Modules.store_messages import update_receive_cache, store_receive_cache
# 忽略所有警告
warnings.filterwarnings("ignore")

resend_data_event_timer.start()

def retransmit_cache_event(ack_num):
    global send_cache, retransmit_flag, retransmit_seq_num
    time.sleep(sleep_time) # 触发重传事件后休眠 2 秒
    # 将发送缓存中的 seq_num 之后的数据包重传
    
    retransmit_seq_num = ack_num
    retransmit_flag = True
    
# 定义回调函数处理接收到的IPv6和ICMPv6包
def packet_handler():
    global status, source_address, dst_address, \
        received_messages, expected_seq, receive_window, \
        send_window, send_cache, receive_cache, receive_cache_lock, \
        resend_data_event_timer, ack_event_timer, write_to_file_event_timer, timer, \
        packet_queue
    while True:
        if stop_event.is_set():
            print("PACKET HANDLER STOPPED")
            exit(0)
        
        
        print(f"PACKET QUEUE SIZE: {packet_queue.qsize()}")
        packet = packet_queue.get()
        if packet is None:
            print("WARNING: PACKET IS NONE")
            continue
        # print(packet[IPv6].src, packet[IPv6].dst)
        # print(f"status: {status}")
        plain_text, packet_type, packet_seq_num, proto = handle_packet(packet)
        print("RECEIVING PACKET")
        print(f"plain_text: {plain_text}")
        print(f"packet_type: {packet_type}")
        print(f"packet_seq_num: {packet_seq_num}")
        print(f"proto: {proto}")
        
        if plain_text == SYN_ACK_text and status == SYN_SENT:
            print("ESTABLISHED")
            status = ESTABLISHED
            
            # INFO 不增加序列号
            receive_window.init_window(packet_seq_num, receive_window_size) # TODO: 初始序列号问题
            receive_cache.head_seq = packet_seq_num
            
            send_message(ACK_text, type = 'INFO', send_directly = True)
            
            send_window.init_window(Seq.get_seq('U'), send_window_size)
            send_handler = threading.Thread(target = send_input)
            send_handler.start()
            
            timer.start()
            print("Timer started")
            
            ack_event_timer.start()
            # resend_data_event_timer.start()
            write_to_file_event_timer.start()
        elif status == ESTABLISHED:
            ack_event_timer.reset() # 收到包后计时重置
            plain_text, packet_type, packet_seq_num, proto = handle_packet(packet)
            # packet_seq_num, ACK: int, SACK: [(int, int)], DATA: int
            
            if packet_type == 'ACK' or packet_type == 'SACK':
                # resend_data_event_timer.reset()
                # 对端已接收，需要在发送窗口中标记对端已接收
                send_window.flag_set(packet_seq_num, packet_type)
                # flag_set(send_window, packet_seq_num, packet_type)
                # resend_data(send_window, send_cache)
            elif packet_type == 'DATA':
                if not receive_window.is_in_window(packet_seq_num):
                    # send_ack(receive_window)
                    # receive_window.send_ack()
                    pass
                else:
                    # 收到的包在接收窗口内
                    # 在接收窗口中标记已接收
                    print("SEQ IS IN WINDOW")
                    # TODO: 更新接收缓存，并且在合适的时候写入文件
                    update_receive_cache(receive_cache, plain_text.decode(), \
                        packet_seq_num, receive_cache_lock)
                    receive_window.flag_set(packet_seq_num, packet_type)
                    
            elif packet_type == 'INFO' and plain_text == RST_text:
                print("RST RECEIVED!!!!!")
                stop_event.set()
                exit(0)
            
def send_input():
    if send_file_mode:
        file_path = "random_text.txt"
        with open(file_path, "r") as f:
            file_message = f.read()
            print(file_message)
            send_message(file_message)
        print("File sent!")
        # send_message(RST_text, type = 'INFO', send_directly = True)
    else:
        while True:
            Input = input("Please input your message: ")
            send_message(Input)

def init():
    global status
    if status == CLOSED:
        Seq.set_seq(random.randint(1, UDP_MAX))
        send_message(SYN_text, type = 'INFO', send_directly = True)
        print("SYN_SENT")
        status = SYN_SENT
        
if __name__ == "__main__":
    gen_next_mode_dict()
    
    receive_handler = threading.Thread(target = packet_handler)
    receive_handler.start()
    
    receive_message_thread = threading.Thread(target = receive_message)
    receive_message_thread.start()
    
    time.sleep(1)
    init()