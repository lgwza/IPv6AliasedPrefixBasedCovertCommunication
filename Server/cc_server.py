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
from Common_Modules.error_handle import *
from Common_Modules.common_modules import *
from Common_Modules.timers import *
from Common_Modules.ack_send import send_ack
from Common_Modules.data_resend import resend_data
from Common_Modules.set_flag import flag_set
from Common_Modules.store_messages import update_receive_cache, store_receive_cache
    

# 定义回调函数处理接收到的IPv6和ICMPv6包
def packet_handler():
    global status, source_address, dst_address, \
        received_messages, expected_seq, receive_window, \
        send_window, send_cache, receive_cache, receive_cache_lock, \
        resend_data_event_timer, ack_event_timer, write_to_file_event_timer, \
        timer, receive_cache_head_seq
    # print("Source IPv6 address: ", packet[IPv6].src)
    # print("status: ", status)    
    while True:
        print(f"PACKET QUEUE: {packet_queue}")
        packet = packet_queue.get()
        if packet is None:
            continue
        plain_text, packet_type, packet_seq_num, proto = handle_packet(packet)
        print("ENTER PACKET HANDLER")
        print(f"plain_text: {plain_text}")
        print(f"packet_type: {packet_type}")
        print(f"packet_seq_num: {packet_seq_num}")
        print(f"proto: {proto}")
        if plain_text == SYN_text and status == LISTEN:
            print("SYN_RECEIVED")
            status = SYN_RECEIVED
            Seq.set_seq(random.randint(1, UDP_MAX))
            send_message(SYN_ACK_text, type = 'INFO', send_directly = True)        
            
        elif plain_text == ACK_text and status == SYN_RECEIVED:
            print("ESTABLISHED")
            # TODO 需要更严谨的逻辑
            status = ESTABLISHED
            
            send_window.init_window(Seq.get_seq('U'), 5000)
            send_handler = threading.Thread(target = send_input)
            send_handler.start()
            
            resend_data_event_timer.start()
            
            timer.start()
            print("Timer started")
            
            
            # INFO 不增加序列号
            receive_window.init_window(packet_seq_num, 5000) # TODO: 处理 INFO 的序列号问题
            receive_cache.head_seq = packet_seq_num
            
            ack_event_timer.start()
            write_to_file_event_timer.start()
        elif status == ESTABLISHED:
            ack_event_timer.reset() # 收到包后计时重置
            if packet_type == 'ACK' or packet_type == 'SACK':
                resend_data_event_timer.reset()
                # 对端已接收，需要在发送窗口中标记对端已接收
                send_window.flag_set(packet_seq_num, packet_type)
                resend_data(send_window, send_cache)
            elif packet_type == 'DATA':
                print("RECEIVING DATA")
                print(f"{receive_window.left} {receive_window.right}")
                if not receive_window.is_in_window(packet_seq_num):
                    # send_ack(receive_window)
                    receive_window.send_ack()
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
                exit(0)

def send_input():
    while True:
        Input = input("Please input your message: ")
        send_message(Input)

if __name__ == "__main__":
    status = LISTEN
    gen_next_mode_dict()
    
    listen_handler = threading.Thread(target = packet_handler)
    listen_handler.start()

    receive_message_thread = threading.Thread(target = receive_message)
    receive_message_thread.start()
    
    listen_handler.join()
    receive_message_thread.join()
    