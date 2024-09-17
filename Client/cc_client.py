
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
from error_handle import *

from Common_Modules.common_modules import *
from Common_Modules.timers import *
from Common_Modules.ack_send import send_ack
from Common_Modules.data_resend import resend_data
from Common_Modules.set_flag import flag_set
from Common_Modules.store_messages import update_receive_cache, store_receive_cache
# 忽略所有警告
warnings.filterwarnings("ignore")


ack_event_timer = ResettableTimer(0.2, send_ack, receive_window)
resend_data_event_timer = ResettableTimer(2, resend_data, send_window, send_cache)
write_to_file_event_timer = ResettableTimer(2, store_receive_cache, receive_cache)

receive_cache_lock = threading.Lock()


def retransmit_cache_event(ack_num):
    global send_cache, retransmit_flag, retransmit_seq_num
    time.sleep(sleep_time) # 触发重传事件后休眠 2 秒
    # 将发送缓存中的 seq_num 之后的数据包重传
    
    retransmit_seq_num = ack_num
    retransmit_flag = True
    
    

    
# 定义回调函数处理接收到的IPv6和ICMPv6包
def packet_handler(packet):
    global status, source_address, dst_address, \
        received_messages, expected_seq
    # print(packet[IPv6].src, packet[IPv6].dst)
    # print(f"status: {status}")
    if handle_packet(packet) == SYN_ACK_text and status == SYN_SENT:
        print("ESTABLISHED")
        status = ESTABLISHED
        send_message(ACK_text)
        
        receive_window.init_window(packet_seq(packet) + 1)
        Ack.set_ack(packet_seq(packet) + 1)
        receive_cache.update(packet)
        
        send_handler = threading.Thread(target = send_input)
        send_handler.start()
        
        timer.start()
        print("Timer started")
    elif status == ESTABLISHED:
        ack_event_timer.reset() # 收到包后计时重置
        plain_text, packet_type, packet_seq_num, proto = handle_packet(packet)
        # packet_seq_num, ACK: int, SACK: [(int, int)], DATA: int
        
        print(f"plain_text: {plain_text}")
        print(f"packet_type: {packet_type}")
        print(f"packet_seq_num: {packet_seq_num}")
        print(f"proto: {proto}")
        
        if packet_type == 'ACK' or packet_type == 'SACK':
            resend_data_event_timer.reset()
            # 对端已接收，需要在发送窗口中标记对端已接收
            flag_set(send_window, packet_seq_num, packet_type)
            resend_data(send_window, send_cache, packet_seq_num, packet_type)
        elif packet_type == 'DATA':
            if not receive_window.is_in_window(packet_seq_num):
                send_ack()
            else:
                # 收到的包在接收窗口内
                # 在接收窗口中标记已接收
                flag_set(receive_window, packet_seq_num, packet_type)
                # TODO: 更新接收缓存，并且在合适的时候写入文件
                update_receive_cache(receive_cache, plain_text.decode(), packet_seq_num, receive_cache_lock)
        
        # packet_seq_num = packet_seq(packet)
        # proto = packet_proto(packet)
        
        # if handle_packet(packet) == ACK_text:
        #     print("ACK received")
        #     send_packet_pause_event.clear()
        #     retransmit_cache_event(packet_seq_num)
        #     send_packet_pause_event.set()
        #     return
        # if packet_seq_num == Ack.get_ack(proto):
        #     Ack.ack_plus()
        #     receive_cache.update(packet)
        # else:
        #     send_message(ACK_text, type = 'A')
        #     return
        # received_messages += plain_text
        # print(f"received_message_length: {len(received_messages)}")
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
    if send_file_mode:
        file_path = "random_text.txt"
        with open(file_path, "r") as f:
            file_message = f.read()
            print(file_message)
            send_message(file_message)
        print("File sent!")
        send_message(RST_text)
    else:
        while True:
            Input = input("Please input your message: ")
            send_message(Input)

def init():
    global status
    if status == CLOSED:
        send_message(SYN_text)
        print("SYN_SENT")
        status = SYN_SENT
        
if __name__ == "__main__":
    gen_next_mode_dict()
    receive_handler = threading.Thread(target = receive_message,
                                       args = (sys.modules[__name__],))
    receive_handler.start()
    time.sleep(1)
    init()
    time.sleep(1)
    send_cache_thread = threading.Thread(target = cache_send)
    send_cache_thread.start()
    
    
    