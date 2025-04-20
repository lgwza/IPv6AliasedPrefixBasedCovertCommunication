import sys
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
sys.path.insert(0, parent_dir)

from typing import List, Tuple
from Common_Modules.error_handle import SEND_WINDOW, CACHE, WINDOW, SEND_CACHE

from config import inter_time, source_iface, real_inter_time
from scapy.all import send, sendp

# 返回发送窗口中数据包尚未被确认的序列号闭区间
# 但相应数据包不一定在发送缓存中存在
def seq_num_gen(send_window : WINDOW) -> List[Tuple[int, int]]:
    
    seq_num_section_list = []
    window_left = send_window.left
    nowLeft = -1
    for i in range(send_window.window_size):
        # print(seq_num_list)
        
        if send_window.window[i] == False and nowLeft == -1:
            nowLeft = (window_left + i) % send_window.seq_max
            continue
        if send_window.window[i] == True and nowLeft != -1:
            seq_num_section_list.append((nowLeft, (window_left + i - 1 + send_window.seq_max) % send_window.seq_max))
            nowLeft = -1
        
    if nowLeft != -1:
        seq_num_section_list.append((nowLeft, (window_left + send_window.window_size - 1 + send_window.seq_max) % send_window.seq_max))
    
    return seq_num_section_list
    


# 将发送窗口中未被确认的数据包重新发送
# 并且在发送缓存中是存在的
def resend_data(send_window : SEND_WINDOW, send_cache : SEND_CACHE):
    # print("ENTER RESEND_DATA")
    from common_modules import packet_seq
    seq_num_section_list = seq_num_gen(send_window) # [(int, int), (int, int), ...]，每个元组表示一个序列号区间，区间内的数据包需要重传
    if len(seq_num_section_list) == 0:
        # print("NO DATA TO SEND")
        return
    first_packet_seq_num = seq_num_section_list[0][0]
    # 在 send_cache 中找到第一个需要重传的数据包
    cache_list = send_cache.iter()
    if cache_list == None:
        return
    first_idx = -1
    # print(f"seq_num_section_list: {seq_num_section_list}")
    # first_idx = first_packet_seq_num - send_cache.head_seq
    head_seq = packet_seq(cache_list[0])
    first_idx = (first_packet_seq_num - head_seq + send_window.seq_max) % send_window.seq_max
    # for i in range(len(cache_list)):
    #     if packet_seq(cache_list[i]) == first_packet_seq_num:
    #         assert(i == first_idx)
    #         first_idx = i
    #         break
    # 把 send_cache 中对应的子区间提取出来
    if first_idx == -1:
        return False
    # 此时 first_idx 对应seq_num_list[0][0]
    resend_list = []
    left_idx = -1
    right_idx = -1
    for seq_pair in seq_num_section_list:
        left_seq_num = seq_pair[0]
        right_seq_num = seq_pair[1]
        left_idx = first_idx + (left_seq_num - first_packet_seq_num + send_window.seq_max) % send_window.seq_max
        right_idx = first_idx + (right_seq_num - first_packet_seq_num + send_window.seq_max) % send_window.seq_max
        if left_idx >= len(cache_list):
            continue
        right_idx = min(right_idx, len(cache_list) - 1)
        
        # assert(left_seq_num == packet_seq(cache_list[left_idx]) and right_seq_num == packet_seq(cache_list[right_idx]))
        
        resend_list += cache_list[left_idx : right_idx + 1]
    # print(f"RESENDING LIST: {resend_list}")
    # 重传 resend_list 中的数据包
    sendp(resend_list, inter = inter_time, iface = source_iface, verbose = False)
        
def test():
    send_window = SEND_WINDOW(10)
    send_window.init_window(2 ** 16 - 5)
    send_window.window = [True, False, False, True, True, False, False, False, True, True]
    ret = seq_num_gen(send_window)
    print(ret)
        
if __name__ == "__main__":
    # ret = seq_num_gen(1)
    # print(ret)
    test()