import sys
import os
# 获取当前文件的目录
current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取父目录
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
# 将父目录添加到sys.path
sys.path.insert(0, parent_dir)

from typing import List, Tuple
from error_handle import SEND_WINDOW, CACHE
from common_modules import packet_seq
from config import inter_time
from scapy.all import send

# 返回发送窗口中尚未被确认的数据包的序列号区间
def seq_num_gen(send_window : SEND_WINDOW) -> list[Tuple[int, int]]:
    
    seq_num_list = []
    window_left = send_window.left
    nowLeft = -1
    for i in range(send_window.window_size):
        # print(seq_num_list)
        
        if send_window.window[i] == False and nowLeft == -1:
            nowLeft = (window_left + i) % send_window.seq_max
            continue
        if send_window.window[i] == True and nowLeft != -1:
            seq_num_list.append((nowLeft, (window_left + i - 1 + send_window.seq_max) % send_window.seq_max))
            nowLeft = -1
        
    if nowLeft != -1:
        seq_num_list.append((nowLeft, (window_left + send_window.window_size - 1 + send_window.seq_max) % send_window.seq_max))
    
    return seq_num_list
    


# 将发送窗口中未被确认的数据包重新发送
def resend_data(send_window : SEND_WINDOW, send_cache : CACHE):
    seq_num_list = seq_num_gen(send_window) # [(int, int), (int, int), ...]
    first_packet_seq_num = seq_num_list[0][0]
    # 在 send_cache 中找到第一个需要重传的数据包
    cache_list = send_cache.iter()
    first_idx = -1
    for i in range(len(cache_list)):
        if packet_seq(cache_list[i]) == first_packet_seq_num:
            first_idx = i
            break
    # 把 send_cache 中对应的子区间提取出来
    if first_idx == -1:
        return False
    # 此时 first_idx 对应seq_num_list[0][0]
    resend_list = []
    left_idx = -1
    right_idx = -1
    for seq_pair in seq_num_list:
        left_seq_num = seq_pair[0]
        right_seq_num = seq_pair[1]
        left_idx = first_idx + (left_seq_num - first_packet_seq_num + send_window.seq_max) % send_window.seq_max
        right_idx = first_idx + (right_seq_num - first_packet_seq_num + send_window.seq_max) % send_window.seq_max
        
        assert(left_seq_num == packet_seq(cache_list[left_idx]) and right_seq_num == packet_seq(cache_list[right_idx]))
        
        resend_list += cache_list[left_idx : right_idx + 1]
    
    # 重传 resend_list 中的数据包
    send(resend_list, inter = inter_time)
    
    
    
    
        
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