import sys
import os
# 获取当前文件的目录
current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取父目录
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
# 将父目录添加到sys.path
sys.path.insert(0, parent_dir)

from typing import List, Tuple, Union
from Common_Modules.error_handle import SEND_WINDOW, RECEIVE_WINDOW, \
                         WINDOW, CACHE


# 将接收/发送窗口内相应的包序列号标记为已接收/被确认
def flag_set(window : WINDOW, \
             packet_seq_num : Union[int, List[Tuple[int, int]]], \
             packet_type : str = 'ACK') -> WINDOW:
    # packet_seq_num, ACK: int, SACK: [(int, int), (int, int)], DATA: int
    
    
    if packet_type == 'ACK': # 标记发送窗口相应区间已确认, [left, ACK) 已确认
        winRight = (packet_seq_num - window.left + window.seq_max) % window.seq_max
        window.window[:winRight] = [True] * winRight
    elif packet_type == 'SACK': # 标记发送窗口相应区间已确认, [sack_left, sack_right] 已确认
        for sack in packet_seq_num:
            sack_left = sack[0]
            sack_right = sack[1]
            winLeft = (sack[0] - window.left + window.seq_max) % window.seq_max
            winRight = (sack[1] - window.left + window.seq_max) % window.seq_max
            window.window[winLeft : winRight + 1] = [True] * (winRight - winLeft + 1)
    elif packet_type == 'DATA': # 标记接收窗口
        winPos = (packet_seq_num - window.left + window.ack_max) % window.ack_max
        window.window[winPos] = True
        
    return window

def test():
    pass

if __name__ == '__main__':
    test()