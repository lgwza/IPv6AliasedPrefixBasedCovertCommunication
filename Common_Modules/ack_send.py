
from config import NEW_ACK_text, SACK_text
import sys
import os
# 获取当前文件的目录
current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取父目录
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
# 将父目录添加到sys.path
sys.path.insert(0, parent_dir)
from Common_Modules.error_handle import RECEIVE_WINDOW, WINDOW
from typing import List, Tuple, Union

# 对接收窗口内已标记接收的子区间发送 (S)ACK
def ack_num_gen(window_left : int,
             window_right : int,
             flag : list,
             ack_max : int,
             window_size : int):
    assert((window_right - window_left + ack_max) % ack_max == len(flag) and \
            window_size == len(flag))
    # 先发 ACK，后面的子区间发送 SACK
    
    ack_num = None
    sack_list = []
    
    sack_left = None
    
    for i in range(window_size):
        if flag[i] == False and ack_num == None:
            ack_num = (window_left + i) % ack_max
            continue
        if ack_num != None and flag[i] == True:
            if sack_left == None:
                sack_left = (window_left + i) % ack_max
            continue
        if sack_left != None and flag[i] == False:
            sack_list.append((sack_left, (window_left + i - 1) % ack_max))
            sack_left = None
    if sack_left != None:
        sack_list.append((sack_left, (window_right - 1) % ack_max))
    if sack_left == None and ack_num == None:
        ack_num = (window_right) % ack_max
    
    print(f"ACK: {ack_num}, SACK: {sack_list}")
    
    # ACK: 9, SACK: [(10, 10), (12, 1), (3, 3)]
    return ack_num, sack_list

def send_ack(receive_window : WINDOW):
    from common_modules import send_message
    print(f"ENTER SEND ACK")
    window_left = receive_window.left
    window_right = receive_window.right
    ack_max = receive_window.ack_max
    window_size = receive_window.window_size
    flag = receive_window.window
    
    ack_num, sack_list = ack_num_gen(window_left, window_right, flag, ack_max, window_size)
    
    # 发送 ACK, SACK, 并尝试右移接收窗口，右移到接收窗口第一个为未接收的包
    if ack_num != None:
        # 发送 ACK 号为 ack_num 的 ACK 包
        message = NEW_ACK_text + ack_num.to_bytes(2, 'big')
        # print(message)
        
        send_message(message, type = 'ACK', send_directly = True)
    
    if sack_list != []:
        messages = b''
        for sack in sack_list:
            message = SACK_text + sack[0].to_bytes(2, 'big') + sack[1].to_bytes(2, 'big')
            messages += message
            # print(message)
        send_message(messages, type = 'SACK', send_directly = True)
        
    # 尝试右移接收窗口
    # ack_num 为从左到右第一个 False 的位置
    move_step = (ack_num - window_left + ack_max) % ack_max
    receive_window.open(move_step)
    receive_window.close(move_step)
    # receive_window.move_right(move_step)
    
    # from Client.cc_client import ack_event_timer
    # ack_event_timer.reset()
    
    return receive_window
    
    
    
def test_ack_num_gen():
    window_left = 9
    window_right = 19
    ack_max = 2 ** 16 - 2
    window_size = 11
    flag = [False, True, False, True, True, True, True, True, True, False, True]
    ack_num, sack_list = ack_num_gen(window_left, window_right, flag, ack_max, window_size)

    message = NEW_ACK_text + ack_num.to_bytes(2, 'big')
    print(message)
    
    messages = b''
    for sack in sack_list:
        message = SACK_text + sack[0].to_bytes(2, 'big') + sack[1].to_bytes(2, 'big')
        messages += message
    print(messages)

    
    window_left = 9
    window_right = 3
    ack_max = 16
    window_size = 11
    flag = [True, True, True, True, True, False, True, True, True, True, True]
    ack_num, sack_list = ack_num_gen(window_left, window_right, flag, ack_max, window_size)
    message = NEW_ACK_text + ack_num.to_bytes(2, 'big')
    print(message)
    
    messages = b''
    for sack in sack_list:
        message = SACK_text + sack[0].to_bytes(2, 'big') + sack[1].to_bytes(2, 'big')
        messages += message
    print(messages)
    
if __name__ == '__main__':
    # 测试
    test_ack_num_gen()