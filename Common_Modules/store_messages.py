from typing import List, Tuple
import sys
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
sys.path.insert(0, parent_dir)
from Common_Modules.error_handle import RECEIVE_CACHE
# from common_modules import packet_seq, write_to_file_event_timer
import threading

# 将明文信息写入接收缓存中特定的位置
# 当接收缓存满时，将接收缓存中的数据包写入文件，并清空接收缓存
def update_receive_cache(receive_cache : RECEIVE_CACHE, \
                         plain_text : str, \
                         packet_seq_num : int, \
                         receive_cache_lock : threading.Lock) -> RECEIVE_CACHE:
    print("ENTER UPDATE RECEIVE CACHE")
    with receive_cache_lock:
        head_seq_num = receive_cache.head_seq
        target_idx = ((packet_seq_num - head_seq_num + receive_cache.seq_max) % receive_cache.seq_max + receive_cache.head) % receive_cache.size
        receive_cache.write_to_pos(target_idx, plain_text, packet_seq_num)
    return receive_cache

def store_receive_cache(receive_cache : RECEIVE_CACHE, \
                        receive_cache_lock : threading.Lock) -> None:
    # 将接受缓存中的数据写入文件，直到遇到 None
    # 从 head 到 tail
    written_text = ''
    with receive_cache_lock:
        print(f"receive_cache: {receive_cache.cache[receive_cache.head : receive_cache.head + 5]}")
        while receive_cache.cache[receive_cache.head][0] != None:
            written_text += receive_cache.cache[receive_cache.head][0]
            receive_cache.cache[receive_cache.head] = (None, None)
            receive_cache.head = (receive_cache.head + 1) % receive_cache.size
            receive_cache.tail = (receive_cache.tail + 1) % receive_cache.size
            receive_cache.head_seq = (receive_cache.head_seq + 1) % receive_cache.seq_max
    print(f"WRITING {written_text} TO FILE")
    if written_text != '':
        with open(receive_cache.get_file_name(), 'a') as f:
            f.write(written_text)
    
    # write_to_file_event_timer.reset()
    return

def test():
    cache = RECEIVE_CACHE()
    cache.file_name = 'test.txt'
    cache.size = 10
    cache.seq_max = 100
    cache.head = 0
    cache.tail = 0
    cache.send_ptr = 0
    cache.cache = [None] * cache.size
    cache = update_receive_cache(cache, b'hello', 0)
    assert cache.cache[0] == b'hello'
    cache = update_receive_cache(cache, b'world', 1)
    assert cache.cache[1] == b'world'
    cache = update_receive_cache(cache, b'!', 2)
    assert cache.cache[2] == b'!'
    cache = update_receive_cache(cache, b'hello', 3)
    assert cache.cache[3] == b'hello'
    cache = update_receive_cache(cache, b'world', 4)
    assert cache.cache[4] == b'world'
    cache = update_receive_cache(cache, b'!', 5)
    assert cache.cache[5] == b'!'
    cache = update_receive_cache(cache, b'hello', 6)
    assert cache.cache[6] == b'hello'
    cache = update_receive_cache(cache, b'world', 7)
    assert cache.cache[7] == b'world'
    cache = update_receive_cache(cache, b'!', 8)
    assert cache.cache[8] == b'!'
    cache = update_receive_cache(cache, b'hello', 9)
    assert cache.cache[9] == b'hello'
    cache = update_receive_cache(cache, b'world', 10)
    assert cache.cache[0] == b'world'
    assert cache.cache[1] == b'!'
    assert cache.cache[2] == b'hello'
    assert cache.cache[3] == b'world'
    assert cache.cache[4] == b'!'
    assert cache.cache[5] == b'hello'
    assert cache.cache[6] == b'world'
    assert cache.cache[7] == b'!'
    assert cache.cache[8] == b'hello'
    assert cache.cache[9] == None
    assert cache.head == 0
    assert cache.tail == 0
    assert cache.send_ptr == 0
    assert cache.file_name == 'test.txt'
    assert cache.size == 10
    

if __name__ == '__main__':
    test()