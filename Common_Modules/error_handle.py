import random
import queue
from datetime import datetime, timezone, timedelta
from typing import List, Tuple, Union
from config import NEW_ACK_text, SACK_text


TCP_MAX = 2 ** 32 - 2
ICMP_MAX = 2 ** 16 - 2
UDP_MAX = 2 ** 16 - 2
SCTP_MAX = 2 ** 16 - 2

class SEQ:
    def __init__(self):
        self.seq = random.randint(0, ICMP_MAX)
    
    def set_seq(self, seq):
        self.seq = seq
        return True
    
    def get_seq(self):
        return self.seq
    
    def seq_plus(self):
        self.seq += 1
        return self.seq
    
    def get_seq_tcp(self):
        return self.seq % TCP_MAX
    
    def get_seq_icmp(self):
        return self.seq % ICMP_MAX
    
    def get_seq_udp(self):
        return self.seq % UDP_MAX
    
    def get_seq_sctp(self):
        return self.seq % SCTP_MAX
    
    def get_seq(self, proto):
        if proto == 'T':
            return self.get_seq_tcp()
        elif proto == 'I':
            return self.get_seq_icmp()
        elif proto == 'U':
            return self.get_seq_udp()
        elif proto == 'S':
            return self.get_seq_sctp()
        else:
            return -1
        
class ACK:
    def __init__(self):
        self.ack = -1
        
    def set_ack(self, ack):
        self.ack = ack
        return True
    
    def ack_plus(self):
        self.ack += 1
        return self.ack
    
    def get_ack_tcp(self):
        return self.ack % TCP_MAX
    
    def get_ack_icmp(self):
        return self.ack % ICMP_MAX
    
    def get_ack_udp(self):
        return self.ack % UDP_MAX
    
    def get_ack_sctp(self):
        return self.ack % SCTP_MAX
    
    def get_ack(self, proto):
        if proto == 'T':
            return self.get_ack_tcp()
        elif proto == 'I':
            return self.get_ack_icmp()
        elif proto == 'U':
            return self.get_ack_udp()
        elif proto == 'S':
            return self.get_ack_sctp()
        else:
            return -1
        
        
class WINDOW:
    def __init__(self, max_window_size : int = 1000):
        self.max_window_size = max_window_size
        self.window_size = 0
        self.window = []
        # [left, right)
        self.left = 0
        self.right = 0
        self.seq_max = UDP_MAX
    
    def init_window(self, left : int, window_size : int) -> bool:
        self.left = left
        self.window_size = window_size
        self.right = (self.left + self.window_size) % self.seq_max
        self.window = [False] * window_size
        return True
        
    def is_in_window(self, seq : int) -> bool:
        if self.left <= seq and seq < self.right:
            return True
        if self.right < self.left and (self.left <= seq or seq < self.right):
            return True
        return False
        
    # 右边界右移
    def open(self, delta_size : int) -> bool:
        if self.window_size + delta_size > self.max_window_size:
            print("WARNING: WINDOW SIZE EXCEEDS MAXIMUM")
            return False
        self.window_size += delta_size
        self.right = (self.left + self.window_size) % self.seq_max
        self.window += [False] * delta_size
        return True
    
    # 左边界右移
    def close(self, delta_size : int) -> bool:
        if self.window_size - delta_size < 0:
            print("WARNING: WINDOW SIZE LESS THAN ZERO")
            return False
        self.window_size -= delta_size
        self.left = (self.left + delta_size) % self.seq_max
        self.window = self.window[delta_size :]
        return True
    
    # 右边界左移
    def shrink(self, delta_size : int) -> bool:
        if self.window_size - delta_size < 0:
            print("WARNING: WINDOW SIZE LESS THAN ZERO")
            return False
        self.window_size -= delta_size
        self.window = self.window[: -delta_size]
        self.right = (self.left + self.window_size) % self.seq_max
        return True
        
    def is_empty(self):
        return self.window_size == 0
    
    def extend_to_seq(self, seq : int) -> bool:
        if self.is_in_window(seq):
            print("WARNING: UNABLE TO EXTEND")
            print(f"SEQ {seq} IN WINDOW [{self.left}, {self.right})")
            return False
        extend_len = (seq - self.right + 1 + self.seq_max) % self.seq_max
        self.open(extend_len)
        return True
    
    def flag_set(self, packet_seq_num : Union[int, List[Tuple[int, int]]], \
                 packet_type : str) -> bool:
        # packet_seq_num, ACK: int, SACK: [(int, int), (int, int)], DATA: int
        # 对于 ACK，标记发送窗口中 [left, ACK) 已确认
        if packet_type == 'ACK':
            if not self.is_in_window(packet_seq_num):
                print("WARNING: ACK NUMBER OUT OF WINDOW")
                return False
            winRight = (packet_seq_num - self.left + self.seq_max) % self.seq_max
            self.window[:winRight] = [True] * winRight
            return True
        # 对于 SACK，标记发送窗口中 [sack_left, sack_right] 已确认
        elif packet_type == 'SACK':
            for sack in packet_seq_num:
                sack_left = sack[0]
                sack_right = sack[1]
                if not self.is_in_window(sack_left) or not self.is_in_window(sack_right):
                    print("WARNING: SACK SECTION OUT OF WINDOW")
                    return False
                    
                winLeft = (sack[0] - self.left + self.seq_max) % self.seq_max
                winRight = (sack[1] - self.left + self.seq_max) % self.seq_max
                self.window[winLeft : winRight + 1] = [True] * (winRight - winLeft + 1)
        # 对于 DATA，标记接收窗口
        elif packet_type == 'DATA':
            if not self.is_in_window(packet_seq_num):
                print("WARNING: DATA NUMBER OUT OF WINDOW")
                return False
            winPos = (packet_seq_num - self.left + self.seq_max) % self.seq_max
            self.window[winPos] = True
        return True
    
class RECEIVE_WINDOW(WINDOW):
    def __init__(self, max_window_size : int = 1000):
        super().__init__(max_window_size)
    
    def ack_num_gen(self):
        ack_num = None
        sack_list = []
        sack_left = None
        for i in range(self.window_size):
            if self.window[i] == False and ack_num == None:
                ack_num = (self.left + i) % self.seq_max
                continue
            if ack_num != None and self.window[i] == True:
                if sack_left == None:
                    sack_left = (self.left + i) % self.seq_max
                continue
            if sack_left != None and self.window[i] == False:
                sack_list.append((sack_left, (self.left + i - 1) % self.seq_max))
                sack_left = None
        if sack_left != None:
            sack_list.append((sack_left, (self.right - 1) % self.seq_max))
        if sack_left == None and ack_num == None:
            ack_num = (self.right) % self.seq_max
        
        # print("ACK NUM GENERATED")
        # print(f"ACK: {ack_num}, SACK: {sack_list}")
        
        return ack_num, sack_list
    
    def send_ack(self):
        from common_modules import send_message
        # print("ENTER SEND ACK")
        ack_num, sack_list = self.ack_num_gen()
        
        if ack_num != None:
            message = ack_num.to_bytes(2, 'big') + NEW_ACK_text
            send_message(message, type = 'ACK', send_directly = True)
        
        if sack_list != []:
            messages = b''
            for sack in sack_list:
                message = sack[0].to_bytes(2, 'big') + sack[1].to_bytes(2, 'big') + SACK_text
                messages += message
            send_message(messages, type = 'SACK', send_directly = True)
        return True
    
    def flag_set(self, packet_seq_num : Union[int, List[Tuple[int, int]]], \
                 packet_type : str) -> bool:
        # packet_seq_num, ACK: int, SACK: [(int, int)], DATA: int
        if packet_type == 'DATA':
            if not self.is_in_window(packet_seq_num):
                print("WARNING: DATA NUMBER OUT OF WINDOW")
                return False
            winPos = (packet_seq_num - self.left + self.seq_max) % self.seq_max
            self.window[winPos] = True
            if winPos == 0:
                # 右移窗口
                # 确定窗口中第一个未接收的包
                try:
                    falsePos = self.window.index(False)
                except:
                    falsePos = self.window_size
                self.close(falsePos)
                self.open(falsePos)
                
        else:
            print("WARNING: RECEIVE WINDOW ONLY SUPPORT DATA PACKET")
        return True
    
    
class SEND_WINDOW(WINDOW):
    def __init__(self, max_window_size : int = 1000):
        super().__init__(max_window_size)
        
    def flag_set(self, packet_seq_num : Union[int, List[Tuple[int, int]]], \
                 packet_type : str) -> bool:
        # packet_seq_num, ACK: int, SACK: [(int, int)], DATA: int
        # 对于 ACK，标记发送窗口中 [left, ACK) 已确认
        if packet_type == 'ACK':
            if not self.is_in_window(packet_seq_num) and packet_seq_num != self.right:
                print(f"WINDOW: {self.left}, {self.right}")
                print("WARNING: ACK NUMBER OUT OF WINDOW")
                return False
            winRight = (packet_seq_num - self.left + self.seq_max) % self.seq_max
            self.window[:winRight] = [True] * winRight
        # 对于 SACK，标记发送窗口中 [sack_left, sack_right] 已确认
        elif packet_type == 'SACK':
            for sack in packet_seq_num:
                sack_left = sack[0]
                sack_right = sack[1]
                if not self.is_in_window(sack_left) or not self.is_in_window(sack_right):
                    print("WARNING: SACK SECTION OUT OF WINDOW")
                    return False
                winLeft = (sack[0] - self.left + self.seq_max) % self.seq_max
                winRight = (sack[1] - self.left + self.seq_max) % self.seq_max
                self.window[winLeft : winRight + 1] = [True] * (winRight - winLeft + 1)
        else:
            print("WARNING: SEND WINDOW ONLY SUPPORT ACK AND SACK PACKET")
            return False
        try:
            falsePos = self.window.index(False)
        except:
            falsePos = self.window_size
        self.close(falsePos)
        self.open(falsePos)
        return True
    
class CACHE:
    # 队列缓存
    def __init__(self, size = 100):
        self.size = size
        self.cache = [None] * size
        self.head = 0
        self.tail = 0
        self.send_ptr = 0
        self.seq_max = UDP_MAX
        self.file_name = self.gen_file_name()
    
    def is_empty(self):
        return self.head == self.tail
    
    def is_full(self):
        return (self.tail + 1) % self.size == self.head
    
    def add(self, data):
        if self.is_full():
            return False
        self.cache[self.tail] = data
        self.tail = (self.tail + 1) % self.size
        return True
    
    def pop(self):
        if self.is_empty():
            return None
        data = self.cache[self.head]
        self.head = (self.head + 1) % self.size
        return data
    
    # 更新
    def update(self, data):
        if self.is_full():
            self.pop()
        self.add(data)
        return True
    
    def iter(self):
        if self.is_empty():
            return None
        # 从头到尾遍历
        lis = []
        if self.head < self.tail:
            lis = self.cache[self.head : self.tail]
        else:
            lis = self.cache[self.head :] + self.cache[: self.tail]
        return lis
    
    def is_sendable(self):
        if self.is_empty():
            return False
        if self.head <= self.send_ptr and self.send_ptr < self.tail:
            return True
        if self.tail < self.head and self.head <= self.send_ptr:
            return True
        if self.send_ptr < self.tail and self.tail < self.head:
            return True
        return False
    
    def is_updatable(self):
        if not self.is_full():
            return True
        if (self.send_ptr - self.head + self.size) % self.size > self.size * 0.1:
            return True
        return False
    
    def get_packet(self):
        if self.is_sendable():
            return self.cache[self.send_ptr]
    
    def get_packet_list(self):
        # 从 send_ptr 到 tail
        lis = []
        i = self.send_ptr
        while i != self.tail:
            lis.append(self.cache[i])
            i = (i + 1) % self.size
        self.send_ptr = self.tail
        return lis
    
    def send_ptr_plus(self):
        self.send_ptr = (self.send_ptr + 1) % self.size
        return True
    
    def packet_seq(self, ptr):
        try:
            packet = self.cache[ptr]
        except:
            return -1
        if 'TCP' in packet:
            return packet['TCP'].seq
        elif 'ICMPv6EchoRequest' in packet:
            return packet['ICMPv6EchoRequest'].seq
        elif 'UDP' in packet:
            return packet['UDP'].sport
        else:
            return -1
        
    def send_ptr_back(self, Seq):
        if self.is_empty():
            return False
        i = self.head
        while i != self.tail:
            if self.packet_seq(i) == Seq:
                self.send_ptr = i
                return True
            i = (i + 1) % self.size
        return False
    
    def gen_file_name(self):
        # received_messages_ + 当前时间
        now_utc = datetime.now()
        east_8 = timezone(timedelta(hours = 8))
        now_east_8 = now_utc.astimezone(east_8)
        formatted_time = now_east_8.strftime("%Y%m%d%H%M%S")
        self.file_name = 'Received_Messages/received_messages_' + formatted_time + '.txt'
        return self.file_name
    
    def get_file_name(self):
        return self.file_name

class RECEIVE_CACHE(CACHE):
    def __init__(self, size = 100):
        super().__init__(size)
        self.cache = [(None, None)] * size
        self.head = 0
        self.tail = size - 1
        self.head_seq = 0
        
    def add(self, text, seq):
        if self.is_full():
            return False
        self.cache[self.tail] = (text, seq)
        self.tail = (self.tail + 1) % self.size
        return True
    
    def update(self, text, seq):
        if self.is_full():
            self.pop()
        self.add(text, seq)
        return True
    
    def write_to_pos(self, idx, text, seq):
        assert(0 <= idx and idx < self.size)
        # assert(self.cache[idx] == (None, None))
        print(f"WRITING {text} TO CACHE AT {idx}")
        print(f"CACHE HEAD: {self.head}, CACHE TAIL: {self.tail}")
        self.cache[idx] = (text, seq)
        return True
    
class SEND_CACHE(CACHE):
    def __init__(self, size = 1000):
        super().__init__(size)
    #     self.cache = [(None, None)] * size
    #     self.head = 0
    #     self.tail = size - 1
        self.head_seq = 0
        
    # def add(self, text, seq):
    #     if self.is_full():
    #         return False
    #     self.cache[self.tail] = (text, seq)
    #     self.tail = (self.tail + 1) % self.size
    #     return True
    
    # def update(self, text, seq):
    #     if self.is_full():
    #         self.pop()
    #     self.add(text, seq)
    #     return True
        
        