import random
import queue
from datetime import datetime, timezone, timedelta



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
        
class RECEIVE_WINDOW:
    def __init__(self, window_size = 1000):
        self.window_size = window_size
        self.window = [False] * window_size
        self.left = 0 # 序列号区间左端点
        self.right = 0 # 序列号区间右端点
        self.ack_max = UDP_MAX
    
    def add_window_size(self, size):
        self.window_size += size
        self.window += [False] * size
        return True
    
    def minus_window_size(self, size):
        self.window_size -= size
        self.window = self.window[: -size]
        return True
    
    def init_window(self, left):
        self.left = left
        self.right = (self.left + self.window_size - 1) % self.ack_max
        return True
    
    def is_in_window(self, seq):
        if self.left <= seq and seq <= self.right:
            return True
        if self.right < self.left and (self.left <= seq or seq <= self.right):
            return True
        return False
    
    def move_right(self, step):
        self.left = (self.left + step) % self.ack_max
        self.right = (self.right + step) % self.ack_max
        
        que = queue.Queue()
        
        for i in range(len(self.window)):
            que.put(self.window[i])
        # 移动 window
        for i in range(step):
            que.get()
            que.put(False)
        for i in range(len(self.window)):
            self.window[i] = que.get()
        
        return True
    
    
class SEND_WINDOW:
    def __init__(self, window_size = 1000):
        self.window_size = window_size
        self.window = [False] * window_size # 是否收到确认
        self.left = 0
        self.right = 0
        self.seq_max = UDP_MAX
        
    def add_window_size(self, size):
        self.window_size += size
        self.window += [False] * size
        return True
    
    def minus_window_size(self, size):
        self.window_size -= size
        self.window = self.window[: -size]
        return True
    
    def init_window(self, left):
        self.left = left
        self.right = (self.left + self.window_size - 1) % self.seq_max
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
        self.cache[idx] = (text, seq)
        return True