import random

TCP_MAX = 2 ** 32 - 1
ICMP_MAX = 2 ** 16 - 1
UDP_MAX = 2 ** 16 - 1
SCTP_MAX = 2 ** 16 - 1

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
    
class CACHE:
    # 队列缓存
    def __init__(self, size = 100):
        self.size = size
        self.cache = [None] * size
        self.head = 0
        self.tail = 0
        self.send_ptr = 0
    
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
        i = self.head
        while i != self.tail:
            lis.append(self.cache[i])
            i = (i + 1) % self.size
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
    
<<<<<<< HEAD
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
=======
    def send_ptr_plus(self):
        
>>>>>>> 0b7d551bf14385ca2199696829a100ea89482681
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
        
    
    
        