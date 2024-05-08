source_address = "2402:f000:6:1e00::232"
source_mac = "2c:ea:7f:ed:0b:a0"
source_iface = "eno1"
dst_address = "2401:c080:1000:4662:3eec:efff:feb9:8630"

source_saddr_spoofable = False # 源端源地址可搭载信息——源端可伪造源地址，对端需接收，源端可发送
source_daddr_spoofable = True # 源端目的地址可搭载信息——对端拥有别名前缀，对端需接收，源端可发送
dst_saddr_spoofable = False # 对端源地址可搭载信息——对端可伪造源地址，对端可发送，源端需接收
dst_daddr_spoofable = True # 对端目的地址可搭载信息——源端拥有别名前缀，对端可发送，源端需接收

mode = 'T'

key = b'abcd3333'
initial_message = b'\x00\x01\x02\x03\x04\x05\x06\x07'
SYN_text = b'\x01\x02\x03\x04\x05\x06\x07\x08'
SYN_ACK_text = b'\x01\x02\x03\x04\x01\x02\x03\x04'
ACK_text = b'\x08\x07\x06\x05\x04\x03\x02\x01'
CLOSED = 0
LISTEN = 1
SYN_SENT = 2
SYN_RECEIVED = 3
ESTABLISHED = 4
FIN_WAIT_1 = 5
FIN_WAIT_2 = 6
CLOSE_WAIT = 7
CLOSING = 8
LAST_ACK = 9
TIME_WAIT = 10