from userConfig import *

source_address = SOURCE_IPv6_ADDRESS
source_mac = SOURCE_MAC
sending_iface = SENDING_IFACE
listening_iface = LISTENING_IFACE
dst_address = DESTINATION_IPv6_ADDRESS

source_saddr_spoofable = SOURCE_IPv6_ADDRESS_IS_MESSAGE_SENDABLE # 源端源地址可搭载信息——源端可伪造源地址，对端需接收，源端可发送
source_daddr_spoofable = DESTINATION_IPv6_ADDRESS_IS_MESSAGE_RECEIVABLE # 源端目的地址可搭载信息——对端拥有别名前缀，对端需接收，源端可发送
dst_saddr_spoofable = DESTINATION_IPv6_ADDRESS_IS_MESSAGE_SENDABLE # 对端源地址可搭载信息——对端可伪造源地址，对端可发送，源端需接收
dst_daddr_spoofable = SOURCE_IPv6_ADDRESS_IS_MESSAGE_RECEIVABLE # 对端目的地址可搭载信息——源端拥有别名前缀，对端可发送，源端需接收

monitor_resources = MONITOR_RESOURCES
file_name = FILE_NAME

def gen_next_mode_dict():
    global proto_list, next_mode
    for i in range(len(proto_list)):
        next_mode[proto_list[i]] = proto_list[(i + 1) % len(proto_list)]
    next_mode[''] = proto_list[0]
    
# I for ICMPv6, U for UDP, T for TCP, 
proto_list = []
if USE_ICMPv6:
    proto_list.append('I')
if USE_UDP:
    proto_list.append('U')
if USE_TCP:
    proto_list.append('T')

last_mode = ''
next_mode = {}
gen_next_mode_dict()


filter_condition_dict = {
    'I': 'icmp6 and icmp6[0] == 128',
    'U': 'udp and ip6',
    'T': 'tcp and ip6[6] & 0x2 != 0'
}

send_file_mode = False
receive_file_size = 25000

RTT = MEASURED_RTT
packet_loss_rate = MEASURED_PACKET_LOSS_RATE

# 下面是秒为单位
max_send_speed = 1500
inter_time = 0
real_inter_time = 1 / max_send_speed

send_cache_size = 1500
receive_cache_size = 5000
send_window_max_size = 2500
receive_window_max_size = 5000
send_window_size = 1260
receive_window_size = 5000
ack_event_timer_interval = 0.5
resend_data_event_timer_interval = 0.5
write_to_file_event_timer_interval = 0.1
sender_send_window_size = 5000
sender_send_window_size = int(sender_send_window_size * (100 - packet_loss_rate) / 100)

# send_window_size = int(send_window_size / (packet_loss_rate * 100 + 1))
receive_window_size = int(receive_window_size * (100 - packet_loss_rate) / 100)
resend_data_event_timer_interval = max(RTT / 1000, send_window_size * inter_time)
ack_event_timer_interval = max(RTT / 1000, receive_window_size * real_inter_time, \
    sender_send_window_size * real_inter_time) / 2

print(f"send_window_size: {send_window_size}")
print(f"receive_window_size: {receive_window_size}")
print(f"resend_data_event_timer_interval: {resend_data_event_timer_interval}")
print(f"ack_event_timer_interval: {ack_event_timer_interval}")


# key = get_key()
key = ENCRYPTION_DECRYPTION_KEY
initial_message = b'\x00\x01\x02\x03\x04\x05\x06\x07'
SYN_text = b'\x01\x02\x03\x04\x05\x06\x07\x08'
SYN_ACK_text = b'\x01\x02\x03\x04\x01\x02\x03\x04'
ACK_text = b'\x08\x07\x06\x05\x08\x07\x06\x05'
RST_text = b'\x01\x01\x02\x02\x03\x03\x04\x04'

NEW_ACK_text = b'\x08\x07\x06\x05\x04\x03'
SACK_text = b'\x01\x02\x01\x02'




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
