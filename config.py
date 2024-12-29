import subprocess
from key_gen import get_key
from key_gen import encrypt_data

try:
    command_dev = "ip -6 route get 2001:4860:4860::8888 | grep -oP '(?<=dev )\S+'"
    result_dev = subprocess.run(command_dev, shell=True, stdout=subprocess.PIPE)
    result_dev = result_dev.stdout.decode().strip()
    print(f'source_dev: {result_dev}')

    command_src = "ip -6 route get 2001:4860:4860::8888 | grep -oP '(?<=src )\S+'"
    result_src = subprocess.run(command_src, shell=True, stdout=subprocess.PIPE)
    result_src = result_src.stdout.decode().strip()
    print(f'source_ip: {result_src}')

    command_mac = "ifconfig " + result_dev + " | grep -oP '(?<=ether )\S+'"
    result_mac = subprocess.run(command_mac, shell=True, stdout=subprocess.PIPE)
    result_mac = result_mac.stdout.decode().strip()
    print(f'source_mac: {result_mac}')
except:
    print("ERROR! SOURCE INFO INCOMPLETE!")
    exit(-1)

# source_address = result_src

Simulation = 1
dst_choice = 2
if Simulation == 0:
    source_address = "2001:db8:1::1"
    source_mac = "96:c9:39:e4:05:03"
    source_iface = "veth0"
elif Simulation == 1:
    source_address = "2402:f000:6:1e00::232"
    source_mac = "2c:ea:7f:ed:0b:a0"
    source_iface = "eno1"

if dst_choice == 0:
    dst_address = "2001:db8:2::2"
elif dst_choice == 1:
    dst_address = "2401:c080:1000:4662:3eec:efff:feb9:8630"
elif dst_choice == 2:
    dst_address = "2001:252:188:fe0::1"

# source_mac = result_mac

src_dst_ip_set = {"2402:f000:6:1e00::232",
                  "2401:c080:1000:4662:3eec:efff:feb9:8630"}
# dst_address = list(src_dst_ip_set - {source_address})[0]

# print(dst_address)

# 该地址的源地址能否发送信息，目的地址能否接收信息
spoofable_info = {"2402:f000:6:1e00::232": [False, False],
                  "2401:c080:1000:4662:3eec:efff:feb9:8630": [True, True],
                  "2a09:7c41:0:15::1": [False, False],
                  "2001:db8:1::1": [False, False],
                  "2001:db8:2::2": [True, True],
                  "2001:252:188:fe0::1": [True, True]}

source_saddr_spoofable = spoofable_info[source_address][0] # 源端源地址可搭载信息——源端可伪造源地址，对端需接收，源端可发送
source_daddr_spoofable = spoofable_info[dst_address][1] # 源端目的地址可搭载信息——对端拥有别名前缀，对端需接收，源端可发送
dst_saddr_spoofable = spoofable_info[dst_address][0] # 对端源地址可搭载信息——对端可伪造源地址，对端可发送，源端需接收
dst_daddr_spoofable = spoofable_info[source_address][1] # 对端目的地址可搭载信息——源端拥有别名前缀，对端可发送，源端需接收


def gen_next_mode_dict():
    global proto_list, next_mode
    for i in range(len(proto_list)):
        next_mode[proto_list[i]] = proto_list[(i + 1) % len(proto_list)]
    next_mode[''] = proto_list[0]
    # print(next_mode)
    
# I for ICMPv6, U for UDP, T for TCP, 
# S for SCTP, R for Raw
# proto_list = ['I', 'U', 'T', 'S', 'Raw']
proto_list = ['I']
last_mode = ''
next_mode = {}
gen_next_mode_dict()


mode = 'A'
if mode == 'NDP':
    source_saddr_spoofable = False
    dst_saddr_spoofable = False

filter_condition_dict = {
    'I': 'icmp6 and icmp6[0] == 128',
    'U': 'udp and ip6',
    'T': 'tcp and ip6[6] & 0x2 != 0',
    'S': 'sctp and ip6',
    'Raw': 'ip6 and ip6[6] == 59',
    'NDP': 'icmp6 and ip6[40] == 135'
}



send_file_mode = True
send_file_size = 0

if send_file_mode:
    file_path = "random_text.txt"
    with open(file_path, "r") as f:
        file_message = f.read()
        send_file_size = len(file_message)

receive_file_size = 0
# send_file_size = 5000

sleep_time = 0.025 # 弃用

RTT = 0.615 # ms
packet_loss_rate = 0.0158 # %

max_send_speed = 1100
inter_time = 0
real_inter_time = 1 / max_send_speed
send_cache_size = send_file_size // 8 + 10
receive_cache_size = 1500
send_window_max_size = int(1e8)
receive_window_max_size = int(1e8)
# 会影响，太大导致seq_num_gen较慢，太小导致XXXXX TODO
send_window_size = min(5000, send_cache_size) 
receive_window_size = 5000
ack_event_timer_interval = 0.0005
resend_data_event_timer_interval = 0.0005
write_to_file_event_timer_interval = 0.1

# send_window_size = int(send_window_size / (packet_loss_rate * 100 + 1))
receive_window_size = int(receive_window_size / (packet_loss_rate * 100 + 1))
resend_data_event_timer_interval = max(RTT / 1000, send_window_size * real_inter_time)
resend_data_event_timer_interval = 0.5
ack_event_timer_interval = max(RTT / 1000, receive_window_size * real_inter_time)

print(f"send_window_size: {send_window_size}")
print(f"receive_window_size: {receive_window_size}")
print(f"resend_data_event_timer_interval: {resend_data_event_timer_interval}")
print(f"ack_event_timer_interval: {ack_event_timer_interval}")

# key = get_key()
key = b"12345728"
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
