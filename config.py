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

source_address = result_src
source_mac = result_mac
source_iface = result_dev
src_dst_ip_set = {"2402:f000:6:1e00::232",
                   "2401:c080:1000:4662:3eec:efff:feb9:8630"}
dst_address = list(src_dst_ip_set - {source_address})[0]
# print(dst_address)
spoofable_info = {"2402:f000:6:1e00::232": [False, True],
                  "2401:c080:1000:4662:3eec:efff:feb9:8630": [True, True]}

source_saddr_spoofable = spoofable_info[source_address][0] # 源端源地址可搭载信息——源端可伪造源地址，对端需接收，源端可发送
source_daddr_spoofable = spoofable_info[source_address][1] # 源端目的地址可搭载信息——对端拥有别名前缀，对端需接收，源端可发送
dst_saddr_spoofable = spoofable_info[dst_address][0] # 对端源地址可搭载信息——对端可伪造源地址，对端可发送，源端需接收
dst_daddr_spoofable = spoofable_info[dst_address][1] # 对端目的地址可搭载信息——源端拥有别名前缀，对端可发送，源端需接收

# I for ICMPv6, U for UDP, T for TCP, 
# S for SCTP, R for Raw
proto_list = ['I', 'U', 'T', 'S', 'Raw']
# proto_list = ['I', 'U', 'T']
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
sleep_time = 0.25
if mode == 'A':
    sleep_time /= 1.25


key = get_key()
initial_message = b'\x00\x01\x02\x03\x04\x05\x06\x07'
SYN_text = b'\x01\x02\x03\x04\x05\x06\x07\x08'
SYN_ACK_text = b'\x01\x02\x03\x04\x01\x02\x03\x04'
ACK_text = b'\x08\x07\x06\x05\x08\x07\x06\x05'
RST_text = b'\x01\x01\x02\x02\x03\x03\x04\x04'



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
