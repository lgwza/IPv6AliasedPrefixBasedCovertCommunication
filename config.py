import subprocess
from key_gen import get_key

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
dst_address = "2401:c080:1000:4662:3eec:efff:feb9:8630"

source_saddr_spoofable = False
source_daddr_spoofable = True
dst_saddr_spoofable = True
dst_daddr_spoofable = True

mode = 'I'

key = get_key()
initial_message = b'\x00\x01\x02\x03\x04\x05\x06\x07'
SYN_text = b'\x01\x02\x03\x04\x05\x06\x07\x08'
SYN_ACK_text = b'\x01\x02\x03\x04\x01\x02\x03\x04'
ACK_text = b'\x08\x07\x06\x05\x08\x07\x06\x05'
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
status = LISTEN