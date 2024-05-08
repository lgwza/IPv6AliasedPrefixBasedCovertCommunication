source_address = "2401:c080:1000:4662:3eec:efff:feb9:8630"
source_mac = "3c:ec:ef:b9:86:30"
source_iface = "enp1s0f0"
dst_address = "2402:f000:6:1e00::232"

source_saddr_spoofable = False
source_daddr_spoofable = True
dst_saddr_spoofable = False
dst_daddr_spoofable = True

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
status = LISTEN