# APCC: Enabling Reliable IPv6 Covert Communication with Aliased Prefixes

## Overview

APCC (Aliased Prefixes based Covert Communication) is a reliable IPv6 covert communication system that leverages **IPv6 aliased prefixes** to embed secret data in the **Interface Identifier (IID)** field of IPv6 addresses. This implementation realizes the research presented in the paper *"APCC: Enabling Reliable IPv6 Covert Communication with Aliased Prefixes"*, published at **IWQoS 2025**.

APCC enables **high-throughput**, **high-reliability**, and **high-stealthiness** covert communication by:
- Embedding encrypted payloads in IPv6 source/destination addresses
- Supporting multiple upper-layer protocols (ICMPv6, UDP, TCP)
- Employing sequence numbering, acknowledgments (ACK/SACK), and retransmission
- Blending traffic with scanning-like patterns to evade detection

## Features

- **IPv6 Aliased Prefix Covert Channel**: Secret data is embedded in the 64-bit Interface Identifier of IPv6 addresses within aliased prefixes.
- **Multi-Protocol Support**: Works over ICMPv6 Echo Requests, UDP probes, or TCP SYN packets.
- **Reliable Transmission**: Implements sequence numbers, cumulative ACKs, selective ACKs (SACK), and retransmission to guarantee 100% accuracy under packet loss (tested up to 10%) and high latency (up to 800 ms RTT).
- **Sliding Window Flow Control**: Dynamically manages unacknowledged packets based on network feedback.
- **Encryption & Camouflage**: Payloads are encrypted and disguised as random IID values; traffic mimics IPv6 scanning behavior.
- **Flexible Deployment**: Secret data can be embedded in source address, destination address, or both, depending on aliased prefix availability at endpoints.
- **Dual Operation Modes**: Supports **conversation mode** (interactive) and **file transfer mode** (batch).

## System Requirements

- Linux operating system (required for alias prefix setup and raw packet I/O)
- Python 3.7+
- Root privileges (for packet sniffing/sending and enabling `net.ipv6.ip_nonlocal_bind`)
- Python packages:
  - `scapy`
  - `pycryptodome`
  - `psutil` (optional, for resource monitoring)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/lgwza/APCC.git
   cd APCC/

2. Install dependencies:

```bash
pip3 install scapy pycryptodome psutil
```

3. (Optional but recommended) Enable kernel support for aliased prefixes on **both** communicating hosts:

```bash
sudo sysctl -w net.ipv6.ip_nonlocal_bind=1
sudo ip -6 route add local <YOUR_ALIASED_PREFIX>/64 dev <INTERFACE>
```

## Configuration

### User Configuration (`userConfig.py`)

Edit `userConfig.py` before running:

```python
# Network Interface and IPv6 Aliased Prefixes
SOURCE_IPv6_ADDRESS = "2001:db8:1::1"        # Must belong to a locally configured aliased prefix
DESTINATION_IPv6_ADDRESS = "2001:db8:2::1"   # Must belong to remote's aliased prefix
SENDING_IFACE = "eth0"
LISTENING_IFACE = "eth0"
SOURCE_MAC = "00:11:22:33:44:55"             # Required for crafting packets

# Embedding Capability (set based on aliased prefix ownership)
SOURCE_IPv6_ADDRESS_IS_MESSAGE_SENDABLE = True   # Can embed in source IID
DESTINATION_IPv6_ADDRESS_IS_MESSAGE_RECEIVABLE = True  # Can embed in dest IID

# Protocol Selection (choose one or more; system will use the first available)
USE_ICMPv6 = True
USE_UDP = False
USE_TCP = False

# Network Parameters (used for timeout & window sizing)
MEASURED_RTT = 50          # ms
MEASURED_PACKET_LOSS_RATE = 2  # %

# Encryption Key (must be 8 bytes for block cipher compatibility)
ENCRYPTION_DECRYPTION_KEY = b"12345678"

# Operational Settings
IS_SENDER = True           # Set to False for receiver
FILE_NAME = "message.txt"  # File to send (sender) or output path (receiver)
SEND_FILE_MODE = True      # False for interactive mode
RECEIVE_FILE_SIZE = None   # Optional: expected file size in bytes (receiver)
MONITOR_RESOURCES = False
TEST_MODE = False
```

## Usage

### Receiver (Bob)

1. Set `IS_SENDER = False` in `userConfig.py`
2. Run:

```bash
sudo ./start_server.sh
```

### Sender (Alice)

1. Set `IS_SENDER = True` in `userConfig.py`
2. Place your secret file as `message.txt` (or configure `FILE_NAME`)
3. Run:

```bash
sudo ./start_client.sh
```

> Both parties must pre-share the encryption key and agree on protocol/embedding location.

## Project Structure

```
APCC/
├── Client/                   # Sender-side logic
│   ├── cc_client.py         # Main sender entry
│   └── Timer.py
├── Server/                   # Receiver-side logic
│   ├── cc_server.py         # Main receiver entry
│   └── Timer.py
├── Common_Modules/          # Shared utilities
│   ├── ack_send.py
│   ├── common_modules.py    # Packet crafting, encryption, filtering
│   ├── data_resend.py       # Retransmission logic
│   ├── error_handle.py
│   ├── set_flag.py
│   ├── store_messages.py
│   └── timers.py
├── Received_Messages/       # Default output directory for received files
├── config.py                # Internal constants
├── userConfig.py            # ← USER-EDITABLE CONFIGURATION
├── start_client.sh          # Wrapper for sender
├── start_server.sh          # Wrapper for receiver
└── README.md
```

## Key Components

- **`cc_client.py` / `cc_server.py`**: Entry points implementing APCC’s sending/receiving modules as described in Section IV of the paper.
- **Reliability Engine**: Sequence numbering (in ICMPv6 seq#/UDP src port/TCP seq#), ACK/SACK encoding in IID, sliding window, and timeout-based retransmission.
- **Stealth Layer**: Traffic shaping (optional delays, dummy packets), scanning-like probe generation.
- **Encryption**: 64-bit block cipher (e.g., DES-compatible) applied to each 8-byte payload block before embedding into IID.

## Security & Ethical Notes

- APCC is designed for research on **covert channel risks in IPv6 infrastructure**.
- All experiments in the paper used **authorized environments** with **non-sensitive data**.
- Misuse for data exfiltration or bypassing security controls is **discouraged**.
- Mitigation strategies (e.g., prefix monitoring, NDP spoofing defense) are discussed in Section VI of the paper.

## Performance

- **Throughput**: Up to **34.7 Kbps** (ICMPv6, low-loss LAN)
- **Reliability**: **100%** accuracy under 10% packet loss and 800 ms RTT
- **Stealthiness**: Evades Snort and Zeek; only Suricata triggers alerts on TCP mode
- **Overhead**: ~50% CPU, ~100 MB RAM (on server-grade hardware)

## Citation

If you find this paper useful or use this code in your research, please cite:

```
@inproceedings{wang2025apcc,
  title={APCC: Enabling Reliable IPv6 Covert Communication with Aliased Prefixes},
  author={Wang, Zhaoan and He, Lin and Cheng, Daguo and Liu, Ying},
  booktitle={2025 IEEE/ACM 33rd International Symposium on Quality of Service (IWQoS)},
  pages={1--10},
  year={2025},
  organization={IEEE}
}
```

DOI: 10.1109/IWQoS65803.2025.11143455

You can download this paper via this [link](https://ieeexplore.ieee.org/abstract/document/11143455).

## License

This code is released under the **MIT License**. See `LICENSE` file for details.

## Contact

For academic inquiries, please contact the me via lgwza@qq.com

