import threading
import sys
from pathlib import Path

# 获取当前文件的父目录的父目录，添加到 sys.path，以便导入模块 A
sys.path.append(str(Path(__file__).resolve().parent.parent))

import module_a.A as A  # 正确导入模块 A

def packet_handler(packet):
    print(f"处理来自 C 模块的包: {packet}")

def receive_message():
    print("C 模块的接收消息函数被调用")
    # 创建一个线程来启动 sniffer
    thread = threading.Thread(target=A.start_sniffer, args=('module_c.C',))
    thread.start()
