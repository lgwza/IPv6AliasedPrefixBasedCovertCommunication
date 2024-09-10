import threading
import sys
from pathlib import Path

# 获取当前文件的父目录的父目录，添加到 sys.path，以便导入模块 A
sys.path.append(str(Path(__file__).resolve().parent.parent))

import module_a.A as A  # 正确导入模块 A

def packet_handler(packet):
    print(f"处理来自 B 模块的包: {packet}")

def receive_message():
    print("B 模块的接收消息函数被调用")
    # 创建一个线程来启动 sniffer，并显式传递当前模块
    thread = threading.Thread(target=A.start_sniffer, args=(sys.modules[__name__],))
    thread.start()

# 启动线程，触发接收消息逻辑
receive_message()