import psutil
import os
import threading

def monitor():
    # 测量当前进程的CPU利用率
    while True:
        process = psutil.Process(os.getpid())
        # cpu_usage = process.cpu_percent(interval=1)
        cpu_usage = psutil.cpu_percent(interval=1, percpu = True)
        print(len(cpu_usage))
        print(f"CPU Usage: {cpu_usage}%")

monitor_thread = threading.Thread(target = monitor)
monitor_thread.start()
# 测试代码
def test():
    while True:
        pass

test_thread_1 = threading.Thread(target = test)
test_thread_2 = threading.Thread(target = test)
test_thread_3 = threading.Thread(target = test)
test_thread_4 = threading.Thread(target = test)
test_thread_5 = threading.Thread(target = test)
test_thread_1.start()
test_thread_2.start()
test_thread_3.start()
test_thread_4.start()
test_thread_5.start()
