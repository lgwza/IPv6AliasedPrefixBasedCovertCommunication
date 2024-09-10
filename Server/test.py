import threading
import time

# 创建一个全局的 Event 对象
pause_event = threading.Event()

def worker():
    print("Worker started")
    while True:
        print("Working...")
        time.sleep(1)
        # 检查是否要暂停
        pause_event.wait()  # 等待 Event 被设置为可执行状态
        print("Resumed...")

# 创建并启动线程
thread = threading.Thread(target=worker)
thread.start()

# 主线程等待一段时间后暂停工作线程
time.sleep(3)
print("Pausing the worker thread...")
pause_event.clear()  # 设置 Event 为不可执行状态，暂停线程

# 主线程等待一段时间后恢复工作线程
time.sleep(3)
print("Resuming the worker thread...")
pause_event.set()  # 设置 Event 为可执行状态，恢复线程

# 主线程等待一段时间后结束工作线程
time.sleep(3)
print("Stopping the worker thread...")
# 停止线程的典型方式是通过设置一个退出标志，使得线程在下一次循环检测时退出
