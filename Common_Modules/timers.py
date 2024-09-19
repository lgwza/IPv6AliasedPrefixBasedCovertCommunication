import threading
import time

class ResettableTimer:
    def __init__(self, interval, function, *args, **kwargs):
        """
        初始化可重置计时器。
        :param interval: 时间间隔（秒）。
        :param function: 计时器到期时调用的函数。
        :param args: 传递给函数的参数。
        :param kwargs: 传递给函数的关键字参数。
        """
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self._stop_event = threading.Event()  # 用于停止线程
        self._reset_event = threading.Event()  # 用于重置计时器
        self._thread = threading.Thread(target=self._run_timer)
        self._thread.daemon = True  # 让线程在主线程退出时自动结束
        self._is_running = False
        self.start_time = None  # 用于记录开始时间

    def _run_timer(self):
        """定时器运行的主循环，确保只创建一个线程来处理循环计时。"""
        while not self._stop_event.is_set():
            self._reset_event.wait(self.interval)  # 等待间隔时间或重置事件
            if not self._reset_event.is_set():  # 如果重置事件没有触发，正常调用函数
                self.function(*self.args, **self.kwargs)
            self._reset_event.clear()  # 清除重置事件，准备下一次循环

    def start(self):
        """启动计时器，如果计时器已经运行则忽略。"""
        if not self._is_running:
            self._is_running = True
            self._stop_event.clear()
            self.start_time = time.time()  # 记录开始时间
            if not self._thread.is_alive():  # 确保只创建一个线程
                self._thread.start()
            print(f"Timer started for {self.interval} seconds.")

    def reset(self):
        """重置计时器，使其重新计时。"""
        if self._is_running:
            self._reset_event.set()  # 设置重置事件
            self.start_time = time.time()  # 重置开始时间
            print("Timer reset.")

    def stop(self):
        """停止计时器。"""
        self._is_running = False
        self._stop_event.set()  # 停止事件
        self._reset_event.set()  # 防止线程卡在等待
        print("Timer stopped.")

    def get_elapsed_time(self):
        """获取当前计时器的流逝时间（秒）。"""
        if self.start_time:
            return time.time() - self.start_time
        return 0
        

def on_timer_expired(Str):
    print("Timer expired! Event triggered.")
    print(Str)


if __name__ == '__main__':

    param = ResettableTimer(5, on_timer_expired)
    
    # 实例化重置计时器对象
    resettable_timer = ResettableTimer(5, on_timer_expired, param)

    # 启动计时器
    resettable_timer.start()

    # 模拟事件发生，每次事件发生重置计时器
    time.sleep(2)
    print(f"Elapsed time: {resettable_timer.get_elapsed_time():.2f} seconds")  # 获取当前计时的时间
    resettable_timer.reset()  # 第一次重置

    time.sleep(3)
    print(f"Elapsed time: {resettable_timer.get_elapsed_time():.2f} seconds")  # 获取当前计时的时间
    resettable_timer.reset()  # 第二次重置

    time.sleep(6)  # 超过计时器时间间隔，不再重置
    print(f"Elapsed time: {resettable_timer.get_elapsed_time():.2f} seconds")  # 获取当前计时的时间
    resettable_timer.stop()
