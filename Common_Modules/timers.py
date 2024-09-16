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
        self.timer = None
        self.start_time = None

    def start(self):
        """启动计时器。"""
        self.start_time = time.time()
        self.timer = threading.Timer(self.interval, self.function, *self.args, **self.kwargs)
        self.timer.start()
        print(f"Timer started for {self.interval} seconds.")

    def reset(self):
        """重置计时器。"""
        if self.timer:
            self.timer.cancel()  # 取消当前计时器
            print("Timer reset.")
        self.start()  # 重新启动计时器

    def stop(self):
        """停止计时器。"""
        if self.timer:
            self.timer.cancel()
            print("Timer stopped.")

    def get_elapsed_time(self):
        """获取当前计时器的运行时间。"""
        if self.start_time:
            elapsed_time = time.time() - self.start_time
            return elapsed_time
        else:
            return 0

def on_timer_expired():
    print("Timer expired! Event triggered.")


if __name__ == '__main__':

    # 实例化重置计时器对象
    resettable_timer = ResettableTimer(5, on_timer_expired)

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
