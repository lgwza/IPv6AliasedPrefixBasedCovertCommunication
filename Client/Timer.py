import time
# 定义计时器
class Timer:
    def __init__(self):
        self.start_time = 0
        self.end_time = 0
    
    def start(self):
        self.start_time = time.time()
    
    def end(self):
        self.end_time = time.time()
    
    def get_time(self):
        return self.end_time - self.start_time