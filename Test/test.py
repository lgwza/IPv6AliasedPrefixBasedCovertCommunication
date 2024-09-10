# file_a.py
import inspect
import sys

def func_A():
    # 获取调用者模块
    caller_frame = inspect.stack()[1]
    caller_module = inspect.getmodule(caller_frame[0])

    if caller_module is not None:
        caller_name = caller_module.__name__  # 获取调用者的模块名

        try:
            # 动态获取调用者模块并调用它的 `func`
            caller_module = sys.modules[caller_name]
            caller_module.func()
        except AttributeError:
            print(f"No function named 'func' in module {caller_name}")
    else:
        print("Caller module not found")
