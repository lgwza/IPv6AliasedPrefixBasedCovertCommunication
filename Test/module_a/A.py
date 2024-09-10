from scapy.all import sniff

def start_sniffer(caller_module):
    # 确保传递的模块具有 `packet_handler` 属性
    if not hasattr(caller_module, 'packet_handler'):
        print(f"模块 {caller_module.__name__} 没有 `packet_handler` 函数")
        return

    print(f"嗅探器在模块 {caller_module.__name__} 中启动")
    print(caller_module)
    filter_condition = "ip"  # 设置过滤条件
    sniff(filter=filter_condition, prn=caller_module.packet_handler, store=0)
