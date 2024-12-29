# 生成特定长度的随机 ASCII 文本

import random
import string
import sys

def random_text_gen(length):
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k = length))

# len 从参数读入
length = int(sys.argv[1])

# print(random_text_gen(500))
# 写入文件
with open("random_text.txt", "w") as f:
    f.write(random_text_gen(length))
    f.close()