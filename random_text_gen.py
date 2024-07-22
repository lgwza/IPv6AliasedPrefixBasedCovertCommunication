# 生成特定长度的随机 ASCII 文本

import random
import string

def random_text_gen(length):
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k = length))

len = 10000
# print(random_text_gen(500))
# 写入文件
with open("random_text.txt", "w") as f:
    f.write(random_text_gen(len))
    f.close()