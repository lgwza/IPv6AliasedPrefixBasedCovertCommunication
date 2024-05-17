from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta, timezone

def encrypt(message, key):
    cipher = CAST.new(key, CAST.MODE_ECB)
    return cipher.encrypt(message)

def decrypt(ciphertext, key):
    cipher = CAST.new(key, CAST.MODE_ECB)
    return cipher.decrypt(ciphertext)

# 测试
empty_message = b'12345678'
key = b'01234567'  # 8字节的密钥

# 加密
padded_message = pad(empty_message, 8)  # 对空串进行填充
print("填充后的消息:", padded_message)
ciphertext = encrypt(padded_message, key)
print("加密后的消息:", ciphertext)

# 解密
decrypted_message = decrypt(ciphertext, key)
print(decrypted_message)
print("解密后的消息:", unpad(decrypted_message, 8).decode('utf-8'))  # 移除填充后输出

# print(unpad(b"12345678", 8))
# 设置时区东八区
now_utc = datetime.now()
# 设置东八区时区
east_8 = timezone(timedelta(hours=8))
# 转换为东八区时间并格式化为YYYYMMDDHHMM
now_east_8 = now_utc.astimezone(east_8)
formatted_time = now_east_8.strftime('%Y%m%d%H%M%S')

print(formatted_time)