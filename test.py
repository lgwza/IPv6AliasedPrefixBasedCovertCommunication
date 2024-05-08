from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad, unpad

def encrypt(message, key):
    cipher = CAST.new(key, CAST.MODE_ECB)
    return cipher.encrypt(message)

def decrypt(ciphertext, key):
    cipher = CAST.new(key, CAST.MODE_ECB)
    return cipher.decrypt(ciphertext)

# 测试
empty_message = b''
key = b'01234567'  # 8字节的密钥

# 加密
padded_message = pad(empty_message, 8)  # 对空串进行填充
ciphertext = encrypt(padded_message, key)
print("加密后的消息:", ciphertext.hex())

# 解密
decrypted_message = decrypt(ciphertext, key)
print("解密后的消息:", unpad(decrypted_message, 8).decode('utf-8'))  # 移除填充后输出
