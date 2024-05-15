from Crypto.Cipher import ChaCha20
from datetime import datetime, timedelta, timezone
import os
import hashlib

def get_current_time_east_8():
    # 获取当前UTC时间
    now_utc = datetime.now()
    # 设置东八区时区
    east_8 = timezone(timedelta(hours=8))
    # 转换为东八区时间并格式化为YYYYMMDDHHMM
    now_east_8 = now_utc.astimezone(east_8)
    formatted_time = now_east_8.strftime('%Y%m%d%H%M')
    return formatted_time.encode()  # 转换为字节串

def encrypt_time_with_chacha20(time_bytes, key):
    # 生成随机nonce
    nonce = b'\xbf\xcc\xe4\x81\xfc\xee2^:\xdd\xd4F'
    # 创建ChaCha20加密器对象
    cipher = ChaCha20.new(key=key, nonce=nonce)
    # 加密数据
    encrypted_data = cipher.encrypt(time_bytes)
    return nonce + encrypted_data  # 返回nonce和密文，解密时需要nonce

def md5_hash(bytes_string):
    # 创建md5对象
    md5 = hashlib.md5()
    # 更新md5对象
    md5.update(bytes_string)
    # 获取md5值
    return md5.digest()

def encrypt_data(data, key):
    nonce = b'\xbf\xcc\xe4\x81\xfc\xee2^:\xdd\xd4F'
    cipher = ChaCha20.new(key=key, nonce=nonce)
    encrypted_data = cipher.encrypt(data)
    encrypt_data = nonce + encrypted_data
    # md5, 8 bit
    return md5_hash(encrypt_data)[:8]

def get_key():
    # chacha20 key 必须为32字节
    key = b'}\x0c\xf3ufE\x94\xfaT\xb7\x8d\x81\xb6\x1b~\xe1\x81\x88\xbd\xfc\xf5\xa4\xbf\xb5\x98\x1d\xa2\x93iq#\x0b'

    # 获取当前时间并格式化
    current_time_bytes = get_current_time_east_8()
    # print(current_time_bytes)
    # 加密时间
    encrypted_time = encrypt_time_with_chacha20(current_time_bytes, key)

    # 输出前8位
    ret_key = md5_hash(encrypted_time)[:8]
    print(current_time_bytes)
    print(ret_key)
    return ret_key

if __name__ == '__main__':
    get_key()
