# ---------- client.py ----------
import socket  # 网络通信socket模块
import threading  # 线程模块用于收发分离处理
import time  # 异常重连延时
from cryptography.hazmat.primitives.asymmetric import x25519  # X25519密钥交换算法
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # HKDF，用于密钥派生
from cryptography.hazmat.primitives import hashes  # 哈希算法模块
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AEAD加密模式AES-GCM实现
import os  # 用于生成加密随机nonce

def generate_shared_key(private_key, peer_public_key_bytes):  # 通过私钥和对方公钥字节生成对称共享密钥
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)  # 创建公钥对象
    shared_key = private_key.exchange(peer_public_key)  # 通过X25519计算原共享密钥
    derived_key = HKDF(  # HKDF生成固定长度安全密钥用于对称加密
        algorithm=hashes.SHA256(),  # 使用SHA256算法
        length=32,  # 生成32字节密钥
        salt=None,  # 不使用盐（正式环境建议使用随机盐）
        info=b'handshake data'  # 应用信息上下文
    ).derive(shared_key)  # 执行密钥派生
    return derived_key  # 返回对称加密密钥

def encrypt_and_send(sock, key, plaintext):  # 加密明文发送给服务器
    try:
        aesgcm = AESGCM(key)  # 创建AES-GCM加密器
        nonce = os.urandom(12)  # 生成12字节唯一nonce
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)  # 加密明文并生成认证密文
        msg_length = len(nonce + ciphertext)  # 计算需要发送的字节数
        sock.sendall(msg_length.to_bytes(4, 'big') + nonce + ciphertext)  # 先发长度再发密文
    except Exception as e:
        print(f"Error during encryption or sending: {e}")  # 出错打印

def receive_and_decrypt(sock, key):  # 从socket接收并解密消息
    try:
        raw_msglen = recvall(sock, 4)  # 先读取消息长度4字节头
        if not raw_msglen:
            return None  # 连接关闭
        msglen = int.from_bytes(raw_msglen, 'big')  # 解析长度
        encrypted_message = recvall(sock, msglen)  # 根据长度读取全部密文
        if not encrypted_message:
            return None  # 连接关闭
        aesgcm = AESGCM(key)  # 生成AES解密器
        nonce = encrypted_message[:12]  # 提取nonce
        actual_ciphertext = encrypted_message[12:]  # 提取密文
        plaintext = aesgcm.decrypt(nonce, actual_ciphertext, None)  # 解密并认证密文
        return plaintext.decode()  # 解码文本返回
    except Exception as e:
        print(f"Error during decryption: {e}")  # 解密失败打印
        return "ERROR"  # 返回错误信息标识

def recvall(sock, n):  # 确保读取n字节，不足则循环读取
    data = bytearray()  # 缓冲区
    while len(data) < n:  # 未达到目标长度则继续接收
        packet = sock.recv(n - len(data))  # 接收剩余字节数
        if not packet:
            return None  # 连接断开返回None
        data.extend(packet)  # 追加数据
    return data  # 返回完整数据

def handle_server_connection(server_socket, shared_key):  # 客户端消息异步收发处理
    stop_event = threading.Event()  # 停止线程信号

    def send_messages():  # 发送线程，循环读取用户输入并发送
        while not stop_event.is_set():  # 未置停止标志一直循环
            message = input("Client: ")  # 终端输入
            encrypt_and_send(server_socket, shared_key, message)  # 加密发送消息
            if message.lower() == 'exit':  # 'exit'为退出信号
                stop_event.set()  # 设置停止事件
                server_socket.close()  # 主动关闭socket连接
                break  # 退出发送线程循环

    def receive_messages():  # 接收线程，持续接收解密并打印服务器消息
        while not stop_event.is_set():  # 持续接收
            message = receive_and_decrypt(server_socket, shared_key)  # 接收解密消息
            if message is None or message.lower() == 'exit':  # 对方退出或连接关闭
                print("Server disconnected.")  # 打印断开通知
                stop_event.set()  # 标记停止线程
                break  # 跳出循环终止线程
            elif message == "ERROR":  # 解密异常提示
                print("Decryption failed.")  # 错误提示
            else:
                print(f"Server: {message}")  # 输出服务器消息

    send_thread = threading.Thread(target=send_messages)  # 创建并启动发送线程
    receive_thread = threading.Thread(target=receive_messages)  # 创建并启动接收线程
    send_thread.start()  # 启动发送
    receive_thread.start()  # 启动接收
    send_thread.join()  # 等发送线程结束
    receive_thread.join()  # 等接收线程结束

def main():
    while True:  # 主循环防止异常退出导致程序结束，实现自动重连
        try:
            private_key = x25519.X25519PrivateKey.generate()  # 随机生成X25519私钥
            public_key = private_key.public_key().public_bytes()  # 获取对应公钥字节
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 新建TCP socket
            server_socket.connect(('localhost', 65432))  # 连接指定服务器和端口
            peer_public_key_bytes = server_socket.recv(32)  # 接收服务器的公钥（X25519固定32字节）
            server_socket.sendall(public_key)  # 发送本机公钥完成密钥交换交互
            shared_key = generate_shared_key(private_key, peer_public_key_bytes)  # 派生AES对称加密钥匙
            handle_server_connection(server_socket, shared_key)  # 进入消息收发处理线程
            break  # 处理完毕正常退出循环
        except Exception as e:  # 捕获连接及运行时异常
            print(f"An error occurred: {e}")  # 打印异常详细信息
            print("Reconnecting...")  # 提示尝试重连
            time.sleep(2)  # 延时2秒再重试连接
            continue  # 循环重试，保证高可用连接

if __name__ == "__main__":
    main()  # 程序入口，启动客户端
