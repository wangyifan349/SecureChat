# ---------- server.py ----------
import socket  # 提供底层网络接口
import threading  # 用于多线程处理发送与接收
import time  # 延迟，重试网络连接用
from cryptography.hazmat.primitives.asymmetric import x25519  # X25519公钥算法，用于密钥交换
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # HKDF密钥派生函数，用于生成安全对称密钥
from cryptography.hazmat.primitives import hashes  # 哈希算法模块，用于HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES GCM模式，认证加密实现
import os  # 用于生成随机数及系统层交互

def generate_shared_key(private_key, peer_public_key_bytes):  # 利用本地私钥和对方公钥生成协议共享密钥，并派生对称密钥
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)  # 根据对方公钥字节获得公钥对象
    shared_key = private_key.exchange(peer_public_key)  # 使用X25519算法计算共享的原始共享密钥（未派生）
    derived_key = HKDF(  # 使用HKDF扩展生成固定长度且安全的对称加密钥匙
        algorithm=hashes.SHA256(),  # HKDF使用的 hash 函数为SHA256
        length=32,  # 目标密钥长度为32字节(256 bit)
        salt=None,  # 不指定盐，HKDF会使用默认或空盐（生产环境建议指定）
        info=b'handshake data'  # 补充上下文绑定信息防止密钥重利用攻击
    ).derive(shared_key)  # 进行密钥派生输出对称密钥
    return derived_key  # 返回对称密钥

def encrypt_and_send(sock, key, plaintext):  # 明文加密然后通过socket发送
    try:
        aesgcm = AESGCM(key)  # 用共享对称密钥初始化AES-GCM加密器
        nonce = os.urandom(12)  # 生成12字节安全随机数做为AES-GCM nonce（不可重复）
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)  # 明文utf-8编码后加密（额外认证信息为空）
        msg_length = len(nonce + ciphertext)  # 计算完整消息长度(随机数+密文)
        sock.sendall(msg_length.to_bytes(4, 'big') + nonce + ciphertext)  # 先发送4字节长度头，再发送密文数据
    except Exception as e:
        print(f"Error during encryption or sending: {e}")  # 发送或加密异常报告

def receive_and_decrypt(sock, key):  # 从socket接收并解密数据
    try:
        raw_msglen = recvall(sock, 4)  # 先接收4字节消息长度字段，保证能够完整读后续数据
        if not raw_msglen:
            return None  # 连接已断开返回None通知上层退出
        msglen = int.from_bytes(raw_msglen, 'big')  # 解析长度 (大端字节序)
        encrypted_message = recvall(sock, msglen)  # 读取指定长度的完整密文消息
        if not encrypted_message:
            return None  # 对端关闭连接
        aesgcm = AESGCM(key)  # 生成AESGCM解密器
        nonce = encrypted_message[:12]  # nonce字节位于密文前12字节
        actual_ciphertext = encrypted_message[12:]  # 后续字节为认证加密的密文部分
        plaintext = aesgcm.decrypt(nonce, actual_ciphertext, None)  # 进行认证解密，失败时抛异常
        return plaintext.decode()  # 解码为unicode字符串文本返回
    except Exception as e:
        print(f"Error during decryption: {e}")  # 解密失败或数据异常打印日志
        return "ERROR"  # 返回错误字符串标示解密异常

def recvall(sock, n):  # 确保从socket接收完整n字节的数据，不足则阻塞等待
    data = bytearray()  # 初始化数据缓冲容器
    while len(data) < n:  # 当当前接收字节少于要求字节数时循环接收
        packet = sock.recv(n - len(data))  # 接收剩余长度字节
        if not packet:
            return None  # 连接关闭返回None
        data.extend(packet)  # 累加接收的数据块
    return data  # 返回完整的字节数据

def handle_client_connection(client_socket, shared_key):  # 多线程管理服务器侧客户端连接通讯
    stop_event = threading.Event()  # 事件对象标记终止信号

    def send_messages():  # 负责从终端读取消息加密发送到客户端的线程函数
        while not stop_event.is_set():  # 持续检查终止标志，未停止则循环
            message = input("Server: ")  # 客户端消息输入
            encrypt_and_send(client_socket, shared_key, message)  # 加密后发送给客户端
            if message.lower() == 'exit':  # 用户输入exit则准备关闭连接
                stop_event.set()  # 设置停止信号
                client_socket.close()  # 关闭socket连接
                break  # 退出循环结束线程

    def receive_messages():  # 负责接收客户端消息并解密打印的线程函数
        while not stop_event.is_set():  # 持续读取数据
            message = receive_and_decrypt(client_socket, shared_key)  # 从socket接收数据并解密
            if message is None or message.lower() == 'exit':  # 客户端关闭或发送exit则断开
                print("Client disconnected.")  # 打印断开通知
                stop_event.set()  # 设置停止信号
                break  # 终止线程
            elif message == "ERROR":  # 解密失败时
                print("Decryption failed.")  # 打印错误警告
            else:
                print(f"Client: {message}")  # 正常显示收到消息

    send_thread = threading.Thread(target=send_messages)  # 启动发送消息线程
    receive_thread = threading.Thread(target=receive_messages)  # 启动接收消息线程
    send_thread.start()  # 启动发送线程执行
    receive_thread.start()  # 启动接收线程执行
    send_thread.join()  # 等待发送线程安全退出
    receive_thread.join()  # 等待接收线程安全退出

def main():
    while True:  # 程序主循环，实现异常自动重启监听
        try:
            private_key = x25519.X25519PrivateKey.generate()  # 生成X25519密钥对私钥
            public_key = private_key.public_key().public_bytes()  # 获取对应公钥字节序列
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建IPv4 TCP socket
            server_socket.bind(('localhost', 65432))  # 绑定本地地址和端口
            server_socket.listen(1)  # 监听最大挂起连接数为1
            print("Server listening on port 65432...")
            client_socket, addr = server_socket.accept()  # 阻塞等待客户端连接
            print(f"Connection from {addr}")  # 输出连接地址
            client_socket.sendall(public_key)  # 发送本地公钥给客户端完成密钥交换第一步
            peer_public_key_bytes = client_socket.recv(32)  # 接收客户端公钥字节（固定32字节长度）
            shared_key = generate_shared_key(private_key, peer_public_key_bytes)  # 生成对称共享密钥
            handle_client_connection(client_socket, shared_key)  # 进入客户端消息交互逻辑
            break  # 正常退出循环
        except Exception as e:  # 捕获所有异常，防止程序崩溃
            print(f"An error occurred: {e}")  # 输出异常跟踪
            print("Restarting server...")  # 提示即将重启
            time.sleep(2)  # 等待2秒，避免高速重连造成资源耗尽
            continue  # 继续重新监听等待新连接

if __name__ == "__main__":
    main()  # 启动服务器主函数入口
