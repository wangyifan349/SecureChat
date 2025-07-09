# chat_core.py

import sys
import socket
import threading
import json
import time
import os
import base64
from nacl.public import PrivateKey, PublicKey  # 用于X25519密钥交换
from nacl.bindings.crypto_kx import crypto_kx_client_session_keys, crypto_kx_server_session_keys  # 会话密钥生成
from Crypto.Cipher import ChaCha20_Poly1305  # 加密算法
from PyQt5.QtCore import QObject, pyqtSignal

class ChatCore(QObject):
    # 定义信号，用于与GUI通信
    message_signal = pyqtSignal(dict)
    status_signal = pyqtSignal(str)

    def __init__(self, mode, ip, port):
        super().__init__()
        self.mode = mode  # 模式，'server'或'client'
        self.ip = ip  # IP地址
        self.port = port  # 端口号
        self.sock = None  # 套接字
        self.tx_key = None  # 发送密钥
        self.rx_key = None  # 接收密钥
        self.running = True  # 运行标志

        # 启动网络线程
        self.network_thread = threading.Thread(target=self.run, daemon=True)
        self.network_thread.start()

    def run(self):
        try:
            if self.mode == 'server':
                self.start_server()  # 启动服务器模式
            else:
                self.start_client()  # 启动客户端模式

            self.perform_handshake()  # 执行密钥交换
            self.status_signal.emit("[*] Handshake complete. Secure channel ready.")

            # 启动接收线程
            self.receiver_thread = threading.Thread(target=self.receiver_loop, daemon=True)
            self.receiver_thread.start()
        except Exception as e:
            self.status_signal.emit(f"[!] Error: {e}")
            self.running = False

    def start_server(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建监听套接字
        listener.bind((self.ip, self.port))  # 绑定IP和端口
        listener.listen(1)  # 开始监听
        self.status_signal.emit(f"[*] Listening on {self.ip}:{self.port}")
        conn, addr = listener.accept()  # 接受连接
        self.status_signal.emit(f"[*] Connection from {addr}")
        self.sock = conn  # 使用连接套接字

    def start_client(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建套接字
        self.sock.connect((self.ip, self.port))  # 连接到服务器
        self.status_signal.emit(f"[*] Connected to {self.ip}:{self.port}")

    def perform_handshake(self):
        self.rx_key, self.tx_key = self.do_handshake(self.sock, is_server=(self.mode == 'server'))  # 执行密钥交换

    # 辅助函数
    def recv_exact(self, sock, nbytes):
        buf = b''  # 接收缓冲区
        while len(buf) < nbytes:
            chunk = sock.recv(nbytes - len(buf))  # 接收数据
            if not chunk:
                return None
            buf += chunk
        return buf

    def send_packet(self, sock, data: bytes):
        length = len(data).to_bytes(4, 'big')  # 数据长度
        sock.sendall(length + data)  # 发送数据

    def recv_packet(self, sock) -> bytes:
        hdr = self.recv_exact(sock, 4)  # 接收数据头
        if not hdr:
            return None
        length = int.from_bytes(hdr, 'big')  # 数据长度
        return self.recv_exact(sock, length)  # 接收完整数据

    def do_handshake(self, sock, is_server: bool):
        priv_key = PrivateKey.generate()  # 生成私钥
        pub_key = priv_key.public_key  # 生成公钥

        pub_bytes = pub_key.encode()  # 公钥字节

        if is_server:
            peer_pub_bytes = self.recv_packet(sock)  # 接收对方公钥
            self.send_packet(sock, pub_bytes)  # 发送自己的公钥
        else:
            self.send_packet(sock, pub_bytes)  # 发送自己的公钥
            peer_pub_bytes = self.recv_packet(sock)  # 接收对方公钥

        peer_pub_key = PublicKey(peer_pub_bytes)  # 对方公钥

        # 生成会话密钥
        if is_server:
            rx_key, tx_key = crypto_kx_server_session_keys(
                server_private_key=priv_key.encode(),
                server_public_key=pub_bytes,
                client_public_key=peer_pub_bytes
            )
        else:
            tx_key, rx_key = crypto_kx_client_session_keys(
                client_private_key=priv_key.encode(),
                client_public_key=pub_bytes,
                server_public_key=peer_pub_bytes
            )

        # 打印密钥交换信息
        print("[*] Shared keys established.")
        return rx_key, tx_key

    def receiver_loop(self):
        while self.running:
            try:
                packet = self.recv_packet(self.sock)  # 接收数据包
                if packet is None:
                    self.status_signal.emit("[*] Peer closed connection.")
                    self.running = False
                    break

                encrypted_message = json.loads(packet.decode('utf-8'))  # 解码JSON数据
                nonce = base64.b64decode(encrypted_message['nonce'])  # 提取nonce
                tag = base64.b64decode(encrypted_message['tag'])  # 提取标签
                ciphertext = base64.b64decode(encrypted_message['ciphertext'])  # 提取密文
            except Exception as e:
                self.status_signal.emit(f"[!] Failed to parse JSON: {e}")
                continue

            try:
                cipher = ChaCha20_Poly1305.new(key=self.rx_key, nonce=nonce)  # 创建解密器
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # 解密并验证
            except Exception as e:
                self.status_signal.emit(f"[!] Decrypt failed: {e}")
                continue

            try:
                message_obj = json.loads(plaintext.decode('utf-8'))  # 解码明文JSON
                timestamp = message_obj.get('timestamp', 'Unknown time')  # 时间戳
                message = message_obj.get('message', '')  # 消息内容

                # 使用信号将消息传递给GUI
                self.message_signal.emit({
                    'message': message,
                    'timestamp': timestamp,
                    'sender': 'peer'  # 对方发送的消息
                })
                # 打印接收到的消息
                print(f"[RECV {timestamp}] {message}")
            except json.JSONDecodeError:
                self.status_signal.emit(f"[!] Received non-JSON data.")

    def send_message(self, message_text):
        if not self.running or not self.sock:
            self.status_signal.emit("[!] Connection is not established.")
            return

        try:
            message_obj = {
                'message': message_text,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            }

            data = json.dumps(message_obj, separators=(',', ':')).encode('utf-8')  # 序列化消息
            nonce = os.urandom(12)  # 生成随机nonce
            cipher = ChaCha20_Poly1305.new(key=self.tx_key, nonce=nonce)  # 创建加密器
            ciphertext, tag = cipher.encrypt_and_digest(data)  # 加密并生成标签

            encrypted_message = {
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
            }

            self.send_packet(self.sock, json.dumps(encrypted_message).encode('utf-8'))  # 发送加密消息

            # 使用信号将自己发送的消息传递给GUI
            timestamp = message_obj['timestamp']
            self.message_signal.emit({
                'message': message_text,
                'timestamp': timestamp,
                'sender': 'self'  # 自己发送的消息
            })
            # 打印发送的消息
            print(f"[SEND {timestamp}] {message_text}")
        except Exception as e:
            self.status_signal.emit(f"[!] Failed to send message: {e}")

    def close(self):
        self.running = False
        if self.sock:
            self.sock.close()  # 关闭套接字
