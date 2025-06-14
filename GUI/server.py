# server.py
import socket  # 网络通信
import threading  # 多线程
import time  # 延时休眠
import tkinter as tk  # GUI主模块
from tkinter import ttk  # 主题控件
from tkinter.scrolledtext import ScrolledText  # 滚动文本框
from cryptography.hazmat.primitives.asymmetric import x25519  # X25519密钥交换
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # HKDF密钥派生
from cryptography.hazmat.primitives import hashes  # 哈希算法
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-GCM认证加密
import os  # 随机数生成
import queue  # 线程安全队列
import traceback  # 异常堆栈打印

# 生成共享密钥并派生对称密钥
def generate_shared_key(private_key, peer_public_key_bytes):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)  # 加载对方公钥
    shared_key = private_key.exchange(peer_public_key)  # 交换共享密钥
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_key)  # 派生对称密钥
    return derived_key

# 加密明文为密文包
def encrypt_message(key, plaintext):
    aesgcm = AESGCM(key)  # AES-GCM加密器
    nonce = os.urandom(12)  # 12字节随机数nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)  # 加密明文
    return nonce + ciphertext  # 拼接nonce与密文返回

# 解密收到的密文包为明文
def decrypt_message(key, pkt):
    aesgcm = AESGCM(key)  # AES-GCM解密器
    nonce = pkt[:12]  # 取前12字节nonce
    ciphertext = pkt[12:]  # 余下为密文
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)  # 解密并认证
    return plaintext.decode('utf-8')  # 转字符串返回

# 发送完整包（含4字节长度字段）
def send_packet(sock, packet):
    length = len(packet)
    sock.sendall(length.to_bytes(4, 'big') + packet)  # 消息长度大端序 + 消息本体

# 从socket接收完整包
def recv_pkt(sock):
    raw_len = recvall(sock, 4)  # 先接收4字节字段长度
    if not raw_len:  # 连接关闭
        return None
    length = int.from_bytes(raw_len, 'big')  # 转整型
    # 安全检查
    if length <= 0 or length > 10**7:  # 防止恶意大包
        return None
    data = recvall(sock, length)  # 接收包体
    return data

# 确保读取n字节数据，端口阻塞直至数据完整或断开
def recvall(sock, n):
    data = b''
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))  # 接收剩余字节
        except Exception:
            return None
        if not packet:  # 断开
            return None
        data += packet
    return data

# Tkinter主界面类
class ServerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title('🔒 SecureChat 服务器')
        self.master.geometry("700x500")
        self.master.configure(bg='#e3f2fd')  # 背景色

        # 创建带滚动条的只读文本框展示聊天内容
        self.chat_display = ScrolledText(master, state='disabled', font=("Consolas", 12), bg='#ffffff', fg='#000000')
        self.chat_display.pack(padx=15, pady=15, fill=tk.BOTH, expand=True)

        # 输入与按钮区域
        frame = tk.Frame(master, bg='#e3f2fd')
        frame.pack(padx=15, pady=(0,15), fill=tk.X)

        # 消息输入框
        self.message_entry = ttk.Entry(frame, font=("Consolas", 12))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,10))
        self.message_entry.bind('<Return>', self.send_message)  # 回车发送

        # 发送按钮
        self.send_button = ttk.Button(frame, text='发送', command=self.send_message)
        self.send_button.pack(side=tk.LEFT)

        # 初始化控制变量
        self.stop_event = threading.Event()
        self.sock = None
        self.client_socket = None
        self.shared_key = None
        self.receive_queue = queue.Queue()  # 保证线程安全消息传递

        # 右键清空菜单
        self.chat_display.bind("<Button-3>", self._show_context_menu)
        self.menu = tk.Menu(master, tearoff=0)
        self.menu.add_command(label="清空聊天", command=self.clear_chat)

        # 服务器线程
        threading.Thread(target=self.start_server, daemon=True).start()

        # 定时刷新消息
        self.master.after(100, self.process_incoming_messages)

    # 右键菜单显示
    def _show_context_menu(self, event):
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    # 清空聊天区
    def clear_chat(self):
        self.chat_display.config(state='normal')
        self.chat_display.delete('1.0', tk.END)
        self.chat_display.config(state='disabled')

    # 服务器启动、监听、接受连接和密钥交换逻辑
    def start_server(self):
        while not self.stop_event.is_set():
            try:
                private_key = x25519.X25519PrivateKey.generate()  # 私钥
                public_key = private_key.public_key().public_bytes()  # 公钥字节
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 重用端口
                self.sock.bind(('0.0.0.0', 65432))
                self.sock.listen(1)
                self.update_chat_display('服务器启动，等待客户端连接...')
                self.client_socket, addr = self.sock.accept()
                self.update_chat_display(f'已连接来自 {addr}')
                self.client_socket.sendall(public_key)  # 发送公钥
                peer_public_key_bytes = recvall(self.client_socket, 32)
                if not peer_public_key_bytes:
                    self.update_chat_display("未收到客户端公钥，断开连接。")
                    self.client_socket.close()
                    continue
                self.shared_key = generate_shared_key(private_key, peer_public_key_bytes)  # 生成对称密钥
                threading.Thread(target=self.receive_loop, daemon=True).start()  # 启接收线程
                break
            except Exception as e:
                self.update_chat_display(f"服务器错误: {e}")
                time.sleep(2)

    # 线程安全发送消息方法（新开线程发送）
    def safe_send(self, message):
        if not self.client_socket or not self.shared_key:
            self.update_chat_display("未连接客户端，不能发送消息。")
            return
        try:
            pkt = encrypt_message(self.shared_key, message)
            send_packet(self.client_socket, pkt)
        except Exception as e:
            self.update_chat_display(f"发送失败: {e}")

    # 发送按钮/回车事件
    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if not message:
            return
        self.message_entry.delete(0, tk.END)
        threading.Thread(target=self.safe_send, args=(message,), daemon=True).start()
        self.update_chat_display(f"服务器: {message}")
        if message.lower() == 'exit':
            self.stop_event.set()
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
                if self.sock:
                    self.sock.close()
            except Exception:
                pass
            self.master.quit()

    # 接收线程，持续接收消息放入线程安全队列
    def receive_loop(self):
        try:
            while not self.stop_event.is_set():
                pkt = recv_pkt(self.client_socket)
                if pkt is None:
                    self.receive_queue.put("客户端已断开连接。")
                    self.stop_event.set()
                    break
                try:
                    message = decrypt_message(self.shared_key, pkt)
                except Exception:
                    # 解密失败，疑似中间人篡改包，丢弃并报警告
                    self.receive_queue.put("[警告] 收到无效或被篡改的消息")
                    continue
                if not message:
                    continue
                if message.lower() == 'exit':
                    self.receive_queue.put("客户端请求断开连接。")
                    self.stop_event.set()
                    break
                self.receive_queue.put(f"客户端: {message}")
        except Exception:
            err = traceback.format_exc()
            self.receive_queue.put(f"接收线程异常退出:\n{err}")
            self.stop_event.set()

    # 主线程调用，安全更新文本框显示
    def update_chat_display(self, msg):
        def append():
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, msg + "\n")
            self.chat_display.see(tk.END)
            self.chat_display.config(state='disabled')
        self.master.after(0, append)

    # 定时调用，读取接收队列的消息，交给update_chat_display
    def process_incoming_messages(self):
        try:
            while True:
                msg = self.receive_queue.get_nowait()
                self.update_chat_display(msg)
        except queue.Empty:
            pass
        if not self.stop_event.is_set():
            self.master.after(100, self.process_incoming_messages)
        else:
            self.update_chat_display("服务器已停止。")

def main():
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use('clam')  # 主题美观
    app = ServerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
