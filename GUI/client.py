# client.py
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import queue
import traceback

def generate_shared_key(private_key, peer_public_key_bytes):
    # 解析对方公钥并生成共享密钥和派生对称密钥
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)
    return derived_key

def encrypt_message(key, plaintext):
    # AES-GCM加密消息
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ciphertext

def decrypt_message(key, pkt):
    # 解密消息
    aesgcm = AESGCM(key)
    nonce = pkt[:12]
    ciphertext = pkt[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

def send_packet(sock, packet):
    # 发送包含4字节长度包头的包
    length = len(packet)
    sock.sendall(length.to_bytes(4, 'big') + packet)

def recv_pkt(sock):
    # 接收完整消息包
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    length = int.from_bytes(raw_len, 'big')
    if length <= 0 or length > 10 ** 7:
        return None  # 安全限制
    data = recvall(sock, length)
    return data

def recvall(sock, n):
    # 确保读满n字节或连接关闭
    data = b''
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
        except Exception:
            return None
        if not packet:
            return None
        data += packet
    return data

class ClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title('🔒 SecureChat 客户端')
        self.master.geometry("700x500")
        self.master.configure(bg='#fff3e0')

        # 消息显示区
        self.chat_display = ScrolledText(master, state='disabled', font=("Consolas", 12), bg='#fffaf0', fg='#444444')
        self.chat_display.pack(padx=15, pady=15, fill=tk.BOTH, expand=True)

        # 输入区
        frame = tk.Frame(master, bg='#fff3e0')
        frame.pack(padx=15, pady=(0, 15), fill=tk.X)

        self.message_entry = ttk.Entry(frame, font=("Consolas", 12))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,10))
        self.message_entry.bind('<Return>', self.send_message)

        self.send_button = ttk.Button(frame, text='发送', command=self.send_message)
        self.send_button.pack(side=tk.LEFT)

        self.stop_event = threading.Event()
        self.sock = None
        self.shared_key = None
        self.receive_queue = queue.Queue()

        # 主窗口关闭事件
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

        # 连接服务器线程
        threading.Thread(target=self.connect_server_loop, daemon=True).start()

        # 定时检查消息队列并刷新界面
        self.master.after(100, self.process_incoming_messages)

    def connect_server_loop(self):
        while not self.stop_event.is_set():
            try:
                private_key = x25519.X25519PrivateKey.generate()
                public_key = private_key.public_key().public_bytes()
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect(('127.0.0.1', 65432))
                self.update_chat_display('已连接到服务器。')
                peer_public_key_bytes = recvall(self.sock, 32)
                if not peer_public_key_bytes:
                    self.update_chat_display("未能接收服务器公钥，断开连接。")
                    self.sock.close()
                    time.sleep(2)
                    continue
                self.sock.sendall(public_key)
                self.shared_key = generate_shared_key(private_key, peer_public_key_bytes)
                self.sock.settimeout(None)
                threading.Thread(target=self.receive_loop, daemon=True).start()
                break
            except Exception as e:
                self.update_chat_display(f"连接异常: {e}")
                time.sleep(2)

    def safe_send(self, message):
        if not self.sock or not self.shared_key:
            self.update_chat_display("尚未连接服务器，无法发送。")
            return
        try:
            pkt = encrypt_message(self.shared_key, message)
            send_packet(self.sock, pkt)
        except Exception as e:
            self.update_chat_display(f"发送失败: {e}")

    def send_message(self, event=None):
        msg = self.message_entry.get().strip()
        if not msg:
            return
        self.message_entry.delete(0, tk.END)
        threading.Thread(target=self.safe_send, args=(msg,), daemon=True).start()
        self.update_chat_display(f"客户端: {msg}")
        if msg.lower() == 'exit':
            self.stop_event.set()
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except Exception:
                pass
            self.master.quit()

    def receive_loop(self):
        try:
            while not self.stop_event.is_set():
                pkt = recv_pkt(self.sock)
                if pkt is None:
                    self.receive_queue.put("服务器已断开连接。")
                    self.stop_event.set()
                    break
                try:
                    message = decrypt_message(self.shared_key, pkt)
                except Exception:
                    self.receive_queue.put("[警告] 收到无效或被篡改的消息")
                    continue
                if not message:
                    continue
                if message.lower() == 'exit':
                    self.receive_queue.put("服务器请求断开连接。")
                    self.stop_event.set()
                    break
                self.receive_queue.put(f"服务器: {message}")
        except Exception:
            err = traceback.format_exc()
            self.receive_queue.put(f"接收线程异常退出:\n{err}")
            self.stop_event.set()

    def update_chat_display(self, msg):
        def append():
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, msg + "\n")
            self.chat_display.see(tk.END)
            self.chat_display.config(state='disabled')
        self.master.after(0, append)

    def process_incoming_messages(self):
        try:
            while True:
                msg = self.receive_queue.get_nowait()
                self.update_chat_display(msg)
        except queue.Empty:
            pass
        if not self.stop_event.is_set():
            self.master.after(100, self.process_incoming_messages)

    def on_close(self):
        self.stop_event.set()
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
        except Exception:
            pass
        self.master.destroy()

def main():
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use('clam')  # 美观主题
    app = ClientGUI(root)
    root.mainloop()

if __name__=="__main__":
    main()
