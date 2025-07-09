# tcp_x25519_json_chat.py

import socket
import threading
import sys
import os
import json
from cryptography.hazmat.primitives.asymmetric import x25519  # 使用cryptography库的X25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # 使用AEAD加密

# —— 辅助函数 —— #
def recv_exact(sock, nbytes):
    """
    接收指定字节数的数据。
    """
    buf = b''
    while len(buf) < nbytes:
        chunk = sock.recv(nbytes - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def send_packet(sock, data: bytes):
    """
    发送数据包，包含数据长度和实际数据。
    """
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)

def recv_packet(sock) -> bytes:
    """
    接收数据包，先接收数据长度，再接收实际数据。
    """
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None
    length = int.from_bytes(hdr, 'big')
    return recv_exact(sock, length)

def do_handshake(sock, is_server: bool) -> ChaCha20Poly1305:
    """
    执行X25519密钥交换，返回一个AEAD加密器。
    is_server=True: 先接收客户端公钥，再发送服务端公钥。
    is_server=False: 先发送客户端公钥，再接收服务端公钥。
    """
    priv_key = x25519.X25519PrivateKey.generate()
    pub_bytes = priv_key.public_key().public_bytes()

    if is_server:
        peer_pub = recv_packet(sock)
        send_packet(sock, pub_bytes)
    else:
        send_packet(sock, pub_bytes)
        peer_pub = recv_packet(sock)

    peer_pubkey = x25519.X25519PublicKey.from_public_bytes(peer_pub)
    shared = priv_key.exchange(peer_pubkey)
    aead_key = shared[:32]
    return ChaCha20Poly1305(aead_key)

# —— 接收线程 —— #
def receiver_thread(sock, aead: ChaCha20Poly1305):
    while True:
        packet = recv_packet(sock)
        if packet is None:
            print("[*] Peer closed connection.")
            break

        nonce = packet[:12]
        ciphertext = packet[12:]
        try:
            plaintext = aead.decrypt(nonce, ciphertext, None)
        except Exception as e:
            print("[!] Decrypt failed:", e)
            continue

        try:
            obj = json.loads(plaintext.decode('utf-8'))
            # 处理接收到的JSON对象
            print(f"[RECV] JSON object: {obj}")
        except json.JSONDecodeError:
            print("[!] Received non-JSON data:", plaintext)

# —— 发送线程 —— #
def sender_thread(sock, aead: ChaCha20Poly1305):
    """
    提示用户输入一行JSON字典，例如 {"type":"msg","content":"hello"}
    输入 'exit' 退出。
    """
    while True:
        line = input("Enter JSON (or 'exit'): ").strip()
        if line.lower() == 'exit':
            sock.close()
            break
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print("[!] Invalid JSON:", e)
            continue

        data = json.dumps(obj, separators=(',',':')).encode('utf-8')
        nonce = os.urandom(12)
        cipher = aead.encrypt(nonce, data, None)
        send_packet(sock, nonce + cipher)

# —— 主函数 —— #
def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ('server','client'):
        print("Usage:")
        print("  python tcp_x25519_json_chat.py server <bind_ip> <port>")
        print("  python tcp_x25519_json_chat.py client <server_ip> <port>")
        return

    mode, ip, port = sys.argv[1], sys.argv[2], int(sys.argv[3])

    if mode == 'server':
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((ip, port))
        listener.listen(1)
        print(f"[*] Listening on {ip}:{port}")
        conn, addr = listener.accept()
        print(f"[*] Connection from {addr}")
        sock = conn
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        print(f"[*] Connected to {ip}:{port}")

    aead = do_handshake(sock, is_server=(mode=='server'))
    print("[*] Handshake complete. Secure channel ready.")

    t_recv = threading.Thread(target=receiver_thread, args=(sock, aead), daemon=True)
    t_send = threading.Thread(target=sender_thread, args=(sock, aead), daemon=True)
    t_recv.start()
    t_send.start()
    t_send.join()
    print("[*] Sender exited, shutting down.")

if __name__ == '__main__':
    main()
