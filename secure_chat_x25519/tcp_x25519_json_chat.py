import socket
import threading
import sys
import os
import json
import time
import base64
from nacl.public import PrivateKey, PublicKey
from nacl.bindings.crypto_kx import crypto_kx_client_session_keys, crypto_kx_server_session_keys
from Crypto.Cipher import ChaCha20_Poly1305

# —— helper functions —— #
def recv_exact(sock, nbytes):
    buf = b''
    while len(buf) < nbytes:
        chunk = sock.recv(nbytes - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def send_packet(sock, data: bytes):
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)

def recv_packet(sock) -> bytes:
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None
    length = int.from_bytes(hdr, 'big')
    return recv_exact(sock, length)

def do_handshake(sock, is_server: bool):
    """
    使用PyNaCl进行X25519密钥交换，返回会话密钥。
    is_server=True: 先接收客户端公钥，然后发送服务端公钥。
    is_server=False: 先发送客户端公钥，然后接收服务端公钥。
    """
    priv_key = PrivateKey.generate()
    pub_key = priv_key.public_key

    pub_bytes = pub_key.encode()

    if is_server:
        peer_pub_bytes = recv_packet(sock)
        send_packet(sock, pub_bytes)
    else:
        send_packet(sock, pub_bytes)
        peer_pub_bytes = recv_packet(sock)

    peer_pub_key = PublicKey(peer_pub_bytes)

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

    return rx_key, tx_key

# —— receiver thread —— #
def receiver_thread(sock, rx_key):
    while True:
        packet = recv_packet(sock)
        if packet is None:
            print("\n[*] Peer closed connection.")
            break

        try:
            # 解析收到的JSON数据
            encrypted_message = json.loads(packet.decode('utf-8'))
            nonce = base64.b64decode(encrypted_message['nonce'])
            tag = base64.b64decode(encrypted_message['tag'])
            ciphertext = base64.b64decode(encrypted_message['ciphertext'])
        except Exception as e:
            print("\n[!] Failed to parse JSON:", e)
            continue

        try:
            cipher = ChaCha20_Poly1305.new(key=rx_key, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            print("\n[!] Decrypt failed:", e)
            continue

        try:
            message_obj = json.loads(plaintext.decode('utf-8'))
            timestamp = message_obj.get('timestamp', 'Unknown time')
            message = message_obj.get('message', '')

            print(f"\n[RECV][{timestamp}] {message}")
            print("Enter message (or 'exit'): ", end='', flush=True)
        except json.JSONDecodeError:
            print("\n[!] Received non-JSON data:", plaintext)

# —— sender thread —— #
def sender_thread(sock, tx_key):
    """
    提示用户输入消息文本。
    输入 'exit' 退出。
    """
    while True:
        try:
            line = input("Enter message (or 'exit'): ").strip()
        except EOFError:
            # 处理 Ctrl+D
            sock.close()
            break
        if line.lower() == 'exit':
            sock.close()
            break

        # 创建包含消息和时间戳的对象
        message_obj = {
            'message': line,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        }

        data = json.dumps(message_obj, separators=(',', ':')).encode('utf-8')
        nonce = os.urandom(12)
        cipher = ChaCha20_Poly1305.new(key=tx_key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # 构造要发送的JSON消息，包含nonce、tag、密文
        encrypted_message = {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

        send_packet(sock, json.dumps(encrypted_message).encode('utf-8'))

# —— main entry —— #
def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ('server', 'client'):
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

    rx_key, tx_key = do_handshake(sock, is_server=(mode == 'server'))
    print("[*] Handshake complete. Secure channel ready.")

    t_recv = threading.Thread(target=receiver_thread, args=(sock, rx_key), daemon=True)
    t_send = threading.Thread(target=sender_thread, args=(sock, tx_key), daemon=True)
    t_recv.start()
    t_send.start()
    t_send.join()
    print("[*] Sender exited, shutting down.")

if __name__ == '__main__':
    main()
