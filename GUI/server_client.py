import sys
import socket
import threading
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTextEdit, QLineEdit, QPushButton, 
                             QVBoxLayout, QWidget, QLabel, QComboBox, QTabWidget, QFormLayout, QSpinBox, QHBoxLayout)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
# -------------------- Network Thread Class --------------------
class NetworkThread(QThread):
    # Signals to communicate with the main thread
    message_received = pyqtSignal(str)
    connection_status = pyqtSignal(str)
    def __init__(self, mode, host, port):
        super().__init__()
        self.mode = mode
        self.host = host
        self.port = port
        self.socket = None
        self.shared_key = None
        self.stop_event = threading.Event()

    def run(self):
        # Determine whether to run as server or client
        if self.mode == 'server':
            self.run_server()
        elif self.mode == 'client':
            self.run_client()

    def run_server(self):
        # Server logic with automatic reconnection
        while not self.stop_event.is_set():
            try:
                # Generate private and public keys
                private_key = x25519.X25519PrivateKey.generate()
                public_key = private_key.public_key().public_bytes()
                
                # Set up server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.bind((self.host, self.port))
                server_socket.listen(1)
                self.connection_status.emit("Server listening on port {}...".format(self.port))
                
                # Accept connection
                self.socket, addr = server_socket.accept()
                self.connection_status.emit(f"Connection from {addr}")
                
                # Exchange public keys
                self.socket.sendall(public_key)
                peer_public_key_bytes = self.socket.recv(32)
                self.shared_key = generate_shared_key(private_key, peer_public_key_bytes)
                
                # Start receiving messages
                self.receive_messages()
            except Exception as e:
                self.connection_status.emit(f"An error occurred: {e}")
                self.connection_status.emit("Restarting server...")
                time.sleep(2)

    def run_client(self):
        # Client logic with automatic reconnection
        while not self.stop_event.is_set():
            try:
                # Generate private and public keys
                private_key = x25519.X25519PrivateKey.generate()
                public_key = private_key.public_key().public_bytes()
                
                # Connect to server
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                
                # Exchange public keys
                peer_public_key_bytes = self.socket.recv(32)
                self.socket.sendall(public_key)
                self.shared_key = generate_shared_key(private_key, peer_public_key_bytes)
                
                # Start receiving messages
                self.receive_messages()
            except Exception as e:
                self.connection_status.emit(f"An error occurred: {e}")
                self.connection_status.emit("Reconnecting...")
                time.sleep(2)

    def send_message(self, message):
        # Encrypt and send message
        if self.socket and self.shared_key:
            encrypt_and_send(self.socket, self.shared_key, message)
            if message.lower() == 'exit':
                self.stop_event.set()
                self.socket.close()

    def receive_messages(self):
        # Receive and decrypt messages
        while not self.stop_event.is_set():
            try:
                message = receive_and_decrypt(self.socket, self.shared_key)
                if message is None or message.lower() == 'exit':
                    self.connection_status.emit("Disconnected.")
                    self.stop_event.set()
                    break
                elif message == "ERROR":
                    self.connection_status.emit("Decryption failed.")
                else:
                    self.message_received.emit(message)
            except Exception as e:
                self.connection_status.emit(f"Error receiving message: {e}")
                self.stop_event.set()
                break
# -------------------- Main Chat Application Class --------------------
class ChatApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat")
        self.setGeometry(100, 100, 600, 500)

        # Create tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        # Create chat and settings tabs
        self.chat_tab = QWidget()
        self.settings_tab = QWidget()
        # Add tabs to the tab widget
        self.tabs.addTab(self.chat_tab, "Chat")
        self.tabs.addTab(self.settings_tab, "Settings")
        # Initialize tabs
        self.init_chat_tab()
        self.init_settings_tab()

        self.network_thread = None

    def init_chat_tab(self):
        # Layout for chat tab
        layout = QVBoxLayout()
        # Chat display area
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setFont(QFont("Courier", 10))
        layout.addWidget(self.chat_display)
        # Input and send button layout
        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        input_layout.addWidget(self.message_input)
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_button)
        layout.addLayout(input_layout)
        self.chat_tab.setLayout(layout)
    def init_settings_tab(self):
        # Layout for settings tab
        layout = QFormLayout()
        # Mode selection
        self.mode_selector = QComboBox()
        self.mode_selector.addItems(["Server", "Client"])
        layout.addRow("Mode:", self.mode_selector)
        # Host input
        self.host_input = QLineEdit("localhost")
        layout.addRow("Host:", self.host_input)
        # Port input
        self.port_input = QSpinBox()
        self.port_input.setRange(1024, 65535)
        self.port_input.setValue(65432)
        layout.addRow("Port:", self.port_input)
        # Connect button
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.start_connection)
        layout.addRow(self.connect_button)

        self.settings_tab.setLayout(layout)
    def start_connection(self):
        # Start network connection based on settings
        mode = self.mode_selector.currentText().lower()
        host = self.host_input.text()
        port = self.port_input.value()

        if self.network_thread:
            self.network_thread.stop_event.set()
            self.network_thread.wait()

        self.network_thread = NetworkThread(mode, host, port)
        self.network_thread.message_received.connect(self.display_message)
        self.network_thread.connection_status.connect(self.display_status)
        self.network_thread.start()
    def send_message(self):
        # Send message through network thread
        message = self.message_input.text()
        if message and self.network_thread:
            self.network_thread.send_message(message)
            self.chat_display.append(f"You: {message}")
            self.message_input.clear()
    def display_message(self, message):
        # Display received message
        self.chat_display.append(f"Peer: {message}")
    def display_status(self, status):
        # Display connection status
        print(status)  # Print status messages to the console
        self.chat_display.append(status)
# -------------------- Helper Functions --------------------
def generate_shared_key(private_key, peer_public_key_bytes):
    # Generate shared key using X25519 and HKDF
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)
    return derived_key
def encrypt_and_send(sock, key, plaintext):
    # Encrypt message and send over socket
    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        msg_length = len(nonce + ciphertext)
        sock.sendall(msg_length.to_bytes(4, 'big') + nonce + ciphertext)
    except Exception as e:
        print(f"Error during encryption or sending: {e}")
def receive_and_decrypt(sock, key):
    # Receive and decrypt message from socket
    try:
        raw_msglen = recvall(sock, 4)
        if not raw_msglen:
            return None
        msglen = int.from_bytes(raw_msglen, 'big')
        encrypted_message = recvall(sock, msglen)
        if not encrypted_message:
            return None
        aesgcm = AESGCM(key)
        nonce = encrypted_message[:12]
        actual_ciphertext = encrypted_message[12:]
        plaintext = aesgcm.decrypt(nonce, actual_ciphertext, None)
        return plaintext.decode()
    except Exception as e:
        print(f"Error during decryption: {e}")
        return "ERROR"
def recvall(sock, n):
    # Helper function to receive n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data
# -------------------- Main Function --------------------
def main():
    # Initialize and run the application
    app = QApplication(sys.argv)
    chat_app = ChatApp()
    chat_app.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
