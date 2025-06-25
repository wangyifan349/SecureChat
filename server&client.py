import socket  # Import socket module for network communication
import threading  # Import threading module for concurrent execution
import time  # Import time module for delays
from cryptography.hazmat.primitives.asymmetric import x25519  # Import X25519 for key exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # Import HKDF for key derivation
from cryptography.hazmat.primitives import hashes  # Import hashes for cryptographic operations
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Import AESGCM for encryption
import os  # Import os for generating random numbers

def generate_shared_key(private_key, peer_public_key_bytes):
    # Convert peer's public key bytes to a public key object
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    # Perform key exchange to get a shared key
    shared_key = private_key.exchange(peer_public_key)
    # Derive a symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),  # Use SHA256 for hashing
        length=32,  # Output key length of 32 bytes
        salt=None,  # No salt used
        info=b'handshake data'  # Contextual information
    ).derive(shared_key)
    return derived_key  # Return the derived symmetric key

def encrypt_and_send(sock, key, plaintext):
    try:
        aesgcm = AESGCM(key)  # Initialize AESGCM with the symmetric key
        nonce = os.urandom(12)  # Generate a random 12-byte nonce
        # Encrypt the plaintext message
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        msg_length = len(nonce + ciphertext)  # Calculate total message length
        # Send the message length and encrypted data
        sock.sendall(msg_length.to_bytes(4, 'big') + nonce + ciphertext)
    except Exception as e:
        print(f"Error during encryption or sending: {e}")  # Print error if any

def receive_and_decrypt(sock, key):
    try:
        raw_msglen = recvall(sock, 4)  # Receive the first 4 bytes for message length
        if not raw_msglen:
            return None  # Return None if connection is closed
        msglen = int.from_bytes(raw_msglen, 'big')  # Convert bytes to integer
        encrypted_message = recvall(sock, msglen)  # Receive the full encrypted message
        if not encrypted_message:
            return None  # Return None if connection is closed
        aesgcm = AESGCM(key)  # Initialize AESGCM with the symmetric key
        nonce = encrypted_message[:12]  # Extract nonce from the message
        actual_ciphertext = encrypted_message[12:]  # Extract ciphertext
        # Decrypt the message
        plaintext = aesgcm.decrypt(nonce, actual_ciphertext, None)
        return plaintext.decode()  # Return the decoded plaintext
    except Exception as e:
        print(f"Error during decryption: {e}")  # Print error if any
        return "ERROR"  # Return error string

def recvall(sock, n):
    data = bytearray()  # Initialize a bytearray to store received data
    while len(data) < n:  # Loop until all bytes are received
        packet = sock.recv(n - len(data))  # Receive the remaining bytes
        if not packet:
            return None  # Return None if connection is closed
        data.extend(packet)  # Append received packet to data
    return data  # Return the complete data

def handle_connection(sock, shared_key, is_server):
    stop_event = threading.Event()  # Event to signal stopping threads

    def send_messages():
        while not stop_event.is_set():  # Loop until stop event is set
            try:
                # Prompt user for input
                message = input("Server: " if is_server else "Client: ")
                encrypt_and_send(sock, shared_key, message)  # Encrypt and send message
                if message.lower() == 'exit':  # Check for exit command
                    stop_event.set()  # Set stop event
                    sock.close()  # Close the socket
                    break  # Exit the loop
            except Exception as e:
                print(f"Error sending message: {e}")  # Print error if any
                stop_event.set()  # Set stop event
                break  # Exit the loop

    def receive_messages():
        while not stop_event.is_set():  # Loop until stop event is set
            try:
                message = receive_and_decrypt(sock, shared_key)  # Receive and decrypt message
                if message is None or message.lower() == 'exit':  # Check for disconnection or exit
                    print("Client disconnected." if is_server else "Server disconnected.")
                    stop_event.set()  # Set stop event
                    break  # Exit the loop
                elif message == "ERROR":  # Check for decryption error
                    print("Decryption failed.")
                else:
                    # Print the received message
                    print(f"Client: {message}" if is_server else f"Server: {message}")
            except Exception as e:
                print(f"Error receiving message: {e}")  # Print error if any
                stop_event.set()  # Set stop event
                break  # Exit the loop

    # Create and start threads for sending and receiving messages
    send_thread = threading.Thread(target=send_messages)
    receive_thread = threading.Thread(target=receive_messages)
    send_thread.start()
    receive_thread.start()
    send_thread.join()  # Wait for send thread to finish
    receive_thread.join()  # Wait for receive thread to finish

def run_server():
    while True:  # Loop to allow for reconnection
        try:
            private_key = x25519.X25519PrivateKey.generate()  # Generate private key
            public_key = private_key.public_key().public_bytes()  # Get public key bytes
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket
            server_socket.bind(('localhost', 65432))  # Bind to localhost and port 65432
            server_socket.listen(1)  # Listen for incoming connections
            print("Server listening on port 65432...")
            client_socket, addr = server_socket.accept()  # Accept a connection
            print(f"Connection from {addr}")
            client_socket.sendall(public_key)  # Send public key to client
            peer_public_key_bytes = client_socket.recv(32)  # Receive client's public key
            shared_key = generate_shared_key(private_key, peer_public_key_bytes)  # Generate shared key
            handle_connection(client_socket, shared_key, is_server=True)  # Handle communication
        except Exception as e:
            print(f"An error occurred: {e}")  # Print error if any
            print("Restarting server...")
            time.sleep(2)  # Wait before restarting

def run_client():
    while True:  # Loop to allow for reconnection
        try:
            private_key = x25519.X25519PrivateKey.generate()  # Generate private key
            public_key = private_key.public_key().public_bytes()  # Get public key bytes
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket
            server_socket.connect(('localhost', 65432))  # Connect to server
            peer_public_key_bytes = server_socket.recv(32)  # Receive server's public key
            server_socket.sendall(public_key)  # Send public key to server
            shared_key = generate_shared_key(private_key, peer_public_key_bytes)  # Generate shared key
            handle_connection(server_socket, shared_key, is_server=False)  # Handle communication
        except Exception as e:
            print(f"An error occurred: {e}")  # Print error if any
            print("Reconnecting...")
            time.sleep(2)  # Wait before reconnecting

def main():
    # Prompt user to choose mode
    mode = input("Enter 'server' to run as server or 'client' to run as client: ").strip().lower()
    if mode == 'server':
        run_server()  # Run as server
    elif mode == 'client':
        run_client()  # Run as client
    else:
        print("Invalid mode. Please enter 'server' or 'client'.")  # Invalid input

if __name__ == "__main__":
    main()  # Entry point of the script
