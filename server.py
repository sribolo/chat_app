import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = '127.0.0.1'
PORT = 1060
LISTENER_LIMIT = 5
active_clients = {}
client_aes_keys = {}

# Generate RSA Key Pair
rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
rsa_public_key = rsa_private_key.public_key()


def send_message_to_client(client, message, aes_key):
    try:
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
        encrypted_message = encryptor.update(message) + encryptor.finalize()
        client.sendall(iv + encrypted_message + encryptor.tag)
    except Exception as e:
        print(f"[ERROR] Could not send message to client: {e}")


def broadcast(message, sender_username=None):
    """Send a message to all clients except the sender."""
    for username, client in active_clients.items():
        if username != sender_username:
            try:
                aes_key = client_aes_keys[username]
                iv = os.urandom(12)
                encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
                encrypted_message = encryptor.update(message) + encryptor.finalize()
                client.sendall(len(encrypted_message).to_bytes(4, byteorder='big')) # Send the length of the encrypted message
                client.sendall(iv)  # Send the IV
                client.sendall(encrypted_message)  # Send the encrypted message
                client.sendall(encryptor.tag)  # Send the authentication tag
            except Exception as e:
                print(f"[ERROR] Could not send message to client {username}: {e}")


def aes_decrypt(iv, encrypted_message, tag, aes_key):
    """Decrypt the message using AES GCM mode."""
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    try:
        return decryptor.update(encrypted_message) + decryptor.finalize()
    except ValueError as e:
        print(f"[ERROR] Invalid authentication tag: {e}")
        return None


def handle_client(client_socket, client_address):
    print(f"[INFO] New connection from {client_address}")
    username = ""
    try:
        # Send public key to client
        client_socket.sendall(rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # Receive encrypted AES key
        encrypted_aes_key = client_socket.recv(256)
        aes_key = rsa_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Receive username
        username = client_socket.recv(1024).decode()
        if not username:
            print(f"[ERROR] Empty username received from {client_address}")
            return

        active_clients[username] = client_socket
        client_aes_keys[username] = aes_key
        print(f"[INFO] {username} has joined the chat.")
        broadcast(f"SERVER~{username} joined the chat.".encode(), username)

        while True:
            # Receive message components
            try:
                # Receive the length of the encrypted message
                message_length_bytes = client_socket.recv(4)
                if not message_length_bytes:
                    print(f"[INFO] Client {username} disconnected.")
                    break  # Client disconnected
                message_length = int.from_bytes(message_length_bytes, byteorder='big')

                # Receive the IV
                iv = client_socket.recv(12)

                # Receive the encrypted message
                encrypted_message = bytearray()
                while len(encrypted_message) < message_length:
                    chunk = client_socket.recv(message_length - len(encrypted_message))
                    encrypted_message.extend(chunk)

                # Receive the authentication tag
                tag = client_socket.recv(16)

                # Print the encrypted message received
                print(f"[INFO] Received encrypted message from {username}: {encrypted_message.hex()}")

                # Decrypt message
                decrypted_message = aes_decrypt(iv, encrypted_message, tag, aes_key).decode()

                # Print when the message is successfully decrypted
                print(f"[INFO] Decrypted message from {username}: {decrypted_message}")

                final_message = f"{username}:{decrypted_message}"
                print(final_message)  # Print to server console for debugging
                broadcast(final_message.encode(), username)

            except Exception as e:
                print(f"[ERROR] Error while processing message from {username}: {e}")
                break
    finally:
        if username:
            del active_clients[username]
            del client_aes_keys[username]
            print(f"[INFO] {username} has left the chat.")
        client_socket.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(LISTENER_LIMIT)
    print(f"Server is listening on {HOST}:{PORT}")

    while True:
        client_socket, client_address = server.accept()
        print(f"Successfully connected to client {client_address[0]} {client_address[1]}")
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()


if __name__ == "__main__":
    start_server()