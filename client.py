import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 1060

class Client:
    def __init__(self, master):
        self.gui = master
        self.gui.title("Chat Client")
        self.client_socket = None
        self.username = ""
        self.aes_key = os.urandom(32)

        # RSA Key Pair
        self.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        self.rsa_public_key = self.rsa_private_key.public_key()

        self.setup_ui()

    def setup_ui(self):
        self.gui.geometry("570x420")

        # Define frames
        top_frame = tk.Frame(self.gui, width=600, height=100)
        top_frame.grid(row=0, column=0, sticky=tk.NSEW)
        middle_frame = tk.Frame(self.gui, width=600, height=400)
        middle_frame.grid(row=1, column=0, sticky=tk.NSEW)
        bottom_frame = tk.Frame(self.gui, width=600, height=100)
        bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

        # Top frame - Username entry and join button
        self.username_label = tk.Label(top_frame, text="Enter username:")
        self.username_label.pack(side=tk.LEFT, padx=10)
        self.username_textbox = tk.Entry(top_frame, width=23)
        self.username_textbox.pack(side=tk.LEFT)
        self.username_button = tk.Button(top_frame, text="Join", command=self.connect_to_server)
        self.username_button.pack(side=tk.LEFT, padx=15)

        # Middle frame - Chat text area
        self.text_area = scrolledtext.ScrolledText(middle_frame, width=67, height=26.5)
        self.text_area.config(state=tk.DISABLED)
        self.text_area.pack(side=tk.TOP)

        # Bottom frame - Message entry and buttons
        self.message_textbox = tk.Entry(bottom_frame, width=38)
        self.message_textbox.pack(side=tk.LEFT, padx=10)
        self.send_button = tk.Button(bottom_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=10)
        self.end_chat_button = tk.Button(bottom_frame, text="End Chat", command=self.end_chat)
        self.end_chat_button.pack(side=tk.LEFT, padx=10)

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            self.add_message("[SERVER] Connected to Server")

            # Receive public key from server
            public_key_data = self.client_socket.recv(1024)
            self.public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())

            # Generate and send AES key
            encrypted_aes_key = self.public_key.encrypt(
                self.aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            self.client_socket.sendall(encrypted_aes_key)

            # Send username
            self.username = self.username_textbox.get()
            self.client_socket.sendall(self.username.encode())

            # Disable username entry
            self.username_textbox.config(state=tk.DISABLED)
            self.username_button.config(state=tk.DISABLED)

            # Start receiving messages in a separate thread
            threading.Thread(target=self.receive_messages, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Connection Error", f"Error: {e}")

    def receive_messages(self):
        while True:
            try:
                # Receive the length of the encrypted message
                message_length_bytes = self.client_socket.recv(4)
                if not message_length_bytes:
                    raise ConnectionError("Connection closed by server.")
                message_length = int.from_bytes(message_length_bytes, byteorder='big')

                # Validate message length
                if message_length <= 0:
                    print(f"[ERROR] Invalid message length received: {message_length}")
                    continue

                # Receive the IV, encrypted message, and authentication tag
                encrypted_message_with_iv_and_tag = bytearray()
                while len(encrypted_message_with_iv_and_tag) < message_length + 28:
                    chunk = self.client_socket.recv(message_length + 28 - len(encrypted_message_with_iv_and_tag))
                    if not chunk:
                        raise ConnectionError("Connection closed by server.")
                    encrypted_message_with_iv_and_tag.extend(chunk)

                # Extract IV, encrypted message, and authentication tag
                iv = bytes(encrypted_message_with_iv_and_tag[:12])
                encrypted_message = bytes(encrypted_message_with_iv_and_tag[12:-16])
                tag = bytes(encrypted_message_with_iv_and_tag[-16:])

                # Decrypt the message
                message = self.aes_decrypt(iv, encrypted_message, tag).decode('utf-8')

                # Check if the message is from the server or another client
                if message.startswith("SERVER~"):
                    self.add_message(message)
                else:
                    username, message = message.split(":", 1)
                    self.add_message(f"{username}: {message}")

            except ConnectionError as e:
                print(f"[INFO] Connection closed by server: {e}")
                break
            except OSError as e:
                if e.errno == 9:  # Bad file descriptor
                    print(f"[INFO] Socket connection closed: {e}")
                    break
            except Exception as e:
                print(f"[ERROR] Unexpected error: {e}")
                continue

    def send_message(self):
        message = self.message_textbox.get()
        if message:
            try:
                iv, encrypted_message, tag = self.aes_encrypt(message)
                print(f"[INFO] Sending encrypted message: {encrypted_message.hex()}")

                # Send the length of the encrypted message
                self.client_socket.sendall(len(encrypted_message).to_bytes(4, byteorder='big'))

                # Send message components: iv, encrypted_message, tag
                self.client_socket.sendall(iv + encrypted_message + tag)
                self.message_textbox.delete(0, tk.END)
            except OSError as e:
                if e.errno == 9:  # Bad file descriptor
                    print(f"[INFO] Socket connection closed: {e}")
                    self.end_chat()
                else:
                    messagebox.showerror("Send Error", f"Could not send message: {e}")
                    self.end_chat()
            except Exception as e:
                messagebox.showerror("Send Error", f"Could not send message: {e}")
                self.end_chat()
        else:
            messagebox.showerror("Empty message", "Message cannot be empty")
    def aes_encrypt(self, message):
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(self.aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        return iv, encrypted_message, encryptor.tag

    def aes_decrypt(self, iv, encrypted_message, tag):
        decryptor = Cipher(algorithms.AES(self.aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        return decryptor.update(encrypted_message) + decryptor.finalize()

    def add_message(self, message):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state=tk.DISABLED)
        self.text_area.yview(tk.END)

    def end_chat(self):
        self.client_socket.close()
        self.add_message("[SERVER] Disconnected from server.")
        self.gui.quit()

if __name__ == "__main__":
    root = tk.Tk()
    client = Client(root)
    root.mainloop()