

# Encrypted Multi-Client Chat Application

This project is a GUI-based multi-client chat application built using Python. It enables secure communication over a network with end-to-end encryption using AES for symmetric encryption and RSA for key exchange. 

### Features
- **End-to-End Encryption**: AES (GCM) encryption for secure message exchange, with AES keys shared securely using RSA encryption.
- **Multi-Client Support**: Allows multiple clients to connect and communicate in a single chat room.
- **GUI Interface**: Built with Tkinter for a simple, user-friendly interface.
- **Secure Key Exchange**: RSA public-private key exchange for encrypted AES keys, enhancing message security.
  
---

## Table of Contents
1. [Requirements](#requirements)
2. [Setup and Installation](#setup-and-installation)
3. [Usage](#usage)
4. [Functionality](#functionality)
5. [Acknowledgments](#acknowledgments)

---

## Requirements

The application uses several external libraries. Ensure the following are installed:
- `cryptography` for encryption (`pip install cryptography`)
- `tkinter` (pre-installed with Python standard library)
- `socket` and `threading` modules (Python standard library)

Ensure Python 3.6 or higher is installed on your system.

---

## Setup and Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/sribolo/secure-chat-app.git
   cd secure-chat-app
   ```

2. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```

3. **Generate RSA Keys (Optional)**: You can regenerate the RSA key pair if needed. 
   ```python
   # Python script provided to generate RSA keys.
   # Keys will be saved as 'private_key.pem' and 'public_key.pem'.
   ```

---

## Usage

1. **Start the Server**:
   - Run the server script to start the chat server, which will listen for incoming client connections.
   ```bash
   python server.py
   ```

2. **Start the Client**:
   - Run the client script to open the chat client.
   ```bash
   python client.py
   ```

3. **Connect and Chat**:
   - Enter a username in the client interface and click “Join” to connect to the server.
   - Type messages in the text box and click “Send” to chat with other connected users.

---

## Functionality

### Server (`server.py`)
- Listens for incoming client connections and handles message distribution to all connected clients.
- Broadcasts messages while maintaining AES encryption for each client.
- Handles client AES key exchanges using RSA to secure communication channels.

### Client (`client.py`)
- Connects to the server, sends an AES key encrypted with RSA, and facilitates secure chat sessions.
- Provides a Tkinter-based GUI for ease of use, including message entry, send functionality, and an option to end the chat.

---

## Acknowledgments
This project leverages Python’s `cryptography` library and standard `socket` programming to build a secure chat application suitable for network security and cryptography demonstrations.

