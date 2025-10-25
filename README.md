# 🔐 Secure Chat App with End-to-End Encryption

This project is a real-time, private chat application that implements **End-to-End Encryption (E2EE)** using Python, Flask-SocketIO, and the `cryptography` library.

The server acts only as a blind relay for encrypted messages. It cannot read the content of the messages, and it does not store user private keys. This ensures that only the sender and the intended recipient can ever decrypt and read the conversation.

---

## Core Technology: Hybrid Encryption

This application uses a **hybrid encryption** scheme to get the best of both worlds: the security of asymmetric (public-key) cryptography and the speed of symmetric cryptography.

1.  **RSA (Asymmetric):** Each user has a **public key** (shared with everyone) and a **private key** (kept secret). RSA is used only to securely exchange a one-time-use "session key."
2.  **AES (Symmetric):** This is a very fast and secure algorithm used to encrypt the actual chat messages. The key for this is the "session key" that was exchanged using RSA.

This way, long messages are encrypted quickly with AES, and the key to unlock them is securely shared using RSA.

---

## Features

* **End-to-End Encryption:** Messages are encrypted on the sender's device and decrypted only on the recipient's device.
* **Real-Time Communication:** Uses WebSockets (via Flask-SocketIO) for instant message delivery.
* **Secure Key Exchange:** Safely establishes a shared secret (AES key) for each conversation using RSA.
* **User Registration:** A simple system where users register a username and their public key with the server.
* **Persistent Keys:** RSA private keys are generated and saved locally for each user (e.g., `alice_private.pem`), so their identity is persistent.
* **Server Privacy:** The server is "blind" and cannot read any message content.
