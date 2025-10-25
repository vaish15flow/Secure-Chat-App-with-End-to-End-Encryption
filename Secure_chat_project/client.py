# client.py (Fixed and Improved)
import socketio
import os
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

# --- Global Variables ---
sio = socketio.Client()
username = ""
private_key = None
public_key = None
# {recipient_username: aes_key}
session_keys = {}
# {recipient_username: public_key_pem}
recipient_public_keys = {} # <-- ADDED: To store recipient keys
# {recipient_username: "message"}
pending_messages = {} # <-- ADDED: To send first message automatically

# --- Key Generation and Management ---
def generate_and_load_keys(user):
    global private_key, public_key
    private_key_file = f"{user}_private.pem"
    if os.path.exists(private_key_file):
        # Load existing keys
        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        public_key = private_key.public_key()
        print("🔑 Loaded existing RSA keys.")
    else:
        # Generate new keys
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        # Save private key
        with open(private_key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print("✨ Generated and saved new RSA keys.")

def get_public_key_pem(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

# --- Encryption / Decryption ---
def encrypt_aes(message, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(message.encode()) + encryptor.finalize()

def decrypt_aes(encrypted_message, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted_message) + decryptor.finalize()).decode()

def encrypt_rsa(data, recipient_pem):
    recipient_public_key = serialization.load_pem_public_key(recipient_pem.encode())
    return recipient_public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_rsa(encrypted_data):
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# --- Socket.IO Event Handlers ---
@sio.event
def connect():
    print("🔗 Connected to server!")
    public_key_pem = get_public_key_pem(public_key)
    sio.emit('register', {'username': username, 'public_key': public_key_pem})

@sio.event
def disconnect():
    print("🔌 Disconnected from server.")

@sio.on('register_success')
def on_register_success(user_list):
    print(f"✅ Successfully registered as '{username}'.")
    print("Available users:", user_list)

@sio.on('register_fail')
def on_register_fail(data):
    print(f"❌ Registration failed: {data['message']}")
    sio.disconnect()

@sio.on('user_list_update')
def on_user_list_update(user_list):
    print("\n[SYSTEM] User list updated:", user_list)

# --- MODIFIED FUNCTION ---
@sio.on('user_info_response')
def on_user_info_response(data):
    global username
    recipient_username = data['username']
    recipient_public_key_pem = data['public_key']
    
    # 1. Store the recipient's public key
    recipient_public_keys[recipient_username] = recipient_public_key_pem
    
    # 2. Generate AES session key for this recipient
    aes_key = os.urandom(32)  # 256-bit AES key
    session_keys[recipient_username] = aes_key
    
    # 3. Encrypt the AES key with RECIPIENT'S public key
    encrypted_aes_key = encrypt_rsa(aes_key, recipient_public_key_pem)

    print(f"🔒 Secure session with '{recipient_username}' established.")

    # 4. Check if we have a pending message to send
    if recipient_username in pending_messages:
        message = pending_messages.pop(recipient_username)
        print(f"[SYSTEM] Sending pending message: {message}")

        iv = os.urandom(16)
        encrypted_message = encrypt_aes(message, aes_key, iv)
        
        # 5. Send the first message payload, including the encrypted key
        payload = {
            'sender': username,
            'recipient': recipient_username,
            'encrypted_data': {
                'message': base64.b64encode(encrypted_message).decode(),
                'key': base64.b64encode(encrypted_aes_key).decode(), # <-- Send the key
                'iv': base64.b64encode(iv).decode()
            }
        }
        sio.emit('private_message', payload)

# --- MODIFIED FUNCTION ---
@sio.on('new_private_message')
def on_new_private_message(data):
    sender = data['sender']
    encrypted_data = data['encrypted_data']

    encrypted_msg_b64 = encrypted_data['message']
    encrypted_key_b64 = encrypted_data['key'] # This might be None
    iv_b64 = encrypted_data['iv']

    encrypted_msg = base64.b64decode(encrypted_msg_b64)
    iv = base64.b64decode(iv_b64)

    # Check if we need to decrypt a new session key
    if sender not in session_keys:
        if encrypted_key_b64 is None:
            print(f"\n[ERROR] Received message from {sender} without a session key.")
            return
        
        # This is the first message, decrypt the AES key
        try:
            encrypted_key = base64.b64decode(encrypted_key_b64)
            session_keys[sender] = decrypt_rsa(encrypted_key)
        except Exception as e:
            print(f"\n[ERROR] Could not decrypt session key from {sender}: {e}")
            return
    
    # Decrypt the message with the session key
    try:
        aes_key = session_keys[sender] # Get the established key
        decrypted_message = decrypt_aes(encrypted_msg, aes_key, iv)
        print(f"\n📩 [{sender}]: {decrypted_message}")
    except Exception as e:
        print(f"\n[ERROR] Could not decrypt message from {sender}: {e}")

# --- Main Application Logic (MODIFIED) ---
def send_messages():
    print("Type messages in the format: @recipient message")
    print("Example: @bob Hello Bob!")
    while True:
        message_text = input()
        if not message_text.startswith('@'):
            print("[SYSTEM] Invalid format. Use @recipient message")
            continue
        
        try:
            recipient, message = message_text[1:].split(' ', 1)
        except ValueError:
            print("[SYSTEM] Invalid format. Use @recipient message")
            continue
        
        # --- IF NO SESSION ---
        if recipient not in session_keys:
            print(f"[SYSTEM] No secure session with '{recipient}'. Establishing one...")
            # Store the message to be sent after key exchange
            pending_messages[recipient] = message 
            sio.emit('request_user_info', {'username': recipient})
            continue

        # --- IF SESSION EXISTS ---
        aes_key = session_keys[recipient]
        iv = os.urandom(16)
        encrypted_message = encrypt_aes(message, aes_key, iv)
        
        # Send payload *without* the key, as it's established
        payload = {
            'sender': username,
            'recipient': recipient,
            'encrypted_data': {
                'message': base64.b64encode(encrypted_message).decode(),
                'key': None, # <-- Key is None, not needed
                'iv': base64.b64encode(iv).decode()
            }
        }
        sio.emit('private_message', payload)

# --- Entry Point ---
if __name__ == '__main__':
    username = input("Enter your username: ")
    generate_and_load_keys(username)
    
    # Start message sending in a separate thread
    thread = threading.Thread(target=send_messages)
    thread.daemon = True
    thread.start()

    try:
        sio.connect('http://localhost:5001')
        sio.wait()
    except Exception as e:
        print(f"Could not connect to server: {e}")