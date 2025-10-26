import socketio
import requests
import json
import os
import base64
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------- CONFIG ----------------
SERVER_URL = "http://127.0.0.1:5000"

# ---------------- Setup ----------------
sio = socketio.Client()
LOG_FILE = None  # Will be set based on username

# ---------------- RSA / AES ----------------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(pubkey):
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def encrypt_aes_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def decrypt_aes_key(enc_key, private_key):
    return private_key.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def encrypt_message(message, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_message(ciphertext_b64, aes_key):
    data = base64.b64decode(ciphertext_b64)
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

def save_encrypted_log(message_data):
    global LOG_FILE
    if not LOG_FILE:
        return
    with open(LOG_FILE, "a") as f:
        json.dump(message_data, f)
        f.write("\n")

# ---------------- SOCKET EVENTS ----------------
@sio.on("connect")
def on_connect():
    print(f"[Connected] to Secure Chat Server as {USERNAME}")
    sio.emit("identify", {"username": USERNAME})

@sio.on("receive_encrypted")
def on_receive(data):
    enc_aes_key = base64.b64decode(data["enc_key"])
    enc_message = data["ciphertext"]
    aes_key = decrypt_aes_key(enc_aes_key, PRIVATE_KEY)
    message = decrypt_message(enc_message, aes_key)
    print(f"\n💬 {data['from']} -> {USERNAME}: {message}\n> ", end="")
    
    # Save received encrypted message locally
    save_encrypted_log(data)

# ---------------- MAIN LOGIC ----------------
def send_message():
    while True:
        to_user = input("Send to: ").strip()
        message = input("Message: ")

        # Fetch receiver’s public key
        resp = requests.get(f"{SERVER_URL}/get_key/{to_user}")
        if resp.status_code != 200:
            print("❌ Receiver not registered or offline.")
            continue

        recv_pub_key_pem = resp.json()["public_pem"].encode()
        recv_pub_key = serialization.load_pem_public_key(recv_pub_key_pem)

        # Generate AES key and encrypt
        aes_key = os.urandom(32)
        enc_aes_key = encrypt_aes_key(aes_key, recv_pub_key)
        enc_message = encrypt_message(message, aes_key)

        payload = {
            "from": USERNAME,
            "to": to_user,
            "enc_key": base64.b64encode(enc_aes_key).decode(),
            "ciphertext": enc_message
        }
        sio.emit("send_encrypted", payload)

        # Save sent encrypted message locally
        save_encrypted_log(payload)

# ---------------- RUN ----------------
if __name__ == "__main__":
    USERNAME = input("Enter your username: ").strip()
    LOG_FILE = f"{USERNAME}_output.enc"

    PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keys()

    # Save private key locally (optional for backup)
    priv_path = f"{USERNAME}_private.pem"
    with open(priv_path, "wb") as f:
        f.write(PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Register public key with server
    resp = requests.post(f"{SERVER_URL}/register_key", json={
        "username": USERNAME,
        "public_pem": serialize_public_key(PUBLIC_KEY)
    })
    if resp.status_code == 200:
        print(f"[Registered] Public key for {USERNAME} on server.")
    else:
        print("❌ Failed to register key.")

    # Connect to SocketIO server
    sio.connect(SERVER_URL)

    # Start sending messages in a separate thread
    send_thread = threading.Thread(target=send_message)
    send_thread.start()

    # Keep the client running
    sio.wait()
