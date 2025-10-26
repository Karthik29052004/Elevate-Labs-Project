# server.py
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from collections import defaultdict

# ---------------- CONFIG ----------------
LOG_FILE = "chat_logs.enc"
LOG_KEY_FILE = "log_key.key"
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

PUBLIC_KEYS = {}
USER_SID = {}
ENCRYPTED_LOGS = defaultdict(list)

# ---------------- ROUTES ----------------
@app.route("/register_key", methods=["POST"])
def register_key():
    data = request.json
    PUBLIC_KEYS[data["username"]] = data["public_pem"]
    return jsonify({"status": "ok"})

@app.route("/get_key/<username>", methods=["GET"])
def get_key(username):
    key = PUBLIC_KEYS.get(username)
    if not key:
        return jsonify({"error": "not found"}), 404
    return jsonify({"public_pem": key})

# ---------------- SOCKET EVENTS ----------------
@socketio.on("identify")
def identify(data):
    USER_SID[data["username"]] = request.sid
    join_room(data["username"])
    print(f"[Connected] User: {data['username']}")

@socketio.on("send_encrypted")
def send_encrypted(data):
    to = data["to"]
    frm = data["from"]
    ENCRYPTED_LOGS[(frm, to)].append(data)
    emit("receive_encrypted", data, room=to)

    # Save encrypted log
    save_encrypted_log(data)

# ---------------- LOGGING ----------------
def save_encrypted_log(message_data):
    """
    Saves each encrypted message to chat_logs.enc
    Each line is a base64-encoded JSON string
    """
    # Create or load AES-256 key for logs
    if not os.path.exists(LOG_KEY_FILE):
        log_key = os.urandom(32)  # 32 bytes = AES-256
        with open(LOG_KEY_FILE, "wb") as f:
            f.write(log_key)
    else:
        with open(LOG_KEY_FILE, "rb") as f:
            log_key = f.read()
            if len(log_key) != 32:
                # regenerate if corrupted
                log_key = os.urandom(32)
                with open(LOG_KEY_FILE, "wb") as fw:
                    fw.write(log_key)

    # Encrypt message JSON
    json_data = json.dumps(message_data).encode()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(log_key[:32]), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(json_data) + encryptor.finalize()
    enc_line = base64.b64encode(iv + ciphertext).decode()

    # Append to log file
    with open(LOG_FILE, "a") as f:
        f.write(enc_line + "\n")

# ---------------- RUN ----------------
if __name__ == "__main__":
    print("🚀 Starting Secure Chat Server on http://127.0.0.1:5000")
    socketio.run(app, host="0.0.0.0", port=5000)
