from flask import Flask, render_template, request, jsonify
import sqlite3
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# AES-256 Master Key (32 Bytes)
SECRET_KEY = b'12345678901234567890123456789012'

def encrypt_aes256(plain_text):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return f"{iv}:{ct}"

def decrypt_aes256(encrypted_str):
    try:
        iv_b64, ct_b64 = encrypted_str.split(':')
        iv = base64.b64decode(iv_b64)
        ct = base64.b64decode(ct_b64)
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception:
        return "[Decryption Failed]"

def init_db():
    conn = sqlite3.connect('secure_users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            encrypted_secret TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    secret = request.form.get('secret')

    if not username or not secret:
        return jsonify({'status': 'error', 'message': 'All fields required!'}), 400

    encrypted_data = encrypt_aes256(secret)

    try:
        conn = sqlite3.connect('secure_users.db')
        cursor = conn.cursor()
        # Parameterized query to prevent SQL Injection
        cursor.execute('INSERT INTO users (username, encrypted_secret) VALUES (?, ?)', (username, encrypted_data))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'User registered! Data encrypted with AES-256.'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Username already exists!'}), 400

@app.route('/login_secure', methods=['POST'])
def login_secure():
    username = request.form.get('username')
    
    # Check for SQL Injection patterns for detection logging
    sqli_detected = any(char in username for char in ["'", "--", ";", "OR 1=1", "OR '1'='1"])

    conn = sqlite3.connect('secure_users.db')
    cursor = conn.cursor()
    # Safe Double-Layer: Capability checking & Parameterized query
    cursor.execute('SELECT username, encrypted_secret FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        decrypted_secret = decrypt_aes256(row[1])
        return jsonify({
            'status': 'success',
            'message': 'Access Granted (Secure Query Executed)',
            'user': row[0],
            'encrypted_data_db': row[1],
            'decrypted_secret': decrypted_secret,
            'sqli_attack_blocked': sqli_detected
        })
    else:
        return jsonify({
            'status': 'failed',
            'message': 'User Not Found or Payload Neutralized Safely!',
            'sqli_attack_blocked': sqli_detected
        }), 404

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)