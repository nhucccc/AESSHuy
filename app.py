from flask import Flask, render_template, request, send_file, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'outputs'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Đảm bảo thư mục tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

def derive_key_iv(password, salt):
    key_iv = PBKDF2(password, salt, dkLen=32 + 16, count=1000000)
    return key_iv[:32], key_iv[32:]  # 256-bit key, 128-bit IV

def encrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()
    salt = get_random_bytes(16)
    key, iv = derive_key_iv(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padding_len = 16 - len(data) % 16
    data += bytes([padding_len]) * padding_len
    ciphertext = cipher.encrypt(data)
    return salt + ciphertext

def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        file_data = f.read()
    salt = file_data[:16]
    ciphertext = file_data[16:]
    key, iv = derive_key_iv(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(ciphertext)
    padding_len = data[-1]
    return data[:-padding_len]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    mode = request.form.get('mode')  # encrypt / decrypt
    password = request.form.get('password')
    file = request.files['file']

    if not password or not file:
        return "Thiếu mật khẩu hoặc file!", 400

    filename = file.filename
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(input_path)

    if mode == 'encrypt':
        output_data = encrypt_file(input_path, password)
        output_filename = filename + '.aes'
    else:
        try:
            output_data = decrypt_file(input_path, password)
            output_filename = filename.replace('.aes', '.dec')
        except Exception:
            return "Giải mã thất bại. Sai mật khẩu hoặc file hỏng.", 400

    output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
    with open(output_path, 'wb') as f:
        f.write(output_data)

    return send_file(output_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
