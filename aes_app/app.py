from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'

# pastikan foldernya ada
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

# Fungsi bantu
def get_cipher(key):
    key_bytes = key.encode('utf-8')
    key_padded = key_bytes.ljust(32, b'\0')[:32]  # AES-256
    return AES.new(key_padded, AES.MODE_CBC, iv=b'\0' * 16)

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files['file']
    key = request.form['key']

    if file and key:
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        with open(file_path, 'rb') as f:
            data = f.read()

        cipher = get_cipher(key)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))

        encrypted_path = os.path.join(ENCRYPTED_FOLDER, file.filename + '.enc')
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        return send_file(encrypted_path, as_attachment=True)

    return 'Error: File dan key diperlukan!'

@app.route('/decrypt', methods=['POST'])
def decrypt():
    file = request.files['file']
    key = request.form['key']

    if file and key:
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        cipher = get_cipher(key)
        try:
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        except ValueError:
            return "Dekripsi gagal: kemungkinan kunci salah atau file bukan terenkripsi dengan AES ini."

        decrypted_path = os.path.join(DECRYPTED_FOLDER, file.filename.replace('.enc', ''))
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)

        return send_file(decrypted_path, as_attachment=True)

    return 'Error: File dan key diperlukan!'

if __name__ == '__main__':
    app.run(debug=True, port=8080)
