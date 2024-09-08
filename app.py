import qrcode
from flask import Flask, render_template, request, flash, redirect, url_for, send_file, session, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from io import BytesIO
import zipfile
from datetime import datetime
from hashlib import sha256

from qrcode.main import QRCode

app = Flask(__name__)
app.secret_key = '@Zil1992'  # Replace with your own secret key for Flask

class Encryptor:
    def __init__(self, key: str):
        # Hash the key to ensure consistent key length and uniqueness
        self.key = sha256(key.encode('utf-8')).digest()[:32]  # Use the first 32 bytes of the SHA-256 hash

    def encrypt_text(self, plaintext: str) -> str:
        plaintext_bytes = plaintext.encode('utf-8')
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        encrypted_data = base64.b64encode(iv + encrypted_bytes).decode('utf-8')
        return encrypted_data

    def decrypt_text(self, encrypted_data: str) -> str:
        try:
            encrypted_data_bytes = base64.b64decode(encrypted_data)
            iv = encrypted_data_bytes[:16]
            encrypted_bytes = encrypted_data_bytes[16:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
            decrypted_text = decrypted_bytes.decode('utf-8')
            return decrypted_text
        except Exception as e:
            return f"* Decryption Error: {str(e)}"

    def encrypt_file(self, data: bytes) -> bytes:
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(pad(data, AES.block_size))
        return iv + encrypted_bytes

    def decrypt_file(self, data: bytes) -> bytes:
        iv = data[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(data[16:]), AES.block_size)
        return decrypted_bytes


@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    data = request.json.get('data')
    if not data:
        flash('No data provided for QR code generation.', 'danger')
        return redirect(url_for('index'))

    max_length = 1000  # Adjust this based on QR code capacity
    chunks = [data[i:i + max_length] for i in range(0, len(data), max_length)]

    qr_images = []
    try:
        # Create a QR code for each chunk
        for i, chunk in enumerate(chunks):
            qr = QRCode(
                version=None,  # Automatically determine the version needed
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )

            qr.add_data(chunk)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            img_bytes = BytesIO()
            img.save(img_bytes)
            img_bytes.seek(0)
            qr_images.append(img_bytes)

        # Send the first QR code as an example
        if len(qr_images) > 1:
            flash(f'Data was split into {len(qr_images)} QR codes. Please save all to preserve your content.', 'info')

        return send_file(qr_images[0], mimetype='image/png')

    except Exception as e:
        flash(f'Error generating QR code: {str(e)}', 'danger')
        return redirect(url_for('index'))



@app.route('/', methods=['GET', 'POST'])
@app.route('/encrypt', methods=['GET', 'POST'])
def index():
    key = None  # Initialize the key variable
    sit = None
    if request.method == 'POST':
        action = request.form.get('action')
        key = request.form.get('key')
        text = request.form.get('text')

        if not key or not text:
            flash('Key and text are required!', 'danger')
            return redirect(url_for('index'))

        encryptor = Encryptor(key)

        try:
            if action == 'encrypt':
                encrypted_text = encryptor.encrypt_text(text)
                sit = "e"
                flash(f'{encrypted_text}', 'success')
            elif action == 'decrypt':
                decrypted_text = encryptor.decrypt_text(text)
                sit = "d"
                # Use a specific marker to detect decryption errors
                if decrypted_text.startswith('* Decryption Error'):
                    flash(decrypted_text, 'danger')
                else:
                    flash(decrypted_text, 'success')
        except Exception as e:
            flash(f'An error occurred during {action}: {str(e)}', 'danger')

    return render_template('index.html', key=key or '', sit=sit or '')

@app.route('/file', methods=['GET', 'POST'])
def file_encrypt_decrypt():
    if request.method == 'POST':
        action = request.form.get('action')
        key = request.form.get('key')
        files = request.files.getlist('file')  # Get list of all files

        if not key or not files:
            flash('Key and files are required!', 'danger')
            return redirect(url_for('file_encrypt_decrypt'))

        encryptor = Encryptor(key)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')  # Format as YYYYMMDD_HHMMSS

        if action == 'encrypt':
            output_zip = BytesIO()
            with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file in files:
                    try:
                        file_data = file.read()
                        encrypted_data = encryptor.encrypt_file(file_data)
                        zipf.writestr(f'encrypted_{file.filename}', encrypted_data)
                    except Exception as e:
                        flash(f'Error encrypting {file.filename}: {str(e)}', 'danger')

            output_zip.seek(0)
            zip_filename = f'encrypted_files_{timestamp}.zip'
            return send_file(output_zip, download_name=zip_filename, as_attachment=True)

        elif action == 'decrypt' and len(files) == 1 and zipfile.is_zipfile(files[0]):
            uploaded_zip = files[0]
            output_zip = BytesIO()
            with zipfile.ZipFile(uploaded_zip) as zf, zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_name in zf.namelist():
                    try:
                        encrypted_data = zf.read(file_name)
                        decrypted_data = encryptor.decrypt_file(encrypted_data)
                        zipf.writestr(f'decrypted_{file_name}', decrypted_data)
                    except Exception as e:
                        flash(f'Error decrypting {file_name}: {str(e)}', 'danger')

            output_zip.seek(0)
            zip_filename = f'decrypted_files_{timestamp}.zip'
            return send_file(output_zip, download_name=zip_filename, as_attachment=True)

    return render_template('file.html')

class MultiKeyEncryptor:
    def __init__(self, keys: list):
        # Store original keys for display but hash them for internal use
        self.original_keys = keys
        self.keys = [sha256(key.encode('utf-8')).digest()[:32] for key in keys]

    def encrypt_text(self, plaintext: str) -> str:
        try:
            encrypted_data = plaintext.encode('utf-8')
            result_info = []

            # Sequentially encrypt the data using each hashed key
            for index, (key, original_key) in enumerate(zip(self.keys, self.original_keys), start=1):
                iv = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted_data = iv + cipher.encrypt(pad(encrypted_data, AES.block_size))
                # Show the original key instead of the hash
                result_info.append(f"Key {index}: {original_key}")

            # Encode the fully encrypted data to Base64
            encrypted_result = base64.b64encode(encrypted_data).decode('utf-8')
            result_info.append(f"Encrypted: {encrypted_result}")
            return '\n'.join(result_info)

        except Exception as e:
            return f"Encryption error: {str(e)}"

    def decrypt_text(self, encrypted_data: str) -> str:
        try:
            encrypted_data_bytes = base64.b64decode(encrypted_data)

            # Sequentially decrypt using the hashed keys in reverse order
            for key in reversed(self.keys):
                iv = encrypted_data_bytes[:16]
                encrypted_data_bytes = encrypted_data_bytes[16:]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted_data_bytes = unpad(cipher.decrypt(encrypted_data_bytes), AES.block_size)

            return encrypted_data_bytes.decode('utf-8')

        except ValueError as e:
            return f"Decryption error: padding or key issue: {str(e)}"
        except UnicodeDecodeError as e:
            return f"Decryption error: cannot decode decrypted data: {str(e)}"
        except Exception as e:
            return f"Decryption error: {str(e)}"


@app.route('/multi-key', methods=['GET', 'POST'])
def multi_key_encrypt_decrypt():
    sit = None
    if request.method == 'POST':
        action = request.form.get('action')
        num_keys = int(request.form.get('num_keys', 1))
        keys = [request.form.get(f'key_{i + 1}') for i in range(num_keys)]
        text = request.form.get('text')

        if not all(keys) or not text:
            flash('All keys and text are required!', 'danger')
            return redirect(url_for('multi_key_encrypt_decrypt'))

        encryptor = MultiKeyEncryptor(keys)
        try:
            if action == 'encrypt':
                formatted_result = encryptor.encrypt_text(text)
                sit = "e"
                flash(formatted_result, 'success')
            elif action == 'decrypt':
                decrypted_text = encryptor.decrypt_text(text)
                sit = "d"
                if "Key is not valid" in decrypted_text or decrypted_text.startswith('Decryption error'):
                    flash(decrypted_text, 'danger')
                else:
                    flash(decrypted_text, 'success')
        except Exception as e:
            flash(f'An error occurred during {action}: {str(e)}', 'danger')

    return render_template('multi_key.html', sit=sit or '')




@app.route('/notepad', methods=['GET', 'POST'])
def notepad():
    return render_template('notepad.html')


@app.route('/create_note', methods=['POST'])
def create_note():
    key = request.form.get('key')
    note_content = request.form.get('note_content')
    if not key or not note_content:
        return jsonify({'error': 'Key and note content are required!'}), 400

    encryptor = Encryptor(key)
    encrypted_note = encryptor.encrypt_text(note_content)

    # Generate filename with datetime
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'encrypted_{timestamp}.txt'

    # Prepare the file for download
    file_bytes = BytesIO(encrypted_note.encode('utf-8'))
    return send_file(file_bytes, as_attachment=True, download_name=filename, mimetype='text/plain')


@app.route('/decrypt_note', methods=['POST'])
def decrypt_note():
    data = request.json
    key = data.get('key')
    encrypted_content = data.get('encrypted_content')
    if not key or not encrypted_content:
        return jsonify({'error': 'Key and encrypted content are required!'}), 400

    encryptor = Encryptor(key)
    decrypted_note = encryptor.decrypt_text(encrypted_content)

    # If the decryption error occurs, send back the error
    if decrypted_note.startswith('* Decryption Error'):
        return jsonify({'error': decrypted_note}), 400

    return jsonify({'content': decrypted_note})


@app.route('/save_note', methods=['POST'])
def save_note():
    data = request.json
    key = data.get('key')
    note_content = data.get('note_content')
    if not key or not note_content:
        return jsonify({'error': 'Key and note content are required!'}), 400

    encryptor = Encryptor(key)
    encrypted_note = encryptor.encrypt_text(note_content)

    # Generate filename with datetime for edited note
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'encrypted_edited_{timestamp}.txt'

    # Prepare the file for download
    file_bytes = BytesIO(encrypted_note.encode('utf-8'))
    return send_file(file_bytes, as_attachment=True, download_name=filename, mimetype='text/plain')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5050, debug=True)
