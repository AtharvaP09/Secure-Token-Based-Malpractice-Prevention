from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask import Response
from models import db
import os
import json
import shutil
import zipfile
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

con = mysql.connector.connect(
    host = 'localhost',
    user = 'root',
    password = os.getenv('SQL_PASSWORD'),
    database = 'malpractice'
    )


cursor1 = con.cursor()
cursor1.execute("""CREATE TABLE IF NOT EXISTS rooms (
    roomid VARCHAR(200) NOT NULL PRIMARY KEY,
    start TIME NULL,
    end INT NULL,
    creator VARCHAR(100) NULL,
    restricted VARCHAR(2000) NULL
);""")

cursor1.close()

# Configure CORS
CORS(app, origins="*", methods=["GET", "POST"], 
     allow_headers=["Content-Type", "Authorization"])

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///project.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

def derive_key_and_iv(key_str, iv_str):
    """
    Derive key and IV using SHA256 for key and MD5 for IV (matching Node.js implementation)
    """
    key = hashlib.sha256(key_str.encode('utf-8')).digest()  # 32 bytes
    iv = hashlib.md5(iv_str.encode('utf-8')).digest()       # 16 bytes
    return key, iv

def encrypt(plaintext, key_str, iv_str):
    """
    Encrypt plaintext using AES-256-CBC (matching Node.js crypto implementation)
    """
    key, iv = derive_key_and_iv(key_str, iv_str)
    
    # Pad plaintext to be multiple of 16 bytes (AES block size)
    plaintext_bytes = plaintext.encode('utf-8')
    padding_length = 16 - (len(plaintext_bytes) % 16)
    padded_plaintext = plaintext_bytes + bytes([padding_length] * padding_length)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt(ciphertext_b64, key_str, iv_str):
    """
    Decrypt base64 encoded ciphertext using AES-256-CBC
    """
    key, iv = derive_key_and_iv(key_str, iv_str)
    
    ciphertext = base64.b64decode(ciphertext_b64)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]
    
    return plaintext.decode('utf-8')

def create_hash(key, data):
    """
    Create HMAC-SHA256 hash
    """
    key_buff = key.encode('utf-8') if isinstance(key, str) else key
    data_buff = data.encode('utf-8') if isinstance(data, str) else data
    
    hmac_hash = hmac.new(key_buff, data_buff, hashlib.sha256).hexdigest()
    return hmac_hash

@app.route('/gettoken', methods=['POST'])
def gettoken_handler():
    try:
        # Get data from request
        data = request.get_json()
        roomid = data.get('roomid')
        name = data.get('name')
        userid = data.get('userid')
        
        if not all([roomid, name, userid]):
            return jsonify({'error': 'Missing required fields: roomid, name, userid'}), 400
        
        keystring = "hackathon25"
        key = keystring.encode('utf-8')
        
        # Create base directory for temp tokens
        base_dir = os.path.join(os.getcwd(), "temp_tokens")
        os.makedirs(base_dir, exist_ok=True)
        
        # Create user directory
        user_dir = os.path.join(base_dir, str(userid))
        os.makedirs(user_dir, exist_ok=True)
        
        # Copy executable file
        source_exe = os.path.join(os.getcwd(), "token", "sniffer.exe")
        dest_exe = os.path.join(user_dir, "token.exe")
        
        if os.path.exists(source_exe):
            shutil.copy2(source_exe, dest_exe)
        else:
            print(f"Warning: Source executable not found at {source_exe}")
        
        # Prepare data for encryption
        token_data = {
            'name': name,
            'roomid': roomid,
            'userid': userid
        }
        
        iv = "deg83tbd87682r3e2b"
        
        # Encrypt the data
        ciphertext = encrypt(json.dumps(token_data), keystring, iv)
        
        # Create HMAC
        hmac_input = iv.encode('utf-8') + ciphertext.encode('utf-8')
        hmac_hash = hmac.new(key, hmac_input, hashlib.sha256).hexdigest()
        
        # Create config
        config = {
            'iv': iv,
            'data': ciphertext,
            'hmac': hmac_hash
        }
        
        # Write config file
        config_path = os.path.join(user_dir, "config.json")
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        
        # Create zip file
        zip_path = os.path.join(base_dir, f"{userid}.zip")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
            for root, dirs, files in os.walk(user_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, user_dir)
                    zipf.write(file_path, arcname)
        

        print('zipped', zip_path)
        # Send the zip file

        def generate():
            with open(zip_path, "rb") as f:
                yield from f
            # cleanup happens only after streaming is done
            try:
                if os.path.exists(zip_path):
                    os.unlink(zip_path)
                if os.path.exists(user_dir):
                    shutil.rmtree(user_dir)
                print(f"Cleaned up {zip_path} and {user_dir}")
            except Exception as e:
                print(f"Cleanup error: {e}")

        return Response(
            generate(),
            mimetype="application/zip",
            headers={"Content-Disposition": f"attachment; filename={userid}.zip"}
        )

    except Exception as e:
        print("Error:", e)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/submit', methods=['POST'])
def submit():
    try:
        # Check if file is present in request
        if 'ledger' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['ledger']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file content
        file_buffer = file.read()
        text = file_buffer.decode('utf-8')
        
        print("Uploaded file content")
        
        # Analyze the text
        print('doing something')
        
        words = text.split('<<SEP>>')

        tags = []

        metaValue = None
        start = False
        end = False
        
        for index, word in enumerate(words):
            if ':' in word:
                parts = word.split(':', 1)  # Split only on first colon
                tag = parts[0]
                value = parts[1] if len(parts) > 1 else ''

                if tag == 'meta':
                    metaValue = value

                if tag == 'status' and value == 'START':
                    start = True

                if tag == 'status' and value == 'END':
                    end = True
                

                tags.append([tag , value])
        
        print(metaValue, start, end)
        metaValue = json.loads(metaValue)
        print(metaValue['roomid'])


        if not metaValue:
            return jsonify({})
        

        

        #get restricted words
        cursor = None
        banned = []
        try:
            cursor = con.cursor()   
            cursor.execute('SELECT restricted FROM rooms WHERE roomid = %s ;', [metaValue["roomid"]])
            result = cursor.fetchall()
            print("Result:", result)

            if len(result):
                banned = result[0][0].split(',')

            print(banned)

        except Exception as e:
            print("Database Error:", e)

        finally:
            if cursor is not None:   # only close if it was created
                cursor.close()
        
        cheats = []

        
        return jsonify({
            'status': 'success',
            'length': len(text),
            'info' : metaValue
        })
        
    except Exception as e:
        print(f"Error in submit: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Helper function to clean up files (if needed separately)
@app.route('/cleanup/<userid>', methods=['DELETE'])
def cleanup_user_files(userid):
    try:
        base_dir = os.path.join(os.getcwd(), "temp_tokens")
        user_dir = os.path.join(base_dir, str(userid))
        zip_path = os.path.join(base_dir, f"{userid}.zip")
        
        # Remove zip file
        if os.path.exists(zip_path):
            os.unlink(zip_path)
        
        # Remove user directory
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir)
        
        return jsonify({'message': f'Cleaned up files for user {userid}'}), 200
    except Exception as e:
        return jsonify({'error': f'Cleanup failed: {e}'}), 500

# Import routes after app configuration
from routes import *

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5643, debug=True)