from app import app
from models import *
from flask import request, jsonify
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import shutil
import zipfile
import hashlib
import hmac
import base64
from app import con
from flask import Response
import string
import random
import jwt

def randomString(length):
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length)).upper()
    return random_string

# Character set: all printable ASCII
CHARS = string.printable  

def generate_key(seed=None):
    """Generate encryption and decryption maps."""
    chars = list(CHARS)
    if seed is not None:
        random.seed(seed)  # reproducibility
    shuffled = chars[:]
    random.shuffle(shuffled)
    
    encrypt_map = dict(zip(chars, shuffled))
    decrypt_map = dict(zip(shuffled, chars))
    
    return encrypt_map, decrypt_map


def encryptSubs(text, encrypt_map):
    """Encrypt using substitution cipher."""
    return "".join(encrypt_map.get(ch, ch) for ch in text)


def decryptSubs(ciphertext, decrypt_map):
    """Decrypt using substitution cipher."""
    return "".join(decrypt_map.get(ch, ch) for ch in ciphertext)


#Default
@app.route('/')
def home():
    return "Secure Token Based Malpractice Prevention , Hello World!"

#Users
@app.route('/users' , methods=["GET"])
def users():
    return"List of users to be displayed"

#User Registration
@app.route('/UserRegistration' , methods=["POST"])
def UserRegistration():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 400

    user = User(username=username, email=email)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

#User Login
@app.route("/UserLogin", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if user is None or not user.check_password(password):
        return jsonify({"message": "Invalid credentials"}), 401

    # Generate JWT token
    webtoken = jwt.encode(
        {"public_id": user.id}, os.getenv("JWT_KEY"), algorithm="HS256"
    )

    # Return token, user ID, and username
    return jsonify({
        "message": "Login successful",
        "user_id": user.id,
        "username": user.username,  
        "webtoken": webtoken
    }), 200

def derive_key_and_iv(key_str, iv_str):

    key = hashlib.sha256(key_str.encode('utf-8')).digest()  # 32 bytes
    iv = hashlib.md5(iv_str.encode('utf-8')).digest()       # 16 bytes
    return key, iv

def encrypt(plaintext, key_str, iv_str):

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

        substext = os.getenv('SUBS_SEED')

        token_data = {
            'name': name,
            'roomid': roomid,
            'userid': userid,
            'subs' : substext
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
            'hmac': hmac_hash,
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

        ##decrypt the text
        _, decrypt_map = generate_key(seed=os.getenv('SUBS_SEED'))

        decryptedText = decryptSubs(text, decrypt_map)

        text = decryptedText
        
        words = text.split('<<SEP>>')

        tags = []
        domains = []
        metaValue = None
        start = False
        end = False
        timestamp = None
        
        for index, word in enumerate(words):
            if ':' in word:
                parts = word.split(':', 1)  # Split only on first colon
                tag = parts[0]
                value = parts[1] if len(parts) > 1 else ''

                if tag == 'checkpoint':
                    timestamp = value

                if tag == 'meta':
                    metaValue = value

                if tag == 'status' and value == 'START':
                    start = True

                if tag == 'status' and value == 'END':
                    end = True
                
                if tag == 'domain':
                    domains.append({'domain':value , 'time':timestamp})


            

                tags.append([tag , value])
        
        print(metaValue, start, end)
        
        metaValue = json.loads(metaValue)
        print(metaValue['roomid'])


        if not metaValue:
            return jsonify({})
        
        roomid = metaValue['roomid']
        userid = metaValue['userid']
        

        #get restricted words
        cursor = None
        banned = []
        cheats = []
        try:
            cursor = con.cursor()   
            #database
            cursor.execute('SELECT restricted FROM rooms WHERE roomid = %s ;', [metaValue["roomid"]])
            result = cursor.fetchall()
            print("Result:", result)

            if len(result):
                banned = result[0][0].split(',')


            for domainObject in domains:
                
                dname = domainObject['domain']

                for b in banned:
                    b = b.strip()
                    dname = dname.strip()
                    if b in dname:
                        print(b, dname)
                        cheats.append(domainObject)

            

            cursor.execute('insert into submissions(roomid, userid, cheats, time) values( %s, %s , %s, sysdate());', [roomid, userid, json.dumps(cheats)])
            con.commit()

            print(cheats)


        except Exception as e:
            print("Error:", e.args)

        finally:
            if cursor is not None:   
                cursor.close()
        

        
        return jsonify({
            'status': 'success',
            'length': len(text),
            'info' : metaValue
        })
        
    except Exception as e:
        print(f"Error in submit: {e}")
        return jsonify({'error': 'Internal server error'}), 500
    

@app.route('/results', methods = ['POST'])
def getResults():
    #get roomid and creator(userid)

    #using userid, check if creator is authentic

    #using roomid, get all the results

    #send results to user

    length = 8
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length)).upper()
    print(random_string)

    return jsonify({'msg' : random_string})


@app.route('/createroom', methods = ['POST'])
def handleRoom():
    data = request.get_json()

    

    return jsonify({'data' : data})
    

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

