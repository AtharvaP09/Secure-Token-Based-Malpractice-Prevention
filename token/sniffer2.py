from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from setInterval import setInterval
import time
import tkinter as tk
import json
import os
import hmac
import hashlib
import sys
import base64
import random
import string
import requests


def encrypt(plaintext: str, key_str: str, iv_str: str) -> str:
    
    # Derive AES key (32 bytes) and IV (16 bytes)
    key = hashlib.sha256(key_str.encode()).digest()   # AES-256 key
    iv = hashlib.md5(iv_str.encode()).digest()        # 16-byte IV

    # Pad plaintext
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Encode to Base64
    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt(ciphertext_b64: str, key_str: str, iv_str: str) -> str:
    # Derive AES key and IV
    key = hashlib.sha256(key_str.encode()).digest()
    iv = hashlib.md5(iv_str.encode()).digest()

    # Decode Base64 ciphertext
    ciphertext = base64.b64decode(ciphertext_b64)

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode("utf-8")


CHARS = string.ascii_letters + string.digits + string.punctuation + " "


def generate_keySubs(seed=None):
    chars = list(CHARS)
    if seed is not None:
        random.seed(seed)  # reproducibility
    shuffled = chars[:]
    random.shuffle(shuffled)
    
    encrypt_map = dict(zip(chars, shuffled))
    decrypt_map = dict(zip(shuffled, chars))
    
    return encrypt_map, decrypt_map


def encryptSubs(text, encrypt_map):
    return "".join(encrypt_map.get(ch, ch) for ch in text)


def decryptSubs(ciphertext, decrypt_map):
    return "".join(decrypt_map.get(ch, ch) for ch in ciphertext) 



"""code starts here"""
if getattr(sys, 'frozen', False):
    # Running as bundled EXE
    exe_dir = os.path.dirname(sys.executable)
else:
    # Running from script
    exe_dir = os.path.dirname(__file__)

config_file = os.path.join(exe_dir, "config.json")

with open(config_file, "r") as f:
    config = json.load(f)


key = 'hackathon25'
keystring = key
key = key.encode()

#first take hash

oldhmac = config['hmac']
iv_string = config['iv']
ciphertext = config['data']  #ciphertext

#decrypt data here

try:
    decrypted_data = decrypt(config['data'] , keystring, iv_string)
    #take data for hmac
    config_data = iv_string.encode() + ciphertext.encode()

    #generate hmac
    newhmac = hmac.new(key, config_data, hashlib.sha256).hexdigest()

    #chack status
    status = hmac.compare_digest(oldhmac, newhmac)

except:
    status = False

print(status)

domains = []

dData = json.loads(decrypted_data)

USER_NAME = dData.get("name", "unknown")
USER_ID = dData.get("userid", -1)
ROOM_ID = dData.get("roomid", "unknown_room")


print("D data",dData)

subs = dData['subs']
starttime = float(dData['starttime'])
duration = dData['duration']
print(starttime, time.time())


emap , dmap = generate_keySubs(subs)

file = open('ledger.txt', 'a', encoding='utf-8')

def gethash(string):
    global key
    binary = string.encode()
    h =  hmac.new(key, binary, hashlib.sha256).hexdigest()
    return h

def writeHash():
    print('done')
    r = file.read()
    print(r)

SERVER_URL = "http://127.0.0.1:5643/api/realtime"  # your API endpoint

def writeToFile(tag, info):
    payload = {
        "name": USER_NAME,
        "userid": USER_ID,
        "roomid": ROOM_ID,
        "tag": tag,
        "info": info,
        "timestamp": time.time()
    }

    try:
        res = requests.post(SERVER_URL, json=payload, timeout=2)
        res.raise_for_status()
    except requests.RequestException as e:
        print("Failed to send log:", e)


def checkTime():
    # print(time.time())
    t = str(time.time())
    # writeToFile('checkpoint', t)

def http_sniffer(pkt):
    if pkt.haslayer(HTTPRequest):
        host = pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else "Unknown"
        path = pkt[HTTPRequest].Path.decode() if pkt[HTTPRequest].Path else "/"
        print(f"[HTTP] Visited: http://{host}{path}")
        writeToFile('domain', f"{host}{path}")

def https_sniffer(pkt):
    if pkt.haslayer(TLSClientHello):
        for ext in pkt[TLSClientHello].ext:
            if isinstance(ext, TLS_Ext_ServerName):
                try:
                    domain = ext.servernames[0].servername.decode()
                    print(f"[HTTPS] Visited domain: {domain}")
                    writeToFile('domain',domain)
                except:
                    pass

def combined_sniffer(pkt):
    if pkt.haslayer(HTTPRequest):
        http_sniffer(pkt)
    elif pkt.haslayer(TLSClientHello):
        https_sniffer(pkt)

#let the program sleep until start time occurs
if time.time() < starttime :
    waitingtime = starttime - time.time()
    print('sleeping for '+ str(waitingtime) + ' seconds...')
    time.sleep(waitingtime)

inter = setInterval(3, checkTime)

print(config_data)
writeToFile('meta', str(decrypted_data))

print("Sniffing HTTP/HTTPS traffic... Press Ctrl+C to stop.")

writeToFile('status', 'START')
writeToFile('checkpoint', str(time.time()))

root = tk.Tk()

root.geometry('400x250')
root.title('Malpractice Prevention')

msg = tk.StringVar()

if status:
    msg.set("your supervision will start now\n Everything you do will be monitored, EVERYTHING. \n The test is for "+str(duration)+" seconds. \nPls don't act smart :)\n\nYou may close this window")

else:
    msg.set("You tried to tamper the config file,\n you shouldnt have done that, \ntry getting another token, \n and next time be a little honest")

label = tk.Label(root, textvariable=msg )
label.pack(expand=True)

root.mainloop()
root.quit()

if not status:
    sys.exit()

sniff(filter="tcp port 80 or tcp port 443 or tcp port 8080", prn=combined_sniffer, store=0, timeout=int(duration))
print("End")


writeToFile('status',"END")
# writeHash()

inter.cancel()