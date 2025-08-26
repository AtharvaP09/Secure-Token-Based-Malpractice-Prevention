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

#decrypt data here
decrypted_data = decrypt(config['data'] , keystring, iv_string)

#take data for hmac
config_data = iv_string.encode() + decrypted_data.encode()

#generate hmac
newhmac = hmac.new(key, config_data, hashlib.sha256).hexdigest()

#chack status
status = hmac.compare_digest(oldhmac, newhmac)
print(status)

domains = []

file = open('ledger.txt', 'a', encoding='utf-8')

def gethash(string):
    global key
    binary = string.encode()
    h =  hmac.new(key, binary, hashlib.sha256).hexdigest()
    return h

root = tk.Tk()

root.geometry('400x250')
root.title('Malpractice Prevention')

msg = tk.StringVar()
msg.set("your supervision will start now\n Evertything you do will be monitored, EVERYTHING. \nPls don't act smart :)")

label = tk.Label(root, textvariable=msg )
label.pack(expand=True)

root.mainloop()
root.quit()

def writeToFile(tag, info):
    file.write(tag+":"+info + ',')
    file.flush()
    os.fsync(file.fileno())

def checkTime():
    print(time.time())
    t = str(time.time())
    writeToFile('checkpoint', t)

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


inter = setInterval(3, checkTime)

print(config_data)
writeToFile('meta', str(config_data))

print("Sniffing HTTP/HTTPS traffic... Press Ctrl+C to stop.")

writeToFile('status', 'START')
sniff(filter="tcp port 80 or tcp port 443 or tcp port 8080", prn=combined_sniffer, store=0, timeout=40)
print("End")


writeToFile('status',"END")


inter.cancel()