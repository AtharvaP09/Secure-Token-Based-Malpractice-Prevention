from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
from setInterval import setInterval
import time
import tkinter as tk
import json
import os
import hmac
import hashlib
import sys



if getattr(sys, 'frozen', False):
    # Running as bundled EXE
    exe_dir = os.path.dirname(sys.executable)
else:
    # Running from script
    exe_dir = os.path.dirname(__file__)

config_file = os.path.join(exe_dir, "config.json")

with open(config_file, "r") as f:
    config = json.load(f)

ledgertext = ''

key = 'hackathon25'
key = key.encode()

#first check hash

oldhmac = config['hmac']

#decrypt data here
config_data = config['data'].encode()

newhmac = hmac.new(key, config_data, hashlib.sha256).hexdigest()
status = hmac.compare_digest(oldhmac, newhmac)
print(status)

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

def foo():
    print(time.time())
    t = str(time.time())

    file.write('checkpoint:'+t+"-"+gethash(t)+',')
    file.flush()
    os.fsync(file.fileno())
    


def writeToFile(tag, info):
    file.write(tag+":"+info+'-'+gethash(info)+',')
    file.flush()
    os.fsync(file.fileno())

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


inter = setInterval(3, foo)

print(config_data)
writeToFile('meta', str(config_data))

print("Sniffing HTTP/HTTPS traffic... Press Ctrl+C to stop.")

writeToFile('status', 'START')
sniff(filter="tcp port 80 or tcp port 443 or tcp port 8080", prn=combined_sniffer, store=0, timeout=40)
print("End")


writeToFile('status',"END")


inter.cancel()