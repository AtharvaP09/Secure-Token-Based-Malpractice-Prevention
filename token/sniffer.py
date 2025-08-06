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

config_file = os.path.join(os.path.dirname(__file__), "config.json")
with open(config_file, "r") as f:
    config = json.load(f)

print(config)

key = 'hackathon25'
key = key.encode()

#first check hash

oldhmac = config['hmac']
config_data = config['data'].encode()

newhmac = hmac.new(key, config_data, hashlib.sha256).hexdigest()
status = hmac.compare_digest(oldhmac, newhmac)
print(status)

file = open('data.txt', 'a')


root = tk.Tk()
root.mainloop()

root.quit()

def foo():
    print(time.time())
    file.write('checkpoint:'+str(time.time())+'\n')
    


def writeToFile(info):
    file.write("domain: "+info+ '\n')

def http_sniffer(pkt):
    if pkt.haslayer(HTTPRequest):
        host = pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else "Unknown"
        path = pkt[HTTPRequest].Path.decode() if pkt[HTTPRequest].Path else "/"
        print(f"[HTTP] Visited: http://{host}{path}")
        writeToFile(f"{host}{path}")

def https_sniffer(pkt):
    if pkt.haslayer(TLSClientHello):
        for ext in pkt[TLSClientHello].ext:
            if isinstance(ext, TLS_Ext_ServerName):
                try:
                    domain = ext.servernames[0].servername.decode()
                    print(f"[HTTPS] Visited domain: {domain}")
                    writeToFile(domain)
                except:
                    pass

def combined_sniffer(pkt):
    if pkt.haslayer(HTTPRequest):
        http_sniffer(pkt)
    elif pkt.haslayer(TLSClientHello):
        https_sniffer(pkt)


inter = setInterval(1, foo)

print("Sniffing HTTP/HTTPS traffic... Press Ctrl+C to stop.")

sniff(filter="tcp port 80 or tcp port 443 or tcp port 8080", prn=combined_sniffer, store=0, timeout=40)
print("End")

inter.cancel()